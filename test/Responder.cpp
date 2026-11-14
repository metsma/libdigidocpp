// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "Responder.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include <algorithm>
#include <array>
#include <cstdio>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace digidoc;
using namespace digidoc::test;
using namespace std;

namespace
{

[[noreturn]] void fail(const char *msg)
{
    ERR_print_errors_fp(stderr);
    throw runtime_error(msg);
}

pair<unique_free_d<X509_free>, unique_free_d<EVP_PKEY_free>> loadP12(const char *path, const char *pass)
{
    auto file = make_unique_ptr<BIO_free>(BIO_new_file(path, "rb"));
    auto p12 = make_unique_ptr<PKCS12_free>(file ? d2i_PKCS12_bio(file.get(), nullptr) : nullptr);
    EVP_PKEY *key {};
    X509 *cert {};
    if(!p12 || PKCS12_parse(p12.get(), pass, &key, &cert, nullptr) != 1)
        fail("Failed to load the responder key");
    return {make_unique_ptr<X509_free>(cert), make_unique_ptr<EVP_PKEY_free>(key)};
}

}

/**
 * Starts RFC 3161 time-stamping and RFC 6960 OCSP services on a free 127.0.0.1
 * port, so that the signing tests do not depend on the network and the demo
 * services.
 *
 * The time-stamping unit and OCSP responder certificates and keys come from
 * @a tsaP12 and @a ocspP12. The test TSL (EE_T.xml) lists them as TSA/QTST
 * and Certstatus/OCSP/QC services, so their responses validate like those of
 * qualified services. The services answer POST requests to tsaUrl() and
 * ocspUrl() on a single thread, one connection at a time.
 *
 * The OCSP service reports certificates issued by an addIssuer() CA as good,
 * unless setStatus() says otherwise, and all other certificates as unknown.
 */
Responder::Responder(const char *tsaP12, const char *tsaPass, const char *ocspP12, const char *ocspPass)
    : ctx(TS_RESP_CTX_new())
    , address(BIO_ADDR_new())
{
    if(!ctx || !address)
        fail("Failed to allocate the responder");

    auto [tsaCert, tsaKey] = loadP12(tsaP12, tsaPass);
    auto policy = make_unique_ptr<ASN1_OBJECT_free>(OBJ_txt2obj("0.4.0.2023.1.1", 1)); // ETSI best practices policy
    if(TS_RESP_CTX_set_signer_cert(ctx.get(), tsaCert.get()) != 1 ||
        TS_RESP_CTX_set_signer_key(ctx.get(), tsaKey.get()) != 1 ||
        !policy || TS_RESP_CTX_set_def_policy(ctx.get(), policy.get()) != 1 ||
        TS_RESP_CTX_set_signer_digest(ctx.get(), EVP_sha256()) != 1 ||
        TS_RESP_CTX_set_ess_cert_id_digest(ctx.get(), EVP_sha256()) != 1)
        fail("Failed to configure the time-stamping responder");
    for(const EVP_MD *md: {EVP_sha224(), EVP_sha256(), EVP_sha384(), EVP_sha512(),
            EVP_sha3_224(), EVP_sha3_256(), EVP_sha3_384(), EVP_sha3_512()})
    {
        if(TS_RESP_CTX_add_md(ctx.get(), md) != 1)
            fail("Failed to configure the time-stamping responder");
    }
    TS_RESP_CTX_set_serial_cb(ctx.get(), [](TS_RESP_CTX *, void *data) -> ASN1_INTEGER * {
        auto serial = make_unique_ptr<ASN1_INTEGER_free>(ASN1_INTEGER_new());
        if(!serial || ASN1_INTEGER_set(serial.get(), ++static_cast<Responder*>(data)->serial) != 1)
            return nullptr;
        return serial.release();
    }, this);

    tie(ocspCert, ocspKey) = loadP12(ocspP12, ocspPass);

    BIO_ADDRINFO *info {};
    if(BIO_lookup_ex("127.0.0.1", "0", BIO_LOOKUP_SERVER, AF_INET, SOCK_STREAM, 0, &info) != 1)
        fail("Failed to resolve the responder address");
    socket = BIO_socket(BIO_ADDRINFO_family(info), BIO_ADDRINFO_socktype(info), BIO_ADDRINFO_protocol(info), 0);
    bool listening = socket != -1 && BIO_listen(socket, BIO_ADDRINFO_address(info), 0) == 1;
    BIO_ADDRINFO_free(info);
    BIO_sock_info_u sockInfo {address.get()};
    if(!listening || BIO_sock_info(socket, BIO_SOCK_INFO_ADDRESS, &sockInfo) != 1)
    {
        if(socket != -1)
            BIO_closesocket(socket);
        fail("Failed to start the responder");
    }
    char *port = BIO_ADDR_service_string(address.get(), 1);
    string base = "http://127.0.0.1:" + string(port ? port : "");
    OPENSSL_free(port);
    tsa = base + "/tsa";
    ocsp = base + "/ocsp";
    thread = std::thread(&Responder::run, this);
}

Responder::~Responder()
{
    stop = true;
    // Wake up the blocking accept() in run() with a connection of our own.
    if(int s = BIO_socket(BIO_ADDR_family(address.get()), SOCK_STREAM, 0, 0); s != -1)
    {
        BIO_connect(s, address.get(), 0);
        BIO_closesocket(s);
    }
    thread.join();
    BIO_closesocket(socket);
}

/**
 * Makes the OCSP service report certificates issued by @a issuer as good.
 */
void Responder::addIssuer(X509 *issuer)
{
    X509_up_ref(issuer);
    lock_guard lock(mutex);
    issuers.emplace_back(issuer);
}

/**
 * Sets the OCSP status of @a cert: V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED
 * or V_OCSP_CERTSTATUS_UNKNOWN. Its issuer must have been added with addIssuer().
 */
void Responder::setStatus(X509 *cert, int status)
{
    lock_guard lock(mutex);
    auto issuer = ranges::find_if(issuers, [cert](const auto &i) {
        return X509_check_issued(i.get(), cert) == X509_V_OK;
    });
    if(issuer == issuers.cend())
        throw runtime_error("Responder::setStatus: the issuer has not been added");
    X509_up_ref(cert);
    statuses.push_back({make_unique_ptr<X509_free>(cert), issuer->get(), status});
}

void Responder::run()
{
    while(!stop)
    {
        int client = BIO_accept_ex(socket, nullptr, 0);
        if(client == -1)
            continue;
        if(stop)
            BIO_closesocket(client);
        else
            handle(client);
        ERR_clear_error();
    }
    OPENSSL_thread_stop();
}

void Responder::handle(int client)
{
#ifdef _WIN32
    const DWORD timeout = 1000;
#else
    const timeval timeout {1, 0};
#endif
    for(int option: {SO_RCVTIMEO, SO_SNDTIMEO})
    {
        if(setsockopt(client, SOL_SOCKET, option,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0)
        {
            BIO_closesocket(client);
            return;
        }
    }
    auto sock = make_unique_ptr<BIO_free>(BIO_new_socket(client, BIO_CLOSE));
    if(!sock)
    {
        BIO_closesocket(client);
        return;
    }
    auto bio = make_unique_ptr<BIO_free_all>(BIO_new(BIO_f_buffer()));
    if(!bio)
        return;
    BIO_push(bio.get(), sock.release());

    // Request line, then the headers up to the empty line. The body is a DER
    // TimeStampReq or OCSPRequest that carries its own length, so
    // Content-Length is not needed.
    array<char, 1024> line {};
    if(BIO_gets(bio.get(), line.data(), int(line.size())) <= 0)
        return;
    string_view requestLine = line.data();
    bool isTSA = requestLine.starts_with("POST /tsa ");
    bool isOCSP = requestLine.starts_with("POST /ocsp ");
    do
    {
        if(BIO_gets(bio.get(), line.data(), int(line.size())) <= 0)
            return;
        if(stop)
            return;
    }
    while(string_view(line.data()) != "\r\n");

    unsigned char *der {};
    int size = -1;
    const char *contentType {};
    if(isTSA)
    {
        if(auto resp = make_unique_ptr<TS_RESP_free>(TS_RESP_create_response(ctx.get(), bio.get())))
            size = i2d_TS_RESP(resp.get(), &der);
        contentType = "application/timestamp-reply";
    }
    else if(isOCSP)
    {
        if(auto resp = ocspResponse(bio.get()))
            size = i2d_OCSP_RESPONSE(resp.get(), &der);
        contentType = "application/ocsp-response";
    }
    if(stop)
    {
        OPENSSL_free(der);
        return;
    }

    if(size > 0)
    {
        BIO_printf(bio.get(), "HTTP/1.0 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n", contentType, size);
        BIO_write(bio.get(), der, size);
    }
    else
        BIO_printf(bio.get(), "HTTP/1.0 %s\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n", contentType ? "500 Internal Server Error" : "404 Not Found");
    BIO_flush(bio.get());
    OPENSSL_free(der);
}

unique_free_d<OCSP_RESPONSE_free> Responder::ocspResponse(BIO *bio)
{
    auto req = make_unique_ptr<OCSP_REQUEST_free>(d2i_OCSP_REQUEST_bio(bio, nullptr));
    if(!req)
        return make_unique_ptr<OCSP_RESPONSE_free>(OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, nullptr));
    auto basic = make_unique_ptr<OCSP_BASICRESP_free>(OCSP_BASICRESP_new());
    auto thisUpdate = make_unique_ptr<ASN1_TIME_free>(X509_gmtime_adj(nullptr, 0));
    auto revocationTime = make_unique_ptr<ASN1_TIME_free>(X509_gmtime_adj(nullptr, -60 * 60));
    if(!basic || !thisUpdate || !revocationTime)
        return make_unique_ptr<OCSP_RESPONSE_free>(nullptr);

    lock_guard lock(mutex);
    for(int i = 0, count = OCSP_request_onereq_count(req.get()); i < count; ++i)
    {
        OCSP_CERTID *id = OCSP_onereq_get0_id(OCSP_request_onereq_get0(req.get(), i));
        ASN1_OBJECT *mdObj {};
        OCSP_id_get0_info(nullptr, &mdObj, nullptr, nullptr, id);
        const EVP_MD *md = EVP_get_digestbyobj(mdObj);
        int status = V_OCSP_CERTSTATUS_UNKNOWN;
        if(md && ranges::any_of(issuers, [&](const auto &issuer) {
                auto issuerId = make_unique_ptr<OCSP_CERTID_free>(OCSP_cert_to_id(md, nullptr, issuer.get()));
                return issuerId && OCSP_id_issuer_cmp(issuerId.get(), id) == 0;
            }))
        {
            status = V_OCSP_CERTSTATUS_GOOD;
            for(const CertStatus &s: statuses)
            {
                auto certId = make_unique_ptr<OCSP_CERTID_free>(OCSP_cert_to_id(md, s.cert.get(), s.issuer));
                if(certId && OCSP_id_cmp(certId.get(), id) == 0)
                    status = s.status;
            }
        }
        if(!OCSP_basic_add1_status(basic.get(), id, status, OCSP_REVOKED_STATUS_UNSPECIFIED,
                status == V_OCSP_CERTSTATUS_REVOKED ? revocationTime.get() : nullptr, thisUpdate.get(), nullptr))
            return make_unique_ptr<OCSP_RESPONSE_free>(nullptr);
    }
    if(OCSP_copy_nonce(basic.get(), req.get()) <= 0 ||
        OCSP_basic_sign(basic.get(), ocspCert.get(), ocspKey.get(), EVP_sha256(), nullptr, 0) != 1)
        return make_unique_ptr<OCSP_RESPONSE_free>(nullptr);
    return make_unique_ptr<OCSP_RESPONSE_free>(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get()));
}
