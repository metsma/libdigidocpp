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

#include <array>
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <string_view>

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

}

/**
 * Starts an RFC 3161 time-stamping service on a free 127.0.0.1 port so that
 * the signing tests do not depend on the network and the demo TSA.
 *
 * The time-stamping unit certificate and key come from @a tsaP12. The test TSL
 * (EE_T.xml) lists that certificate as a TSA/QTST service, so the tokens it
 * issues validate like the ones from a qualified TSA. The service answers POST
 * requests to tsaUrl() on a single thread, one connection at a time.
 */
Responder::Responder(const string &tsaP12, const string &tsaPass)
    : ctx(TS_RESP_CTX_new())
    , address(BIO_ADDR_new())
{
    if(!ctx || !address)
        fail("Failed to allocate the time-stamping responder");

    auto file = make_unique_ptr<BIO_free>(BIO_new_file(tsaP12.c_str(), "rb"));
    auto p12 = make_unique_ptr<PKCS12_free>(file ? d2i_PKCS12_bio(file.get(), nullptr) : nullptr);
    EVP_PKEY *key {};
    X509 *cert {};
    if(!p12 || PKCS12_parse(p12.get(), tsaPass.c_str(), &key, &cert, nullptr) != 1)
        fail("Failed to load the time-stamping unit key");
    auto keyPtr = make_unique_ptr<EVP_PKEY_free>(key);
    auto certPtr = make_unique_ptr<X509_free>(cert);
    auto policy = make_unique_ptr<ASN1_OBJECT_free>(OBJ_txt2obj("0.4.0.2023.1.1", 1)); // ETSI best practices policy
    if(TS_RESP_CTX_set_signer_cert(ctx.get(), cert) != 1 ||
        TS_RESP_CTX_set_signer_key(ctx.get(), key) != 1 ||
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
    // The OCSP responses still come from demo.sk.ee. Validation rejects a
    // signature whose time-stamp is later than the OCSP producedAt time, both
    // with one-second precision, so a local clock running slightly ahead of
    // the OCSP responder could fail a signature made right after the
    // time-stamp. Issuing the time one second early keeps that margin.
    TS_RESP_CTX_set_time_cb(ctx.get(), [](TS_RESP_CTX *, void *, long *sec, long *usec) {
        using namespace chrono;
        auto now = system_clock::now() - 1s;
        *sec = long(duration_cast<seconds>(now.time_since_epoch()).count());
        *usec = long(duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000);
        return 1;
    }, nullptr);

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
    tsa = "http://127.0.0.1:" + string(port ? port : "") + "/tsa";
    OPENSSL_free(port);
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
    // TimeStampReq that carries its own length, so Content-Length is not needed.
    array<char, 1024> line {};
    if(BIO_gets(bio.get(), line.data(), int(line.size())) <= 0)
        return;
    bool tsa = string_view(line.data()).starts_with("POST /tsa ");
    do
    {
        if(BIO_gets(bio.get(), line.data(), int(line.size())) <= 0)
            return;
        if(stop)
            return;
    }
    while(string_view(line.data()) != "\r\n");

    auto resp = make_unique_ptr<TS_RESP_free>(tsa ? TS_RESP_create_response(ctx.get(), bio.get()) : nullptr);
    if(stop)
        return;
    unsigned char *der {};
    if(int size = resp ? i2d_TS_RESP(resp.get(), &der) : -1; size > 0)
    {
        BIO_printf(bio.get(), "HTTP/1.0 200 OK\r\n"
            "Content-Type: application/timestamp-reply\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n", size);
        BIO_write(bio.get(), der, size);
    }
    else
        BIO_printf(bio.get(), "HTTP/1.0 %s\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n", tsa ? "500 Internal Server Error" : "404 Not Found");
    BIO_flush(bio.get());
    OPENSSL_free(der);
}
