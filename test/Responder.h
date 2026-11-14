// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <util/memory.h>

#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/ts.h>

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace digidoc::test
{

class Responder
{
public:
    Responder(const char *tsaP12, const char *tsaPass, const char *ocspP12, const char *ocspPass);
    ~Responder();
    Responder(const Responder &) = delete;
    Responder &operator=(const Responder &) = delete;

    void addIssuer(X509 *issuer);
    void setStatus(X509 *cert, int status);
    const std::string &tsaUrl() const { return tsa; }
    const std::string &ocspUrl() const { return ocsp; }

private:
    struct CertStatus
    {
        unique_free_d<X509_free> cert;
        X509 *issuer;
        int status;
    };

    void run();
    void handle(int client);
    unique_free_d<OCSP_RESPONSE_free> ocspResponse(BIO *bio);

    unique_free_d<TS_RESP_CTX_free> ctx;
    unique_free_d<X509_free> ocspCert;
    unique_free_d<EVP_PKEY_free> ocspKey;
    std::vector<unique_free_d<X509_free>> issuers;
    std::vector<CertStatus> statuses;
    std::mutex mutex;
    unique_free_d<BIO_ADDR_free> address;
    int socket = -1;
    std::string tsa, ocsp;
    std::atomic<bool> stop {false};
    std::atomic<long> serial {0};
    std::thread thread;
};

}
