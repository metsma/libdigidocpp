// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <util/memory.h>

#include <openssl/bio.h>
#include <openssl/ts.h>

#include <atomic>
#include <string>
#include <thread>

namespace digidoc::test
{

class Responder
{
public:
    Responder(const std::string &tsaP12, const std::string &tsaPass);
    ~Responder();
    Responder(const Responder &) = delete;
    Responder &operator=(const Responder &) = delete;

    const std::string &tsaUrl() const { return tsa; }

private:
    void run();
    void handle(int client);

    unique_free_d<TS_RESP_CTX_free> ctx;
    unique_free_d<BIO_ADDR_free> address;
    int socket = -1;
    std::string tsa;
    std::atomic<bool> stop {false};
    std::atomic<long> serial {0};
    std::thread thread;
};

}
