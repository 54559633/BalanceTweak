#pragma once

#ifndef JJV_AUTH_TESTING
#error "JJVAuthTesting.hpp is available only in the explicit offline test build"
#endif

#include <functional>
#include <string>

namespace jjcloud { namespace testing {

struct HttpReply {
    int status = 200;
    std::string body;
    std::string error;
};

using Transport = std::function<HttpReply(const std::string& path, const std::string& body)>;

void setTransport(Transport transport);
void setServerSigningPublicKey(const std::string& publicKeyB64);
void setTimes(double wallSeconds, double monotonicSeconds);
void resetMemory(bool preserveKeychain = false);
std::string restoreStartup();
std::string syncPermanentEntitlement();
std::string heartbeat();

} }  // namespace jjcloud::testing
