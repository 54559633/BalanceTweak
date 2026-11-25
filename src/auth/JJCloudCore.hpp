#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace jjcloud {

struct LG1Token {
    std::string kid;
    std::string payloadB64;
    std::string sigB64;
    std::string signingInput;  // "LG1." + kid + "." + payloadB64
    std::vector<std::uint8_t> payloadBytes;
    std::array<std::uint8_t, 64> sigRaw64;
};

// Strict canonical Base64URL without '=' padding (RFC 4648 Section 5).
std::string base64UrlEncode(const std::uint8_t* data, std::size_t length);
std::string base64UrlEncode(const std::vector<std::uint8_t>& data);
std::optional<std::vector<std::uint8_t>> base64UrlDecode(const std::string& encoded);

// Lowercase hex encoding.
std::string hexEncode(const std::uint8_t* data, std::size_t length);

// SHA-256 (FIPS 180-4).
std::array<std::uint8_t, 32> sha256(const std::uint8_t* data, std::size_t length);
std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data);
std::array<std::uint8_t, 32> sha256(const std::string& data);
std::string sha256Hex(const std::uint8_t* data, std::size_t length);
std::string sha256Hex(const std::vector<std::uint8_t>& data);
std::string sha256Hex(const std::string& data);

// HMAC-SHA256 (RFC 2104) & HKDF-SHA256 (RFC 5869).
std::array<std::uint8_t, 32> hmacSha256(const std::uint8_t* key,
                                        std::size_t keyLen,
                                        const std::uint8_t* data,
                                        std::size_t dataLen);
std::vector<std::uint8_t> hkdfSha256(const std::vector<std::uint8_t>& ikm,
                                     const std::vector<std::uint8_t>& salt,
                                     const std::string& info,
                                     std::size_t outputLength);
std::optional<std::array<std::uint8_t, 32>> deriveLicenseGuardSessionKey(
    const std::vector<std::uint8_t>& ecdhSharedSecret,
    const std::vector<std::uint8_t>& challengeNonceRaw);

// AES-256-GCM (NIST SP 800-38D): sealed packet format is iv(12B) || ciphertext || tag(16B).
std::vector<std::uint8_t> aes256GcmSeal(const std::array<std::uint8_t, 32>& key,
                                        const std::array<std::uint8_t, 12>& iv,
                                        const std::vector<std::uint8_t>& plaintext,
                                        const std::vector<std::uint8_t>& aad);
std::optional<std::vector<std::uint8_t>> aes256GcmOpen(const std::array<std::uint8_t, 32>& key,
                                                       const std::vector<std::uint8_t>& sealedPacket,
                                                       const std::vector<std::uint8_t>& aad);

// ECDSA P-256 signature format conversions: ASN.1 DER <-> fixed 64-byte r||s.
std::optional<std::array<std::uint8_t, 64>> ecdsaDerToRaw64(const std::vector<std::uint8_t>& der);
std::vector<std::uint8_t> ecdsaRaw64ToDer(const std::array<std::uint8_t, 64>& raw64);

// LicenseGuard v2 LG1 token parser & protocol signing/AAD builders.
std::optional<LG1Token> parseLG1Token(const std::string& token);
std::string buildCallAAD(const std::string& appID,
                         const std::string& challengeID,
                         const std::string& challengeNonceB64,
                         const std::string& deviceKeyB64,
                         const std::string& ephemeralKeyB64);
std::string buildResponseAAD(const std::string& requestAAD);
std::string buildProofSigningInput(const std::string& requestAAD,
                                   const std::vector<std::uint8_t>& sealedRaw);
std::string buildAppAttestSigningInput(const std::string& challengeID,
                                       const std::string& keyIDB64);
std::string buildV2EndpointURL(const std::string& baseURL, const std::string& path);

}  // namespace jjcloud
