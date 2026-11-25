#include "JJCloudCore.hpp"

#include <algorithm>
#include <cstring>

namespace jjcloud {
namespace {

constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int base64UrlValue(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

inline std::uint32_t rotr32(std::uint32_t x, std::uint32_t n) {
    return (x >> n) | (x << (32U - n));
}

inline std::uint32_t loadBE32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24U) |
           (static_cast<std::uint32_t>(p[1]) << 16U) |
           (static_cast<std::uint32_t>(p[2]) << 8U) |
           static_cast<std::uint32_t>(p[3]);
}

inline void storeBE32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>((v >> 24U) & 0xffU);
    p[1] = static_cast<std::uint8_t>((v >> 16U) & 0xffU);
    p[2] = static_cast<std::uint8_t>((v >> 8U) & 0xffU);
    p[3] = static_cast<std::uint8_t>(v & 0xffU);
}

inline void storeBE64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>((v >> (56 - 8 * i)) & 0xffU);
    }
}

// ============================================================================
// SHA-256 (FIPS 180-4)
// ============================================================================
constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

struct Sha256Context {
    std::array<std::uint32_t, 8> state = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    std::array<std::uint8_t, 64> buffer{};
    std::size_t bufferLen = 0;
    std::uint64_t totalBits = 0;

    void processBlock(const std::uint8_t* block) {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i) {
            w[i] = loadBE32(block + i * 4);
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3U);
            const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = h + S1 + ch + kSha256K[i] + w[i];
            const std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    void update(const std::uint8_t* data, std::size_t len) {
        totalBits += static_cast<std::uint64_t>(len) * 8ULL;
        std::size_t offset = 0;
        if (bufferLen > 0) {
            const std::size_t take = std::min(len, 64 - bufferLen);
            std::memcpy(buffer.data() + bufferLen, data, take);
            bufferLen += take;
            offset += take;
            if (bufferLen == 64) {
                processBlock(buffer.data());
                bufferLen = 0;
            }
        }
        while (offset + 64 <= len) {
            processBlock(data + offset);
            offset += 64;
        }
        if (offset < len) {
            bufferLen = len - offset;
            std::memcpy(buffer.data(), data + offset, bufferLen);
        }
    }

    std::array<std::uint8_t, 32> finish() {
        buffer[bufferLen++] = 0x80;
        if (bufferLen > 56) {
            std::memset(buffer.data() + bufferLen, 0, 64 - bufferLen);
            processBlock(buffer.data());
            bufferLen = 0;
        }
        std::memset(buffer.data() + bufferLen, 0, 56 - bufferLen);
        storeBE64(buffer.data() + 56, totalBits);
        processBlock(buffer.data());

        std::array<std::uint8_t, 32> out{};
        for (std::size_t i = 0; i < 8; ++i) {
            storeBE32(out.data() + i * 4, state[i]);
        }
        return out;
    }
};

// ============================================================================
// AES-256 (FIPS 197) + GCM (NIST SP 800-38D)
// ============================================================================
constexpr std::array<std::uint8_t, 256> kAesSbox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

inline std::uint8_t xtime(std::uint8_t x) {
    return static_cast<std::uint8_t>((x << 1U) ^ ((x & 0x80U) ? 0x1bU : 0x00U));
}

struct Aes256KeySchedule {
    std::array<std::uint32_t, 60> rk{};

    explicit Aes256KeySchedule(const std::array<std::uint8_t, 32>& key) {
        static constexpr std::array<std::uint8_t, 8> rcon = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
        };
        for (std::size_t i = 0; i < 8; ++i) {
            rk[i] = loadBE32(key.data() + i * 4);
        }
        for (std::size_t i = 8; i < 60; ++i) {
            std::uint32_t temp = rk[i - 1];
            if (i % 8 == 0) {
                temp = (static_cast<std::uint32_t>(kAesSbox[(temp >> 16U) & 0xffU]) << 24U) |
                       (static_cast<std::uint32_t>(kAesSbox[(temp >> 8U) & 0xffU]) << 16U) |
                       (static_cast<std::uint32_t>(kAesSbox[temp & 0xffU]) << 8U) |
                       static_cast<std::uint32_t>(kAesSbox[(temp >> 24U) & 0xffU]);
                temp ^= static_cast<std::uint32_t>(rcon[i / 8]) << 24U;
            } else if (i % 8 == 4) {
                temp = (static_cast<std::uint32_t>(kAesSbox[(temp >> 24U) & 0xffU]) << 24U) |
                       (static_cast<std::uint32_t>(kAesSbox[(temp >> 16U) & 0xffU]) << 16U) |
                       (static_cast<std::uint32_t>(kAesSbox[(temp >> 8U) & 0xffU]) << 8U) |
                       static_cast<std::uint32_t>(kAesSbox[temp & 0xffU]);
            }
            rk[i] = rk[i - 8] ^ temp;
        }
    }

    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
        std::uint8_t s[16];
        for (int i = 0; i < 4; ++i) {
            const std::uint32_t w = loadBE32(in + i * 4) ^ rk[i];
            storeBE32(s + i * 4, w);
        }

        for (int round = 1; round <= 14; ++round) {
            // SubBytes + ShiftRows
            std::uint8_t t[16];
            t[0]  = kAesSbox[s[0]];  t[4]  = kAesSbox[s[4]];  t[8]  = kAesSbox[s[8]];  t[12] = kAesSbox[s[12]];
            t[1]  = kAesSbox[s[5]];  t[5]  = kAesSbox[s[9]];  t[9]  = kAesSbox[s[13]]; t[13] = kAesSbox[s[1]];
            t[2]  = kAesSbox[s[10]]; t[6]  = kAesSbox[s[14]]; t[10] = kAesSbox[s[2]];  t[14] = kAesSbox[s[6]];
            t[3]  = kAesSbox[s[15]]; t[7]  = kAesSbox[s[3]];  t[11] = kAesSbox[s[7]];  t[15] = kAesSbox[s[11]];

            if (round < 14) {
                // MixColumns
                for (int c = 0; c < 4; ++c) {
                    const std::uint8_t a0 = t[c * 4 + 0];
                    const std::uint8_t a1 = t[c * 4 + 1];
                    const std::uint8_t a2 = t[c * 4 + 2];
                    const std::uint8_t a3 = t[c * 4 + 3];
                    const std::uint8_t x = static_cast<std::uint8_t>(a0 ^ a1 ^ a2 ^ a3);
                    s[c * 4 + 0] = static_cast<std::uint8_t>(a0 ^ x ^ xtime(static_cast<std::uint8_t>(a0 ^ a1)));
                    s[c * 4 + 1] = static_cast<std::uint8_t>(a1 ^ x ^ xtime(static_cast<std::uint8_t>(a1 ^ a2)));
                    s[c * 4 + 2] = static_cast<std::uint8_t>(a2 ^ x ^ xtime(static_cast<std::uint8_t>(a2 ^ a3)));
                    s[c * 4 + 3] = static_cast<std::uint8_t>(a3 ^ x ^ xtime(static_cast<std::uint8_t>(a3 ^ a0)));
                }
            } else {
                std::memcpy(s, t, 16);
            }

            // AddRoundKey
            for (int i = 0; i < 4; ++i) {
                const std::uint32_t w = loadBE32(s + i * 4) ^ rk[round * 4 + i];
                storeBE32(s + i * 4, w);
            }
        }
        std::memcpy(out, s, 16);
    }
};

// GF(2^128) multiplication for GHASH (NIST SP 800-38D Algorithm 1).
void ghashMultiply(std::uint8_t x[16], const std::uint8_t h[16]) {
    std::uint8_t z[16] = {};
    std::uint8_t v[16];
    std::memcpy(v, h, 16);

    for (int i = 0; i < 128; ++i) {
        const std::uint8_t bit = static_cast<std::uint8_t>((x[i / 8] >> (7 - (i % 8))) & 1U);
        const std::uint8_t mask = static_cast<std::uint8_t>(-static_cast<std::int8_t>(bit));
        for (int j = 0; j < 16; ++j) {
            z[j] ^= static_cast<std::uint8_t>(v[j] & mask);
        }
        const std::uint8_t lsb = static_cast<std::uint8_t>(v[15] & 1U);
        for (int j = 15; j > 0; --j) {
            v[j] = static_cast<std::uint8_t>((v[j] >> 1U) | ((v[j - 1] & 1U) << 7U));
        }
        v[0] >>= 1U;
        if (lsb) {
            v[0] ^= 0xe1U;
        }
    }
    std::memcpy(x, z, 16);
}

void ghashUpdate(std::uint8_t y[16], const std::uint8_t h[16], const std::uint8_t* data, std::size_t len) {
    std::size_t offset = 0;
    while (offset < len) {
        const std::size_t take = std::min<std::size_t>(16, len - offset);
        for (std::size_t i = 0; i < take; ++i) {
            y[i] ^= data[offset + i];
        }
        ghashMultiply(y, h);
        offset += take;
    }
}

void computeGcmTag(const Aes256KeySchedule& aes,
                   const std::uint8_t h[16],
                   const std::uint8_t j0[16],
                   const std::vector<std::uint8_t>& aad,
                   const std::uint8_t* ciphertext,
                   std::size_t ctLen,
                   std::uint8_t tag[16]) {
    std::uint8_t y[16] = {};
    if (!aad.empty()) {
        ghashUpdate(y, h, aad.data(), aad.size());
    }
    if (ctLen > 0) {
        ghashUpdate(y, h, ciphertext, ctLen);
    }
    std::uint8_t lengths[16];
    storeBE64(lengths, static_cast<std::uint64_t>(aad.size()) * 8ULL);
    storeBE64(lengths + 8, static_cast<std::uint64_t>(ctLen) * 8ULL);
    ghashUpdate(y, h, lengths, 16);

    std::uint8_t eJ0[16];
    aes.encryptBlock(j0, eJ0);
    for (int i = 0; i < 16; ++i) {
        tag[i] = static_cast<std::uint8_t>(y[i] ^ eJ0[i]);
    }
}

void gctrCrypt(const Aes256KeySchedule& aes,
               const std::uint8_t j0[16],
               const std::uint8_t* in,
               std::uint8_t* out,
               std::size_t len) {
    std::uint8_t cb[16];
    std::memcpy(cb, j0, 16);
    std::uint32_t counter = loadBE32(cb + 12);

    std::size_t offset = 0;
    while (offset < len) {
        ++counter;
        storeBE32(cb + 12, counter);
        std::uint8_t ks[16];
        aes.encryptBlock(cb, ks);
        const std::size_t take = std::min<std::size_t>(16, len - offset);
        for (std::size_t i = 0; i < take; ++i) {
            out[offset + i] = static_cast<std::uint8_t>(in[offset + i] ^ ks[i]);
        }
        offset += take;
    }
}

void appendDerInteger(std::vector<std::uint8_t>& out, const std::uint8_t* bigEndian32) {
    std::size_t first = 0;
    while (first < 31 && bigEndian32[first] == 0) {
        ++first;
    }
    const bool needsSignByte = (bigEndian32[first] & 0x80U) != 0;
    const std::size_t len = (32 - first) + (needsSignByte ? 1 : 0);
    out.push_back(0x02);  // INTEGER
    out.push_back(static_cast<std::uint8_t>(len));
    if (needsSignByte) {
        out.push_back(0x00);
    }
    out.insert(out.end(), bigEndian32 + first, bigEndian32 + 32);
}

bool readDerInteger32(const std::vector<std::uint8_t>& der,
                      std::size_t& pos,
                      std::uint8_t out32[32]) {
    if (pos + 2 > der.size() || der[pos] != 0x02) return false;
    ++pos;
    std::size_t len = der[pos++];
    if (len == 0 || (len & 0x80U) != 0 || pos + len > der.size()) return false;
    // Reject negative integers or non-minimal leading zeros.
    if ((der[pos] & 0x80U) != 0) return false;
    if (len > 1 && der[pos] == 0x00 && (der[pos + 1] & 0x80U) == 0) return false;

    std::size_t start = pos;
    pos += len;
    while (len > 0 && der[start] == 0x00) {
        ++start;
        --len;
    }
    if (len > 32) return false;
    std::memset(out32, 0, 32);
    if (len > 0) {
        std::memcpy(out32 + (32 - len), der.data() + start, len);
    }
    return true;
}

}  // namespace

std::string base64UrlEncode(const std::uint8_t* data, std::size_t length) {
    std::string out;
    out.reserve(((length + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= length) {
        const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16U) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8U) |
                                static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kBase64UrlAlphabet[(n >> 18U) & 0x3fU]);
        out.push_back(kBase64UrlAlphabet[(n >> 12U) & 0x3fU]);
        out.push_back(kBase64UrlAlphabet[(n >> 6U) & 0x3fU]);
        out.push_back(kBase64UrlAlphabet[n & 0x3fU]);
        i += 3;
    }
    const std::size_t rem = length - i;
    if (rem == 1) {
        const std::uint32_t n = static_cast<std::uint32_t>(data[i]) << 16U;
        out.push_back(kBase64UrlAlphabet[(n >> 18U) & 0x3fU]);
        out.push_back(kBase64UrlAlphabet[(n >> 12U) & 0x3fU]);
    } else if (rem == 2) {
        const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16U) |
                                (static_cast<std::uint32_t>(data[i + 1]) << 8U);
        out.push_back(kBase64UrlAlphabet[(n >> 18U) & 0x3fU]);
        out.push_back(kBase64UrlAlphabet[(n >> 12U) & 0x3fU]);
        out.push_back(kBase64UrlAlphabet[(n >> 6U) & 0x3fU]);
    }
    return out;
}

std::string base64UrlEncode(const std::vector<std::uint8_t>& data) {
    return base64UrlEncode(data.data(), data.size());
}

std::optional<std::vector<std::uint8_t>> base64UrlDecode(const std::string& encoded) {
    if (encoded.size() % 4 == 1) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve((encoded.size() * 3) / 4);

    std::size_t i = 0;
    while (i + 4 <= encoded.size()) {
        const int v0 = base64UrlValue(static_cast<unsigned char>(encoded[i]));
        const int v1 = base64UrlValue(static_cast<unsigned char>(encoded[i + 1]));
        const int v2 = base64UrlValue(static_cast<unsigned char>(encoded[i + 2]));
        const int v3 = base64UrlValue(static_cast<unsigned char>(encoded[i + 3]));
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) return std::nullopt;
        const std::uint32_t n = (static_cast<std::uint32_t>(v0) << 18U) |
                                (static_cast<std::uint32_t>(v1) << 12U) |
                                (static_cast<std::uint32_t>(v2) << 6U) |
                                static_cast<std::uint32_t>(v3);
        out.push_back(static_cast<std::uint8_t>((n >> 16U) & 0xffU));
        out.push_back(static_cast<std::uint8_t>((n >> 8U) & 0xffU));
        out.push_back(static_cast<std::uint8_t>(n & 0xffU));
        i += 4;
    }

    const std::size_t rem = encoded.size() - i;
    if (rem == 2) {
        const int v0 = base64UrlValue(static_cast<unsigned char>(encoded[i]));
        const int v1 = base64UrlValue(static_cast<unsigned char>(encoded[i + 1]));
        if (v0 < 0 || v1 < 0 || (v1 & 0x0f) != 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
    } else if (rem == 3) {
        const int v0 = base64UrlValue(static_cast<unsigned char>(encoded[i]));
        const int v1 = base64UrlValue(static_cast<unsigned char>(encoded[i + 1]));
        const int v2 = base64UrlValue(static_cast<unsigned char>(encoded[i + 2]));
        if (v0 < 0 || v1 < 0 || v2 < 0 || (v2 & 0x03) != 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((v0 << 2) | (v1 >> 4)));
        out.push_back(static_cast<std::uint8_t>(((v1 & 0x0f) << 4) | (v2 >> 2)));
    }
    return out;
}

std::string hexEncode(const std::uint8_t* data, std::size_t length) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        out[i * 2] = kHex[data[i] >> 4U];
        out[i * 2 + 1] = kHex[data[i] & 0x0fU];
    }
    return out;
}

std::array<std::uint8_t, 32> sha256(const std::uint8_t* data, std::size_t length) {
    Sha256Context ctx;
    if (length > 0) {
        ctx.update(data, length);
    }
    return ctx.finish();
}

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    return sha256(data.data(), data.size());
}

std::array<std::uint8_t, 32> sha256(const std::string& data) {
    return sha256(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::string sha256Hex(const std::uint8_t* data, std::size_t length) {
    const auto digest = sha256(data, length);
    return hexEncode(digest.data(), digest.size());
}

std::string sha256Hex(const std::vector<std::uint8_t>& data) {
    return sha256Hex(data.data(), data.size());
}

std::string sha256Hex(const std::string& data) {
    return sha256Hex(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

std::array<std::uint8_t, 32> hmacSha256(const std::uint8_t* key,
                                        std::size_t keyLen,
                                        const std::uint8_t* data,
                                        std::size_t dataLen) {
    std::array<std::uint8_t, 64> keyBlock{};
    if (keyLen > 64) {
        const auto hashed = sha256(key, keyLen);
        std::memcpy(keyBlock.data(), hashed.data(), 32);
    } else if (keyLen > 0) {
        std::memcpy(keyBlock.data(), key, keyLen);
    }

    std::array<std::uint8_t, 64> ipad{};
    std::array<std::uint8_t, 64> opad{};
    for (std::size_t i = 0; i < 64; ++i) {
        ipad[i] = static_cast<std::uint8_t>(keyBlock[i] ^ 0x36U);
        opad[i] = static_cast<std::uint8_t>(keyBlock[i] ^ 0x5cU);
    }

    Sha256Context inner;
    inner.update(ipad.data(), 64);
    if (dataLen > 0) inner.update(data, dataLen);
    const auto innerHash = inner.finish();

    Sha256Context outer;
    outer.update(opad.data(), 64);
    outer.update(innerHash.data(), 32);
    return outer.finish();
}

std::vector<std::uint8_t> hkdfSha256(const std::vector<std::uint8_t>& ikm,
                                     const std::vector<std::uint8_t>& salt,
                                     const std::string& info,
                                     std::size_t outputLength) {
    if (outputLength == 0 || outputLength > 255U * 32U) return {};
    std::array<std::uint8_t, 32> zeroSalt{};
    const std::uint8_t* saltPtr = salt.empty() ? zeroSalt.data() : salt.data();
    const std::size_t saltLen = salt.empty() ? zeroSalt.size() : salt.size();
    const auto prk = hmacSha256(saltPtr, saltLen, ikm.data(), ikm.size());

    std::vector<std::uint8_t> okm;
    okm.reserve(outputLength);
    std::vector<std::uint8_t> previous;
    const std::size_t rounds = (outputLength + 31U) / 32U;

    for (std::size_t counter = 1; counter <= rounds; ++counter) {
        std::vector<std::uint8_t> input;
        input.reserve(previous.size() + info.size() + 1);
        input.insert(input.end(), previous.begin(), previous.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(static_cast<std::uint8_t>(counter));
        const auto block = hmacSha256(prk.data(), prk.size(), input.data(), input.size());
        previous.assign(block.begin(), block.end());
        const std::size_t take = std::min<std::size_t>(32, outputLength - okm.size());
        okm.insert(okm.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return okm;
}

std::optional<std::array<std::uint8_t, 32>> deriveLicenseGuardSessionKey(
    const std::vector<std::uint8_t>& ecdhSharedSecret,
    const std::vector<std::uint8_t>& challengeNonceRaw) {
    if (ecdhSharedSecret.empty() || challengeNonceRaw.size() != 32) {
        return std::nullopt;
    }
    const auto derived = hkdfSha256(ecdhSharedSecret, challengeNonceRaw, "LicenseGuard/v1", 32);
    if (derived.size() != 32) return std::nullopt;
    std::array<std::uint8_t, 32> key{};
    std::memcpy(key.data(), derived.data(), 32);
    return key;
}

std::vector<std::uint8_t> aes256GcmSeal(const std::array<std::uint8_t, 32>& key,
                                        const std::array<std::uint8_t, 12>& iv,
                                        const std::vector<std::uint8_t>& plaintext,
                                        const std::vector<std::uint8_t>& aad) {
    Aes256KeySchedule aes(key);
    std::uint8_t zeroBlock[16] = {};
    std::uint8_t h[16] = {};
    aes.encryptBlock(zeroBlock, h);

    std::uint8_t j0[16] = {};
    std::memcpy(j0, iv.data(), 12);
    j0[15] = 1;

    std::vector<std::uint8_t> out(12 + plaintext.size() + 16);
    std::memcpy(out.data(), iv.data(), 12);
    if (!plaintext.empty()) {
        gctrCrypt(aes, j0, plaintext.data(), out.data() + 12, plaintext.size());
    }
    computeGcmTag(aes, h, j0, aad, out.data() + 12, plaintext.size(), out.data() + 12 + plaintext.size());
    return out;
}

std::optional<std::vector<std::uint8_t>> aes256GcmOpen(const std::array<std::uint8_t, 32>& key,
                                                       const std::vector<std::uint8_t>& sealedPacket,
                                                       const std::vector<std::uint8_t>& aad) {
    if (sealedPacket.size() < 28) return std::nullopt;
    const std::size_t ctLen = sealedPacket.size() - 28;
    const std::uint8_t* iv = sealedPacket.data();
    const std::uint8_t* ct = sealedPacket.data() + 12;
    const std::uint8_t* receivedTag = sealedPacket.data() + 12 + ctLen;

    Aes256KeySchedule aes(key);
    std::uint8_t zeroBlock[16] = {};
    std::uint8_t h[16] = {};
    aes.encryptBlock(zeroBlock, h);

    std::uint8_t j0[16] = {};
    std::memcpy(j0, iv, 12);
    j0[15] = 1;

    std::uint8_t expectedTag[16] = {};
    computeGcmTag(aes, h, j0, aad, ct, ctLen, expectedTag);

    // Constant-time tag comparison.
    std::uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= static_cast<std::uint8_t>(expectedTag[i] ^ receivedTag[i]);
    }
    if (diff != 0) return std::nullopt;

    std::vector<std::uint8_t> plaintext(ctLen);
    if (ctLen > 0) {
        gctrCrypt(aes, j0, ct, plaintext.data(), ctLen);
    }
    return plaintext;
}

std::optional<std::array<std::uint8_t, 64>> ecdsaDerToRaw64(const std::vector<std::uint8_t>& der) {
    if (der.size() < 8 || der[0] != 0x30) return std::nullopt;
    std::size_t pos = 1;
    std::size_t seqLen = der[pos++];
    if ((seqLen & 0x80U) != 0) {
        const std::size_t count = seqLen & 0x7fU;
        if (count != 1 || pos >= der.size()) return std::nullopt;
        seqLen = der[pos++];
    }
    if (pos + seqLen != der.size()) return std::nullopt;

    std::array<std::uint8_t, 64> raw{};
    if (!readDerInteger32(der, pos, raw.data())) return std::nullopt;
    if (!readDerInteger32(der, pos, raw.data() + 32)) return std::nullopt;
    if (pos != der.size()) return std::nullopt;
    return raw;
}

std::vector<std::uint8_t> ecdsaRaw64ToDer(const std::array<std::uint8_t, 64>& raw64) {
    std::vector<std::uint8_t> body;
    body.reserve(70);
    appendDerInteger(body, raw64.data());
    appendDerInteger(body, raw64.data() + 32);

    std::vector<std::uint8_t> der;
    der.reserve(body.size() + 2);
    der.push_back(0x30);  // SEQUENCE
    der.push_back(static_cast<std::uint8_t>(body.size()));
    der.insert(der.end(), body.begin(), body.end());
    return der;
}

std::optional<LG1Token> parseLG1Token(const std::string& token) {
    const std::size_t firstDot = token.find('.');
    if (firstDot == std::string::npos || firstDot == 0) return std::nullopt;
    const std::size_t secondDot = token.find('.', firstDot + 1);
    if (secondDot == std::string::npos || secondDot == firstDot + 1) return std::nullopt;
    if (token.find('.', secondDot + 1) != std::string::npos) return std::nullopt;

    LG1Token parsed;
    parsed.kid = token.substr(0, firstDot);
    parsed.payloadB64 = token.substr(firstDot + 1, secondDot - firstDot - 1);
    parsed.sigB64 = token.substr(secondDot + 1);
    if (parsed.sigB64.empty()) return std::nullopt;

    const auto payload = base64UrlDecode(parsed.payloadB64);
    const auto sig = base64UrlDecode(parsed.sigB64);
    if (!payload || !sig || sig->size() != 64) return std::nullopt;

    parsed.signingInput = "LG1." + parsed.kid + "." + parsed.payloadB64;
    parsed.payloadBytes = *payload;
    std::memcpy(parsed.sigRaw64.data(), sig->data(), 64);
    return parsed;
}

std::string buildCallAAD(const std::string& appID,
                         const std::string& challengeID,
                         const std::string& challengeNonceB64,
                         const std::string& deviceKeyB64,
                         const std::string& ephemeralKeyB64) {
    return "LG1\n" + appID + "\n" + challengeID + "\n" + challengeNonceB64 + "\n" +
           deviceKeyB64 + "\n" + ephemeralKeyB64;
}

std::string buildResponseAAD(const std::string& requestAAD) {
    return requestAAD + "\nresponse";
}

std::string buildProofSigningInput(const std::string& requestAAD,
                                   const std::vector<std::uint8_t>& sealedRaw) {
    return requestAAD + "\n" + sha256Hex(sealedRaw);
}

std::string buildAppAttestSigningInput(const std::string& challengeID,
                                       const std::string& keyIDB64) {
    return "LG-AppAttest-2\n" + challengeID + "\n" + keyIDB64;
}

std::string buildV2EndpointURL(const std::string& baseURL, const std::string& path) {
    std::string normalized = baseURL.empty() ? "https://gogo.reia.top" : baseURL;
    while (!normalized.empty() && normalized.back() == '/') {
        normalized.pop_back();
    }
    if (!path.empty() && path.front() == '/') {
        return normalized + path;
    }
    return normalized + "/" + path;
}

}  // namespace jjcloud
