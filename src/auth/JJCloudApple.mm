#include "JJCloudAppleBridge.hpp"
#include "JJCloudAuthInternal.hpp"
#include "JJCloudCore.hpp"
#include "JJVServerConfig.h"
#ifdef JJV_AUTH_TESTING
#include "JJVAuthTesting.hpp"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <sys/sysctl.h>
#include <utility>
#include <vector>
#include <mach/mach_time.h>

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <TargetConditionals.h>
#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
#import "DYYLIAmapSearch.h"
#else
#import <AppKit/AppKit.h>
#endif

namespace {

// Standard ASN.1 SubjectPublicKeyInfo headers prepended to SecKeyCopyExternalRepresentation output.
std::optional<std::vector<std::uint8_t>> computeSpkiPinData(SecKeyRef pubKey) {
    if (!pubKey) return std::nullopt;
    CFDictionaryRef attrsRef = SecKeyCopyAttributes(pubKey);
    if (!attrsRef) return std::nullopt;
    NSDictionary *attrs = CFBridgingRelease(attrsRef);
    CFErrorRef err = nullptr;
    CFDataRef rawRef = SecKeyCopyExternalRepresentation(pubKey, &err);
    if (err) CFRelease(err);
    if (!rawRef) return std::nullopt;
    NSData *raw = CFBridgingRelease(rawRef);

    NSString *keyType = attrs[(__bridge id)kSecAttrKeyType];
    NSInteger keySize = [attrs[(__bridge id)kSecAttrKeySizeInBits] integerValue];

    static const std::uint8_t kEcP256Hdr[] = {
        0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
        0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00
    };
    static const std::uint8_t kEcP384Hdr[] = {
        0x30,0x76,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
        0x06,0x05,0x2b,0x81,0x04,0x00,0x22,0x03,0x62,0x00
    };
    static const std::uint8_t kRsa2048Hdr[] = {
        0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,
        0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00
    };
    static const std::uint8_t kRsa4096Hdr[] = {
        0x30,0x82,0x02,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,
        0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x02,0x0f,0x00
    };

    const std::uint8_t *hdr = nullptr;
    std::size_t hdrLen = 0;
    if ([keyType isEqual:(__bridge id)kSecAttrKeyTypeECSECPrimeRandom]) {
        if (keySize == 256) { hdr = kEcP256Hdr; hdrLen = sizeof(kEcP256Hdr); }
        else if (keySize == 384) { hdr = kEcP384Hdr; hdrLen = sizeof(kEcP384Hdr); }
    } else if ([keyType isEqual:(__bridge id)kSecAttrKeyTypeRSA]) {
        if (keySize == 2048) { hdr = kRsa2048Hdr; hdrLen = sizeof(kRsa2048Hdr); }
        else if (keySize == 4096) { hdr = kRsa4096Hdr; hdrLen = sizeof(kRsa4096Hdr); }
    }
    if (!hdr) return std::nullopt;

    std::vector<std::uint8_t> spki;
    spki.reserve(hdrLen + raw.length);
    spki.insert(spki.end(), hdr, hdr + hdrLen);
    const auto *rawBytes = static_cast<const std::uint8_t *>(raw.bytes);
    spki.insert(spki.end(), rawBytes, rawBytes + raw.length);
    return spki;
}

BOOL certificateMatchesSpkiPins(SecCertificateRef cert, NSSet<NSString *> *pins) {
    if (!cert) return NO;
    SecKeyRef pubKey = SecCertificateCopyKey(cert);
    if (!pubKey) return NO;
    auto spki = computeSpkiPinData(pubKey);
    CFRelease(pubKey);
    if (!spki) return NO;
    auto digest = jjcloud::sha256(*spki);
    std::string b64 = jjcloud::base64UrlEncode(digest.data(), digest.size());
    NSString *pin = [NSString stringWithUTF8String:b64.c_str()];
    return pin && [pins containsObject:pin];
}

}  // namespace

// Reject redirects and enforce TLS SPKI certificate pinning against configured GOGO pins.
@interface JJVAuthSessionDelegate : NSObject <NSURLSessionDelegate, NSURLSessionTaskDelegate>
@property (nonatomic, copy) NSString *pinnedHost;
@property (nonatomic, copy) NSSet<NSString *> *pinnedSpkiHashes;
@end

@implementation JJVAuthSessionDelegate

- (void)URLSession:(__unused NSURLSession *)session
              task:(__unused NSURLSessionTask *)task
willPerformHTTPRedirection:(__unused NSHTTPURLResponse *)response
        newRequest:(__unused NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest *))completionHandler {
    completionHandler(nil);
}

- (void)URLSession:(__unused NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler {
    NSURLProtectionSpace *space = challenge.protectionSpace;
    if (![space.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] || !space.serverTrust) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }
    if (self.pinnedHost.length > 0 && ![space.host.lowercaseString isEqualToString:self.pinnedHost.lowercaseString]) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    SecTrustRef trust = space.serverTrust;
    CFErrorRef trustError = nullptr;
    BOOL trusted = SecTrustEvaluateWithError(trust, &trustError);
    if (trustError) CFRelease(trustError);
    if (!trusted) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }
    if (self.pinnedSpkiHashes.count == 0) {
        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
        return;
    }

    BOOL pinMatched = NO;
    if (@available(iOS 15.0, macOS 12.0, *)) {
        CFArrayRef chainRef = SecTrustCopyCertificateChain(trust);
        NSArray *chain = chainRef ? CFBridgingRelease(chainRef) : @[];
        for (id certObj in chain) {
            if (certificateMatchesSpkiPins((__bridge SecCertificateRef)certObj, self.pinnedSpkiHashes)) {
                pinMatched = YES;
                break;
            }
        }
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        CFIndex count = SecTrustGetCertificateCount(trust);
        for (CFIndex idx = 0; idx < count; ++idx) {
            if (certificateMatchesSpkiPins(SecTrustGetCertificateAtIndex(trust, idx), self.pinnedSpkiHashes)) {
                pinMatched = YES;
                break;
            }
        }
#pragma clang diagnostic pop
    }

    if (pinMatched) {
        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
    } else {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

@end

namespace jjcloud {
namespace {

constexpr double kHeartbeatIntervalSeconds = 180.0;
constexpr double kMaxOfflineLicenseSeconds = 86400.0;
constexpr double kClockRollbackToleranceSeconds = 120.0;
NSString *const kAuthService = @"com.dyyli.locationtweak.jjcloud";
NSString *const kDeviceKeyTag = @"com.dyyli.locationtweak.jjcloud.device_p256";
NSString *const kAccountHwHash = @"v2_hw_hash";
NSString *const kAccountSession = @"v2_session";
NSString *const kAccountOfflineLicense = @"v2_offline_license";
NSString *const kAccountPermanentLicense = @"v2_permanent_license";
NSString *const kAccountPermanentReceiptSerial = @"v2_permanent_receipt_serial";
NSString *const kAccountClockWatermark = @"v2_clock_watermark";
NSString *const kAccountAmapKey = @"v2_amap_key";

NSString *buildVersionString() {
    return @"" JJV_BUILD_VERSION;
}

NSString *diagnosticLogFileName() {
    return [NSString stringWithFormat:@"dyyli-startup-%@.log", buildVersionString()];
}

struct AuthorizationState {
    bool authorized = false;
    bool permanentOffline = false;
    bool startupRestoreAttempted = false;
    bool inFlight = false;
    std::uint64_t generation = 0;
    // 调用租约栅栏。generation 表示鉴权状态纪元，只由 revoke/expire/verify 推进；
    // callLeaseId 表示当前 inFlight 归属哪一次调用，申领与看门狗回收都推进它。
    // 两者必须分开：否则看门狗回收后，迟到完成会误命中旧栅栏并顶掉新持有者。
    std::uint64_t callLeaseId = 0;

    std::string sessionToken;
    double sessionExpWall = 0;
    double sessionSteadyDeadline = 0;
    double nextHeartbeatSteady = 0;

    double offlineExpWall = 0;
    double vipWall = 0;
    double serverSyncWall = 0;
    double serverSyncMono = 0;
    bool hasServerClock = false;

    double watermarkWall = 0;
    double watermarkMono = 0;
    long long watermarkBootSec = 0;
    double lastWatermarkPersistMono = -1000.0;
    bool hasWatermark = false;
};

std::mutex gStateMutex;
AuthorizationState gState;
std::mutex gStorageMutex;
std::mutex gDiagnosticMutex;
NSDictionary *gDiagnosticSnapshot;
NSString *gDiagnosticLastSignature;

#ifdef JJV_AUTH_TESTING
std::mutex gTestMutex;
testing::Transport gTestTransport;
std::string gTestServerSigningPubB64;
SecKeyRef gTestServerSigningKey = nullptr;
NSMutableDictionary<NSString *, NSString *> *gTestKeychain = nil;
double gTestWall = 1800000000;
double gTestSteady = 1000;
#endif

long long currentBootTimeSeconds() {
    struct timeval tv{};
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    std::size_t size = sizeof(tv);
    return sysctl(mib, 2, &tv, &size, nullptr, 0) == 0 ? static_cast<long long>(tv.tv_sec) : 0;
}

bool parseUnsignedInt(id value, long long& result, bool allowZero) {
    if ([value isKindOfClass:NSNumber.class] &&
        CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) {
        return false;
    }
    NSString *text = [value isKindOfClass:NSNumber.class] ? [(NSNumber *)value stringValue] : strictString(value);
    if (text.length == 0) return false;
    const char *p = text.UTF8String;
    if (!p || !*p) return false;
    for (const char *q = p; *q; ++q) {
        if (*q < '0' || *q > '9') return false;
    }
    errno = 0;
    char *end = nullptr;
    long long parsed = std::strtoll(p, &end, 10);
    if (errno == ERANGE || !end || *end || (allowZero ? parsed < 0 : parsed <= 0)) return false;
    result = parsed;
    return true;
}

bool positiveInteger(id value, long long& result) { return parseUnsignedInt(value, result, false); }
bool nonNegativeInteger(id value, long long& result) { return parseUnsignedInt(value, result, true); }

RuntimeConfig trustedConfig() {
    return {JJV_TRUSTED_BASE_URL, JJV_TRUSTED_APP_ID, JJV_DEFAULT_APP_KEY, 45, false};
}

NSData *canonicalJSONData(NSDictionary *dictionary) {
    NSJSONWritingOptions opts = NSJSONWritingSortedKeys;
    if (@available(iOS 13.0, macOS 10.15, *)) {
        opts |= NSJSONWritingWithoutEscapingSlashes;
    }
    return [NSJSONSerialization dataWithJSONObject:dictionary options:opts error:nil];
}

std::string jsonForDictionary(NSDictionary *dictionary) {
    NSData *data = canonicalJSONData(dictionary);
    return data
        ? cpp([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding])
        : "{\"ok\":false,\"response_verified\":false,\"error\":\"serialization failed\"}";
}

std::vector<std::uint8_t> bytesFromNSData(NSData *data) {
    if (!data || data.length == 0) return {};
    const auto *p = static_cast<const std::uint8_t *>(data.bytes);
    return std::vector<std::uint8_t>(p, p + data.length);
}

NSData *nsDataFromBytes(const std::vector<std::uint8_t>& bytes) {
    return [NSData dataWithBytes:bytes.data() length:bytes.size()];
}

NSData *nsDataFromString(const std::string& text) {
    return [NSData dataWithBytes:text.data() length:text.size()];
}

bool randomBytes(std::uint8_t *out, std::size_t len) {
    return SecRandomCopyBytes(kSecRandomDefault, len, out) == errSecSuccess;
}

// ============================================================================
// Keychain Storage (Device P-256 Private Key, Session, Offline License, Watermark)
// Plaintext kami is NEVER stored (§13).
// ============================================================================
#ifndef JJV_AUTH_TESTING
NSMutableDictionary *keychainQuery(NSString *account) {
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kAuthService,
        (__bridge id)kSecAttrAccount: account
    } mutableCopy];
}
#endif

NSString *readSecretLocked(NSString *account) {
#ifdef JJV_AUTH_TESTING
    return gTestKeychain ? gTestKeychain[account] : nil;
#else
    NSMutableDictionary *query = keychainQuery(account);
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef value = nullptr;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &value);
    NSData *data = value ? CFBridgingRelease(value) : nil;
    return status == errSecSuccess && [data isKindOfClass:NSData.class]
        ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
        : nil;
#endif
}

bool writeSecretLocked(NSString *account, NSString *text) {
#ifdef JJV_AUTH_TESTING
    if (!gTestKeychain) gTestKeychain = [NSMutableDictionary dictionary];
    if (text) gTestKeychain[account] = [text copy];
    else [gTestKeychain removeObjectForKey:account];
    return true;
#else
    NSMutableDictionary *query = keychainQuery(account);
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) return false;
    NSDictionary *update = @{(__bridge id)kSecValueData: data};
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
    if (status == errSecItemNotFound) {
        query[(__bridge id)kSecValueData] = data;
#if TARGET_OS_IPHONE
        query[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
#endif
        status = SecItemAdd((__bridge CFDictionaryRef)query, nullptr);
    }
    return status == errSecSuccess;
#endif
}

void deleteSecretLocked(NSString *account) {
#ifdef JJV_AUTH_TESTING
    [gTestKeychain removeObjectForKey:account];
#else
    SecItemDelete((__bridge CFDictionaryRef)keychainQuery(account));
#endif
}

void purgeLegacyPlaintextCredentialsLocked() {
#ifdef JJV_AUTH_TESTING
    deleteSecretLocked(@"kami");
#else
    // §13: Never persist kami plaintext anywhere on device.
    deleteSecretLocked(@"kami");
    NSString *legacyFile = [NSHomeDirectory() stringByAppendingPathComponent:
        @"Documents/com.dyyli.locationtweak.jjcloud.auth.json"];
    [[NSFileManager defaultManager] removeItemAtPath:legacyFile error:nil];
    for (NSString *name in @[@"kami", @"markcode", @"verified", @"verified_at", @"vip", @"raw"]) {
        [NSUserDefaults.standardUserDefaults removeObjectForKey:[kAuthService stringByAppendingFormat:@".%@", name]];
    }
#endif
}

struct DeviceIdentity {
    SecKeyRef privateKey = nullptr;  // Retained while alive via gDeviceIdentity
    std::vector<std::uint8_t> publicKeyRaw;  // 65 bytes X9.62 uncompressed (0x04...)
    std::string publicKeyB64;
    std::string deviceIdHex;  // sha256(publicKeyRaw) hex (64 chars)
    std::string hwHash;
    bool ready = false;
};

DeviceIdentity gDeviceIdentity;

bool extractRawUncompressedP256PublicKey(SecKeyRef privateKey, std::vector<std::uint8_t>& outRaw65) {
    SecKeyRef pubKey = SecKeyCopyPublicKey(privateKey);
    if (!pubKey) return false;
    CFErrorRef err = nullptr;
    CFDataRef rawRef = SecKeyCopyExternalRepresentation(pubKey, &err);
    CFRelease(pubKey);
    if (err) CFRelease(err);
    if (!rawRef) return false;
    NSData *raw = CFBridgingRelease(rawRef);
    const auto *bytes = static_cast<const std::uint8_t *>(raw.bytes);
    if (raw.length == 65 && bytes[0] == 0x04) {
        outRaw65.assign(bytes, bytes + 65);
        return true;
    }
    if (raw.length == 64) {
        outRaw65.clear();
        outRaw65.reserve(65);
        outRaw65.push_back(0x04);
        outRaw65.insert(outRaw65.end(), bytes, bytes + 64);
        return true;
    }
    return false;
}

SecKeyRef loadOrCreateDevicePrivateKeyLocked() {
    CFErrorRef err = nullptr;
    SecKeyRef created = nullptr;
#ifndef JJV_AUTH_TESTING
    NSData *tagData = [kDeviceKeyTag dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag: tagData,
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecReturnRef: @YES
    };
    CFTypeRef keyRef = nullptr;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &keyRef);
    if (status == errSecSuccess && keyRef) {
        return (SecKeyRef)keyRef;
    }

    NSMutableDictionary *privateAttrs = [@{
        (__bridge id)kSecAttrIsPermanent: @YES,
        (__bridge id)kSecAttrApplicationTag: tagData,
    } mutableCopy];
#if TARGET_OS_IPHONE
    privateAttrs[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
#endif
    NSDictionary *keyParams = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
        (__bridge id)kSecPrivateKeyAttrs: privateAttrs
    };
    created = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyParams, &err);
    if (err) { CFRelease(err); err = nullptr; }
    if (created) return created;
#endif

    // Fallback: in-memory ephemeral key if Keychain is unavailable (or in isolated test build).
    NSDictionary *ephemeralParams = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256,
    };
    created = SecKeyCreateRandomKey((__bridge CFDictionaryRef)ephemeralParams, &err);
    if (err) CFRelease(err);
    return created;
}

bool ensureDeviceIdentity() {
    std::lock_guard<std::mutex> lock(gStorageMutex);
    if (gDeviceIdentity.ready) return true;

    purgeLegacyPlaintextCredentialsLocked();

    SecKeyRef priv = loadOrCreateDevicePrivateKeyLocked();
    if (!priv) return false;
    std::vector<std::uint8_t> pubRaw;
    if (!extractRawUncompressedP256PublicKey(priv, pubRaw)) {
        CFRelease(priv);
        return false;
    }

    NSString *hwHash = readSecretLocked(kAccountHwHash);
    if (hwHash.length < 16 || hwHash.length > 64) {
        std::string seed = sha256Hex(pubRaw);
#if TARGET_OS_IPHONE
        NSString *idfv = UIDevice.currentDevice.identifierForVendor.UUIDString;
        if (idfv.length) seed += "|" + cpp(idfv);
#endif
        hwHash = ns(sha256Hex(seed));
        writeSecretLocked(kAccountHwHash, hwHash);
    }

    // Restore cached dynamic AMap key if present.
#if TARGET_OS_IPHONE
    NSString *cachedAmap = readSecretLocked(kAccountAmapKey);
    if (cachedAmap.length > 0) {
        DYYLISetDynamicAmapWebServiceKey(cachedAmap);
    }
#endif

    gDeviceIdentity.privateKey = priv;
    gDeviceIdentity.publicKeyRaw = std::move(pubRaw);
    gDeviceIdentity.publicKeyB64 = base64UrlEncode(gDeviceIdentity.publicKeyRaw);
    gDeviceIdentity.deviceIdHex = sha256Hex(gDeviceIdentity.publicKeyRaw);
    gDeviceIdentity.hwHash = cpp(hwHash);
    gDeviceIdentity.ready = true;
    return true;
}

// ============================================================================
// P-256 ECDSA Verify / Sign & ECDH Key Exchange (Security.framework)
// ============================================================================
SecKeyRef importP256PublicKey(const std::vector<std::uint8_t>& raw65) {
    if (raw65.size() != 65 || raw65[0] != 0x04) return nullptr;
    NSDictionary *attrs = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @256
    };
    CFErrorRef err = nullptr;
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)nsDataFromBytes(raw65),
                                         (__bridge CFDictionaryRef)attrs, &err);
    if (err) CFRelease(err);
    return key;
}

SecKeyRef pinnedServerSigningKey(const std::string& kid) {
    if (kid != JJV_SIGNING_KEY_ID) return nullptr;
#ifdef JJV_AUTH_TESTING
    {
        std::lock_guard<std::mutex> lock(gTestMutex);
        if (gTestServerSigningKey) return gTestServerSigningKey;
    }
#endif
    static SecKeyRef cachedKey = nullptr;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        auto raw = base64UrlDecode(JJV_SIGNING_PUBLIC_KEY);
        if (raw) {
            cachedKey = importP256PublicKey(*raw);
        }
    });
    return cachedKey;
}

NSDictionary *verifyAndDecodeLG1Token(const std::string& token, std::string *outError = nullptr) {
    auto parsed = parseLG1Token(token);
    if (!parsed) {
        if (outError) *outError = "令牌格式无效";
        return nil;
    }
    SecKeyRef signingKey = pinnedServerSigningKey(parsed->kid);
    if (!signingKey) {
        if (outError) *outError = "未知服务器签名密钥";
        return nil;
    }
    const auto derSig = ecdsaRaw64ToDer(parsed->sigRaw64);
    CFErrorRef err = nullptr;
    BOOL valid = SecKeyVerifySignature(
        signingKey,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        (__bridge CFDataRef)nsDataFromString(parsed->signingInput),
        (__bridge CFDataRef)nsDataFromBytes(derSig),
        &err);
    if (err) CFRelease(err);
    if (!valid) {
        if (outError) *outError = "服务器签名校验失败";
        return nil;
    }
    id jsonObj = [NSJSONSerialization JSONObjectWithData:nsDataFromBytes(parsed->payloadBytes) options:0 error:nil];
    if (![jsonObj isKindOfClass:NSDictionary.class]) {
        if (outError) *outError = "令牌载荷不是有效 JSON";
        return nil;
    }
    return (NSDictionary *)jsonObj;
}

std::optional<std::string> signWithDeviceKeyB64(const std::string& message) {
    if (!ensureDeviceIdentity()) return std::nullopt;
    CFErrorRef err = nullptr;
    CFDataRef derRef = SecKeyCreateSignature(
        gDeviceIdentity.privateKey,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        (__bridge CFDataRef)nsDataFromString(message),
        &err);
    if (err) CFRelease(err);
    if (!derRef) return std::nullopt;
    NSData *derData = CFBridgingRelease(derRef);
    auto raw64 = ecdsaDerToRaw64(bytesFromNSData(derData));
    if (!raw64) return std::nullopt;
    return base64UrlEncode(raw64->data(), raw64->size());
}

// ============================================================================
// Monotonic Clock Watermark & Effective Wall Time (§13)
// ============================================================================
void loadClockWatermarkLocked() {
    if (gState.hasWatermark) return;
    NSString *json = readSecretLocked(kAccountClockWatermark);
    NSDictionary *dict = json ? dictionaryFromJSON(cpp(json)) : nil;
    if (!dict) return;
    double w = [dict[@"wall"] doubleValue];
    double m = [dict[@"mono"] doubleValue];
    long long b = [dict[@"boot_sec"] longLongValue];
    if (std::isfinite(w) && w > 0 && std::isfinite(m) && m >= 0) {
        gState.watermarkWall = w;
        gState.watermarkMono = m;
        gState.watermarkBootSec = b;
        gState.hasWatermark = true;
    }
}

void updateServerClockAndWatermark(double serverWall) {
    if (!std::isfinite(serverWall) || serverWall <= 0) return;
    const double mono = steadyNow();
    const long long bootSec = currentBootTimeSeconds();
    double persistedWall = serverWall;
    bool shouldPersist = false;
    {
        std::lock_guard<std::mutex> lock(gStateMutex);
        gState.serverSyncWall = serverWall;
        gState.serverSyncMono = mono;
        gState.hasServerClock = true;

        const double nextMaxWall = std::max(serverWall, gState.watermarkWall);
        const bool bootChanged = (gState.watermarkBootSec != bootSec);
        if (!gState.hasWatermark || nextMaxWall > gState.watermarkWall || bootChanged) {
            shouldPersist = !gState.hasWatermark || bootChanged ||
                            (mono - gState.lastWatermarkPersistMono >= 30.0) ||
                            (nextMaxWall - gState.watermarkWall >= 30.0);
            gState.watermarkWall = nextMaxWall;
            gState.watermarkMono = mono;
            gState.watermarkBootSec = bootSec;
            gState.hasWatermark = true;
            if (shouldPersist) gState.lastWatermarkPersistMono = mono;
        }
        persistedWall = gState.watermarkWall;
    }
    if (shouldPersist) {
        std::lock_guard<std::mutex> slock(gStorageMutex);
        NSDictionary *wm = @{@"wall": @(persistedWall), @"mono": @(mono), @"boot_sec": @(bootSec)};
        writeSecretLocked(kAccountClockWatermark, ns(jsonForDictionary(wm)));
    }
}

double effectiveWallLocked() {
    // Once synced with server in this process, advance strictly via monotonic clock so
    // manual system clock rollbacks cannot extend sessions or offline licenses.
    double now = gState.hasServerClock
        ? (gState.serverSyncWall + std::max(0.0, steadyNow() - gState.serverSyncMono))
        : wallNow();
    if (gState.hasWatermark) {
        const long long bootSec = currentBootTimeSeconds();
        if (bootSec > 0 && bootSec == gState.watermarkBootSec) {
            const double monoFloor = gState.watermarkWall + std::max(0.0, steadyNow() - gState.watermarkMono);
            if (now < monoFloor - kClockRollbackToleranceSeconds) {
                now = monoFloor;
            }
        } else if (now < gState.watermarkWall) {
            now = gState.watermarkWall;
        }
    }
    return now;
}

bool liveAuthorizationLocked() {
    if (!gState.authorized) return false;
    if (gState.permanentOffline) return true;
    const double now = effectiveWallLocked();
    const bool offlineLive = (gState.offlineExpWall > 0 && now < gState.offlineExpWall);
    const bool sessionLive = (!gState.sessionToken.empty() && now < gState.sessionExpWall &&
                              steadyNow() < gState.sessionSteadyDeadline);
    return offlineLive || sessionLive;
}

bool expireAuthorizationLocked() {
    if (!gState.authorized || liveAuthorizationLocked()) return false;
    gState.authorized = false;
    gState.permanentOffline = false;
    gState.sessionToken.clear();
    gState.sessionExpWall = 0;
    gState.sessionSteadyDeadline = 0;
    gState.offlineExpWall = 0;
    gState.inFlight = false;
    ++gState.generation;
    return true;
}

void persistAmapKeyIfPresent(NSDictionary *msg) {
    if (![msg isKindOfClass:NSDictionary.class]) return;
    NSString *amapKey = trimmed(strictString(msg[@"amap_key"]));
    if (amapKey.length == 0) return;
#if TARGET_OS_IPHONE
    DYYLISetDynamicAmapWebServiceKey(amapKey);
#endif
    std::lock_guard<std::mutex> lock(gStorageMutex);
    writeSecretLocked(kAccountAmapKey, amapKey);
}

// ============================================================================
// Offline & Permanent License Verification (§7)
// ============================================================================
struct VerifiedOfflineLicense {
    bool valid = false;
    bool permanent = false;
    double expWall = 0;
    double iatWall = 0;
    std::string serial;
};

VerifiedOfflineLicense verifyOfflineLicenseToken(const std::string& token, const std::string& expectedDeviceId) {
    VerifiedOfflineLicense result;
    if (token.empty() || expectedDeviceId.empty()) return result;
    NSDictionary *claims = verifyAndDecodeLG1Token(token);
    if (!claims) return result;

    long long v = 0;
    if (!positiveInteger(claims[@"v"], v) || v != 1) return result;
    if (![strictString(claims[@"app"]) isEqualToString:ns(trustedConfig().appID)]) return result;
    if (![strictString(claims[@"device"]) isEqualToString:ns(expectedDeviceId)]) return result;

    NSString *purpose = strictString(claims[@"purpose"]);
    long long iat = 0;
    if (positiveInteger(claims[@"iat"], iat)) {
        result.iatWall = static_cast<double>(iat);
    }

    if ([purpose isEqualToString:@"permanent_offline_license"]) {
        result.valid = true;
        result.permanent = true;
        result.serial = cpp(trimmed(strictString(claims[@"serial"])));
        return result;
    }
    if ([purpose isEqualToString:@"offline_license"]) {
        long long exp = 0;
        if (!positiveInteger(claims[@"exp"], exp)) return result;
        // Enforce upper bound <= 24h from iat when iat is present.
        double effectiveExp = static_cast<double>(exp);
        if (result.iatWall > 0) {
            effectiveExp = std::min(effectiveExp, result.iatWall + kMaxOfflineLicenseSeconds);
        }
        result.valid = true;
        result.permanent = false;
        result.expWall = effectiveExp;
        return result;
    }
    return result;
}

void clearPersistedAuthArtifacts() {
    std::lock_guard<std::mutex> lock(gStorageMutex);
    deleteSecretLocked(kAccountSession);
    deleteSecretLocked(kAccountOfflineLicense);
    deleteSecretLocked(kAccountPermanentLicense);
    deleteSecretLocked(kAccountPermanentReceiptSerial);
}

void persistSessionToKeychain(const std::string& sessionToken, double sessionExp, double vipWall) {
    std::lock_guard<std::mutex> lock(gStorageMutex);
    if (sessionToken.empty() || sessionExp <= 0) {
        deleteSecretLocked(kAccountSession);
        return;
    }
    NSDictionary *payload = @{
        @"session": ns(sessionToken),
        @"session_exp": @(static_cast<long long>(sessionExp)),
        @"vip": @(static_cast<long long>(vipWall))
    };
    writeSecretLocked(kAccountSession, ns(jsonForDictionary(payload)));
}

// ============================================================================
// HTTPS Transport with Certificate Pinning + Redirect Blocking
// ============================================================================
#ifndef JJV_AUTH_TESTING
NSURLSession *sharedAuthSession() {
    static NSURLSession *session;
    static JJVAuthSessionDelegate *delegate;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSURLSessionConfiguration *configuration = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        configuration.connectionProxyDictionary = @{};
        configuration.HTTPCookieStorage = nil;
        configuration.URLCache = nil;
        configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        configuration.timeoutIntervalForRequest = 15;
        configuration.timeoutIntervalForResource = 18;
        delegate = [JJVAuthSessionDelegate new];
        NSURL *base = [NSURL URLWithString:ns(trustedConfig().baseURL)];
        delegate.pinnedHost = base.host;
        NSMutableSet<NSString *> *pins = [NSMutableSet set];
        NSString *pin1 = @"" JJV_CERT_PIN_1;
        NSString *pin2 = @"" JJV_CERT_PIN_2;
        if (pin1.length > 0) [pins addObject:pin1];
        if (pin2.length > 0) [pins addObject:pin2];
        delegate.pinnedSpkiHashes = [pins copy];
        session = [NSURLSession sessionWithConfiguration:configuration delegate:delegate delegateQueue:nil];
    });
    return session;
}
#endif

struct HttpReply {
    int status = 0;
    std::string body;
    std::string error;
};

HttpReply postJSON(const std::string& path, NSDictionary *payload) {
    NSData *bodyData = canonicalJSONData(payload);
    if (!bodyData) return {0, "", "请求编码失败"};
#ifdef JJV_AUTH_TESTING
    testing::Transport transport;
    {
        std::lock_guard<std::mutex> lock(gTestMutex);
        transport = gTestTransport;
    }
    if (!transport) return {0, "", "offline test transport is unset"};
    std::string bodyStr(static_cast<const char *>(bodyData.bytes), bodyData.length);
    auto reply = transport(path, bodyStr);
    return {reply.status, reply.body, reply.error};
#else
    RuntimeConfig config = trustedConfig();
    NSURL *url = [NSURL URLWithString:ns(buildV2EndpointURL(config.baseURL, path))];
    if (!url || ![url.scheme.lowercaseString isEqualToString:@"https"]) {
        return {0, "", "授权服务器地址配置无效"};
    }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    request.timeoutInterval = 15;
    request.HTTPBody = bodyData;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    NSURLSession *session = sharedAuthSession();
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSData *responseData = nil;
    __block NSInteger responseStatus = 0;
    __block NSError *responseError = nil;
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
                                            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        responseData = data;
        responseError = error;
        responseStatus = [response isKindOfClass:NSHTTPURLResponse.class] ? [(NSHTTPURLResponse *)response statusCode] : 0;
        dispatch_semaphore_signal(semaphore);
    }];
    [task resume];
    if (dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 18 * NSEC_PER_SEC)) != 0) {
        [task cancel];
        return {0, "", "验证连接超时，请检查网络后重试"};
    }
    if (responseError) return {0, "", "无法连接验证服务器，请检查网络后重试"};
    if (responseData.length > 1024 * 1024) return {0, "", "验证响应过大"};
    NSString *text = responseData ? [[NSString alloc] initWithData:responseData encoding:NSUTF8StringEncoding] : nil;
    if (!text) return {0, "", "验证响应格式无效"};
    return {static_cast<int>(responseStatus), cpp(text), ""};
#endif
}

NSString *friendlyHttpError(NSDictionary *errObj, int httpStatus) {
    NSString *code = strictString(errObj[@"error"]) ?: @"";
    if ([code isEqualToString:@"device_blocked"]) {
        NSString *msg = trimmed(strictString(errObj[@"message"]));
        NSString *contact = trimmed(strictString(errObj[@"contact"]));
        NSString *prefix = trimmed(strictString(errObj[@"device_prefix"]));
        NSMutableString *out = [NSMutableString stringWithString:msg.length ? msg : @"当前设备已被封禁，请联系管理员处理"];
        if (contact.length) [out appendFormat:@"\n联系方式：%@", contact];
        if (prefix.length) [out appendFormat:@"\n设备编号：%@", prefix];
        return out;
    }
    if ([code isEqualToString:@"device_deleted"]) return @"设备记录已被后台移除，请重新输入卡密激活";
    if ([code isEqualToString:@"hardware_mismatch"]) return @"设备硬件指纹不匹配，请联系管理员";
    if ([code isEqualToString:@"online_login_required"]) return @"在线会话已到期，请重新验证卡密";
    if ([code isEqualToString:@"card_access_revoked"]) return @"卡密已被停用、解绑或到期，请输入新卡密";
    if ([code isEqualToString:@"device_access_revoked"]) return @"设备授权状态已变更，请重新验证";
    if ([code isEqualToString:@"rate_limited"] || httpStatus == 429) return @"请求过于频繁，请稍后重试";
    if ([code isEqualToString:@"app_attestation_required"]) return @"服务端要求启用 Apple App Attest 校验";
    if ([code isEqualToString:@"upstream_failed_do_not_automatically_retry"]) return @"验证服务暂不可用，请勿重复提交，稍后再试";
    if ([code isEqualToString:@"database_unavailable_do_not_retry_mutations"]) return @"验证服务器繁忙，请稍后手动重试";
    if ([code isEqualToString:@"expired_or_used_challenge"] || [code isEqualToString:@"clock_changed_request_new_challenge"]) {
        return @"安全挑战已过期，请重试";
    }
    if ([code isEqualToString:@"invalid_encrypted_request"]) return @"加密请求校验失败，请重试";
    if (httpStatus == 401 || httpStatus == 403) return @"服务器拒绝了本次验证请求";
    return @"验证服务器暂不可用，请检查网络后重试";
}

bool isMockCurrentlyActive() {
    NSDictionary *obj = dictionaryFromJSON(currentLocationJSON());
    return [obj[@"enabled"] boolValue];
}

struct V2CallOutcome {
    bool transportOk = false;
    bool responseVerified = false;
    bool retryableChallengeError = false;
    bool doNotAutoRetry = false;
    bool revoked = false;
    bool sessionExpired = false;
    int httpStatus = 0;
    std::string serverErrorCode;
    NSString *errorMessage = nil;
    NSDictionary *envelope = nil;  // Verified inner LG1 response claims
};

V2CallOutcome executeV2CallOnce(const std::string& api,
                                NSDictionary *params,
                                const std::string& sessionToken,
                                bool includeMockActive) {
    V2CallOutcome outcome;
    if (!ensureDeviceIdentity()) {
        outcome.errorMessage = @"无法初始化设备安全密钥，请确认钥匙串权限后重试";
        return outcome;
    }

    const RuntimeConfig config = trustedConfig();
    std::array<std::uint8_t, 32> clientNonceRaw{};
    if (!randomBytes(clientNonceRaw.data(), clientNonceRaw.size())) {
        outcome.errorMessage = @"安全随机数生成失败";
        return outcome;
    }
    const std::string clientNonceB64 = base64UrlEncode(clientNonceRaw.data(), clientNonceRaw.size());

    // Step 1: POST /v2/challenge
    NSDictionary *challengeReq = @{
        @"app": ns(config.appID),
        @"client_nonce": ns(clientNonceB64),
        @"device_key": ns(gDeviceIdentity.publicKeyB64)
    };
    HttpReply chReply = postJSON("/v2/challenge", challengeReq);
    if (!chReply.error.empty()) {
        outcome.errorMessage = ns(chReply.error);
        return outcome;
    }
    outcome.httpStatus = chReply.status;
    NSDictionary *chBody = dictionaryFromJSON(chReply.body);
    if (chReply.status < 200 || chReply.status >= 300 || !chBody) {
        outcome.serverErrorCode = cpp(strictString(chBody[@"error"]));
        outcome.errorMessage = friendlyHttpError(chBody, chReply.status);
        return outcome;
    }

    NSString *challengeIdNS = strictString(chBody[@"id"]);
    if (challengeIdNS.length == 0) {
        outcome.errorMessage = @"服务器未返回有效挑战令牌";
        return outcome;
    }
    const std::string challengeId = cpp(challengeIdNS);

    std::string verifyErr;
    NSDictionary *chClaims = verifyAndDecodeLG1Token(challengeId, &verifyErr);
    if (!chClaims) {
        outcome.errorMessage = ns(verifyErr.empty() ? "挑战令牌验签失败" : verifyErr);
        return outcome;
    }

    long long chV = 0, chIat = 0;
    if (!positiveInteger(chClaims[@"v"], chV) || chV != 2 ||
        ![strictString(chClaims[@"purpose"]) isEqualToString:@"challenge"] ||
        ![strictString(chClaims[@"app"]) isEqualToString:ns(config.appID)] ||
        ![strictString(chClaims[@"device"]) isEqualToString:ns(gDeviceIdentity.publicKeyB64)] ||
        ![strictString(chClaims[@"client_nonce"]) isEqualToString:ns(clientNonceB64)]) {
        outcome.errorMessage = @"挑战令牌声明校验失败";
        return outcome;
    }
    if (positiveInteger(chClaims[@"iat"], chIat)) {
        updateServerClockAndWatermark(static_cast<double>(chIat));
    }

    NSString *chNonceNS = strictString(chClaims[@"nonce"]);
    NSString *agreementKeyNS = strictString(chClaims[@"agreement_key"]);
    auto chNonceRaw = chNonceNS ? base64UrlDecode(cpp(chNonceNS)) : std::nullopt;
    auto agreementKeyRaw = agreementKeyNS ? base64UrlDecode(cpp(agreementKeyNS)) : std::nullopt;
    if (!chNonceRaw || chNonceRaw->size() != 32 || !agreementKeyRaw || agreementKeyRaw->size() != 65) {
        outcome.errorMessage = @"挑战密钥参数无效";
        return outcome;
    }

    // Step 2: Ephemeral P-256 keypair + ECDH(ephemeral_priv, agreement_key) + HKDF-SHA256
    NSDictionary *ephAttrs = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256
    };
    CFErrorRef err = nullptr;
    SecKeyRef ephPriv = SecKeyCreateRandomKey((__bridge CFDictionaryRef)ephAttrs, &err);
    if (err) CFRelease(err);
    if (!ephPriv) {
        outcome.errorMessage = @"无法创建临时会话密钥";
        return outcome;
    }

    std::vector<std::uint8_t> ephPubRaw;
    if (!extractRawUncompressedP256PublicKey(ephPriv, ephPubRaw)) {
        CFRelease(ephPriv);
        outcome.errorMessage = @"无法导出临时会话公钥";
        return outcome;
    }
    const std::string ephKeyB64 = base64UrlEncode(ephPubRaw);

    SecKeyRef srvAgreementPub = importP256PublicKey(*agreementKeyRaw);
    if (!srvAgreementPub) {
        CFRelease(ephPriv);
        outcome.errorMessage = @"服务器协商公钥无效";
        return outcome;
    }

    CFDataRef sharedRef = SecKeyCopyKeyExchangeResult(
        ephPriv,
        kSecKeyAlgorithmECDHKeyExchangeStandard,
        srvAgreementPub,
        (__bridge CFDictionaryRef)@{},
        &err);
    CFRelease(srvAgreementPub);
    CFRelease(ephPriv);
    if (err) CFRelease(err);
    if (!sharedRef) {
        outcome.errorMessage = @"ECDH 密钥协商失败";
        return outcome;
    }
    NSData *sharedData = CFBridgingRelease(sharedRef);
    auto sessionKey = deriveLicenseGuardSessionKey(bytesFromNSData(sharedData), *chNonceRaw);
    if (!sessionKey) {
        outcome.errorMessage = @"会话密钥派生失败";
        return outcome;
    }

    // Step 3: Build strict plaintext payload + AES-256-GCM seal + device ECDSA proof
    NSMutableDictionary *plainObj = [@{
        @"api": ns(api),
        @"params": params ?: @{},
        @"client_nonce": ns(clientNonceB64),
        @"session": ns(sessionToken),
        @"mock_active": @(includeMockActive ? 1 : 0),
        @"tamper_flags": @0
    } mutableCopy];
    if (!gDeviceIdentity.hwHash.empty()) {
        plainObj[@"hw_hash"] = ns(gDeviceIdentity.hwHash);
    }

    NSData *plainData = canonicalJSONData(plainObj);
    if (!plainData) {
        outcome.errorMessage = @"业务请求序列化失败";
        return outcome;
    }

    const std::string reqAADStr = buildCallAAD(config.appID, challengeId, cpp(chNonceNS),
                                               gDeviceIdentity.publicKeyB64, ephKeyB64);
    const std::vector<std::uint8_t> reqAAD(reqAADStr.begin(), reqAADStr.end());
    std::array<std::uint8_t, 12> iv{};
    if (!randomBytes(iv.data(), iv.size())) {
        outcome.errorMessage = @"加密随机向量生成失败";
        return outcome;
    }

    const std::vector<std::uint8_t> sealedRaw = aes256GcmSeal(*sessionKey, iv, bytesFromNSData(plainData), reqAAD);
    const std::string sealedB64 = base64UrlEncode(sealedRaw);
    const std::string sealedHashHex = sha256Hex(sealedRaw);
    const std::string proofInput = buildProofSigningInput(reqAADStr, sealedRaw);
    auto proofB64 = signWithDeviceKeyB64(proofInput);
    if (!proofB64) {
        outcome.errorMessage = @"设备签名失败";
        return outcome;
    }

    NSDictionary *callReq = @{
        @"challenge_id": challengeIdNS,
        @"ephemeral_key": ns(ephKeyB64),
        @"sealed": ns(sealedB64),
        @"proof": ns(*proofB64)
    };
    HttpReply callReply = postJSON("/v2/call", callReq);
    if (!callReply.error.empty()) {
        outcome.errorMessage = ns(callReply.error);
        return outcome;
    }
    outcome.httpStatus = callReply.status;
    NSDictionary *callBody = dictionaryFromJSON(callReply.body);
    if (callReply.status < 200 || callReply.status >= 300 || !callBody) {
        NSString *errCode = strictString(callBody[@"error"]) ?: @"";
        outcome.serverErrorCode = cpp(errCode);
        outcome.errorMessage = friendlyHttpError(callBody, callReply.status);
        outcome.retryableChallengeError =
            [errCode isEqualToString:@"expired_or_used_challenge"] ||
            [errCode isEqualToString:@"clock_changed_request_new_challenge"];
        outcome.doNotAutoRetry =
            [errCode isEqualToString:@"upstream_failed_do_not_automatically_retry"] ||
            [errCode isEqualToString:@"database_unavailable_do_not_retry_mutations"] ||
            callReply.status == 502 || callReply.status == 503;
        outcome.revoked =
            [errCode isEqualToString:@"device_blocked"] ||
            [errCode isEqualToString:@"device_deleted"] ||
            [errCode isEqualToString:@"card_access_revoked"] ||
            [errCode isEqualToString:@"device_access_revoked"] ||
            [errCode isEqualToString:@"hardware_mismatch"];
        outcome.sessionExpired = [errCode isEqualToString:@"online_login_required"];
        return outcome;
    }

    // Step 4: Decrypt response sealed packet + verify LG1 signature + validate envelope claims
    NSString *respSealedNS = strictString(callBody[@"sealed"]);
    auto respSealedRaw = respSealedNS ? base64UrlDecode(cpp(respSealedNS)) : std::nullopt;
    if (!respSealedRaw) {
        outcome.errorMessage = @"加密响应解码失败";
        return outcome;
    }
    const std::string respAADStr = buildResponseAAD(reqAADStr);
    const std::vector<std::uint8_t> respAAD(respAADStr.begin(), respAADStr.end());
    auto respTokenBytes = aes256GcmOpen(*sessionKey, *respSealedRaw, respAAD);
    if (!respTokenBytes) {
        outcome.errorMessage = @"响应解密认证失败";
        return outcome;
    }
    const std::string respToken(respTokenBytes->begin(), respTokenBytes->end());
    NSDictionary *envelope = verifyAndDecodeLG1Token(respToken, &verifyErr);
    if (!envelope) {
        outcome.errorMessage = ns(verifyErr.empty() ? "响应令牌验签失败" : verifyErr);
        return outcome;
    }

    long long envV = 0, envIat = 0, envExp = 0;
    if (!positiveInteger(envelope[@"v"], envV) || envV != 1 ||
        ![strictString(envelope[@"app"]) isEqualToString:ns(config.appID)] ||
        ![strictString(envelope[@"device"]) isEqualToString:ns(gDeviceIdentity.deviceIdHex)] ||
        ![strictString(envelope[@"challenge"]) isEqualToString:challengeIdNS] ||
        ![strictString(envelope[@"client_nonce"]) isEqualToString:ns(clientNonceB64)] ||
        ![strictString(envelope[@"request_hash"]) isEqualToString:ns(sealedHashHex)] ||
        ![strictString(envelope[@"api"]) isEqualToString:ns(api)] ||
        !positiveInteger(envelope[@"iat"], envIat) ||
        !positiveInteger(envelope[@"exp"], envExp) ||
        envExp < envIat) {
        outcome.errorMessage = @"响应信封校验失败";
        return outcome;
    }

    updateServerClockAndWatermark(static_cast<double>(envIat));
    outcome.transportOk = true;
    outcome.responseVerified = true;
    outcome.envelope = envelope;
    return outcome;
}

V2CallOutcome executeV2Call(const std::string& api,
                            NSDictionary *params,
                            const std::string& sessionToken,
                            bool includeMockActive) {
    V2CallOutcome outcome = executeV2CallOnce(api, params, sessionToken, includeMockActive);
    if (!outcome.transportOk && outcome.retryableChallengeError) {
        // Safe single retry when 30s epoch rotated between challenge and call.
        outcome = executeV2CallOnce(api, params, sessionToken, includeMockActive);
    }
    return outcome;
}

#if JJV_AUTH_UI_ENABLED
dispatch_queue_t diagnosticIOQueue() {
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("com.dyyli.locationtweak.diagnostics", DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}
#endif

}  // namespace

NSString *ns(const std::string& value) {
    return [NSString stringWithUTF8String:value.c_str()] ?: @"";
}

std::string cpp(NSString *value) {
    return value ? std::string(value.UTF8String ?: "") : "";
}

NSString *strictString(id value) {
    return [value isKindOfClass:NSString.class] ? (NSString *)value : nil;
}

NSString *trimmed(NSString *text) {
    return [text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] ?: @"";
}

NSDictionary *dictionaryFromJSON(const std::string& text) {
    NSData *data = [ns(text) dataUsingEncoding:NSUTF8StringEncoding];
    id object = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

NSMutableDictionary *errorResult(NSString *error, bool verified, long long code) {
    return [@{
        @"ok": @NO,
        @"response_verified": @(verified),
        @"code": @(code),
        @"api": @"kmlogon",
        @"error": error ?: @"验证失败"
    } mutableCopy];
}

double wallNow() {
#ifdef JJV_AUTH_TESTING
    std::lock_guard<std::mutex> lock(gTestMutex);
    return gTestWall;
#else
    return NSDate.date.timeIntervalSince1970;
#endif
}

double steadyNow() {
#ifdef JJV_AUTH_TESTING
    std::lock_guard<std::mutex> lock(gTestMutex);
    return gTestSteady;
#else
    static const double scale = [] {
        mach_timebase_info_data_t info;
        mach_timebase_info(&info);
        return (double)info.numer / info.denom / 1e9;
    }();
    return mach_continuous_time() * scale;
#endif
}

double currentAuthorizationExpiryWall() {
    std::lock_guard<std::mutex> lock(gStateMutex);
    if (gState.vipWall > 0) return gState.vipWall;
    if (gState.offlineExpWall > 0) return gState.offlineExpWall;
    return gState.sessionExpWall;
}

bool isPermanentOfflineAuthorized() {
    std::lock_guard<std::mutex> lock(gStateMutex);
    return gState.authorized && gState.permanentOffline;
}

bool isLoginInFlight() {
    std::lock_guard<std::mutex> lock(gStateMutex);
    return gState.inFlight;
}

bool hasActiveOnlineSession() {
    std::lock_guard<std::mutex> lock(gStateMutex);
    const double now = effectiveWallLocked();
    return !gState.sessionToken.empty() && now < gState.sessionExpWall &&
           steadyNow() < gState.sessionSteadyDeadline;
}

bool isHeartbeatDue() {
    std::lock_guard<std::mutex> lock(gStateMutex);
    if (!gState.authorized || gState.inFlight || gState.sessionToken.empty()) return false;
    const double now = effectiveWallLocked();
    if (now >= gState.sessionExpWall || steadyNow() >= gState.sessionSteadyDeadline) return false;
    return steadyNow() >= gState.nextHeartbeatSteady;
}

bool isGenerationCurrent(std::uint64_t generation) {
    std::lock_guard<std::mutex> lock(gStateMutex);
    return gState.generation == generation;
}

std::string currentDeviceIdHex() {
    if (!ensureDeviceIdentity()) return "";
    return gDeviceIdentity.deviceIdHex;
}

std::string currentDeviceIdPrefix() {
    std::string full = currentDeviceIdHex();
    return full.substr(0, std::min<std::size_t>(16, full.size()));
}

std::string authSummaryJSON() {
    @autoreleasepool {
        const bool authorized = isAuthorized();
        const bool permanent = isPermanentOfflineAuthorized();
        const double expiryWall = currentAuthorizationExpiryWall();
        const std::string fullId = currentDeviceIdHex();
        const std::string prefix = fullId.substr(0, std::min<std::size_t>(16, fullId.size()));
        return jsonForDictionary(@{
            @"authorized": @(authorized),
            @"permanent": @(permanent),
            @"expiry_wall": @(static_cast<long long>(expiryWall)),
            @"device_id": ns(fullId),
            @"device_prefix": ns(prefix)
        });
    }
}

void revokeAuthorization(bool clearPersistedLicenses) {
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(gStateMutex);
        changed = gState.authorized;
        gState.authorized = false;
        gState.permanentOffline = false;
        gState.sessionToken.clear();
        gState.sessionExpWall = 0;
        gState.sessionSteadyDeadline = 0;
        gState.offlineExpWall = 0;
        gState.inFlight = false;
        ++gState.generation;
    }
    if (clearPersistedLicenses) {
        clearPersistedAuthArtifacts();
    }
    if (changed) notifyAuthorizationChanged(false);
}

void recordDiagnostic(NSString *event, NSDictionary *fields) {
    @autoreleasepool {
        NSDictionary *payloadToWrite = nil;
        {
            std::lock_guard<std::mutex> lock(gDiagnosticMutex);
            NSMutableDictionary *snapshot = gDiagnosticSnapshot ? [gDiagnosticSnapshot mutableCopy] :
                [@{
                    @"version": buildVersionString(),
                    @"protocol": @"gogo-v2",
                    @"ctor_seen": @NO,
                    @"bootstrap_seen": @NO,
                    @"authorized": @NO,
                    @"scene_count": @0,
                    @"host_window_count": @0,
                    @"gate_window_count": @0,
                    @"notice_window_count": @0,
                    @"notice_shown_this_launch": @NO,
                    @"ui": @"not_started"
                } mutableCopy];
            if (fields) [snapshot addEntriesFromDictionary:fields];
            snapshot[@"version"] = buildVersionString();
            snapshot[@"protocol"] = @"gogo-v2";
            snapshot[@"event"] = event ?: @"unknown";
            [snapshot removeObjectForKey:@"time"];
            [snapshot removeObjectForKey:@"file_written"];
            NSData *signatureData = canonicalJSONData(snapshot);
            NSString *signature = signatureData ? [[NSString alloc] initWithData:signatureData encoding:NSUTF8StringEncoding] : nil;
            if (signature && [signature isEqualToString:gDiagnosticLastSignature]) return;
            gDiagnosticLastSignature = signature;
            snapshot[@"time"] = @(NSDate.date.timeIntervalSince1970);
            payloadToWrite = [snapshot copy];
            snapshot[@"file_written"] = @(JJV_AUTH_UI_ENABLED ? YES : NO);
            gDiagnosticSnapshot = [snapshot copy];
        }
#if JJV_AUTH_UI_ENABLED
        if (!payloadToWrite) return;
        dispatch_async(diagnosticIOQueue(), ^{
            @autoreleasepool {
                @try {
                    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches/com.dyyli.locationtweak.jjcloud"];
                    [[NSFileManager defaultManager] createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
                    NSString *path = [directory stringByAppendingPathComponent:diagnosticLogFileName()];
                    NSMutableData *contents = [NSMutableData data];
                    NSFileHandle *reader = [NSFileHandle fileHandleForReadingAtPath:path];
                    if (reader) {
                        unsigned long long size = [reader seekToEndOfFile];
                        unsigned long long start = size > 24576 ? size - 24576 : 0;
                        [reader seekToFileOffset:start];
                        NSData *tail = [reader readDataOfLength:24576];
                        [reader closeFile];
                        if (start && tail.length) {
                            const char *bytes = (const char *)tail.bytes;
                            NSUInteger firstLine = 0;
                            while (firstLine < tail.length && bytes[firstLine] != '\n') ++firstLine;
                            if (firstLine < tail.length) {
                                tail = [tail subdataWithRange:NSMakeRange(firstLine + 1, tail.length - firstLine - 1)];
                            } else {
                                tail = [NSData data];
                            }
                        }
                        [contents appendData:tail];
                    }
                    NSData *line = canonicalJSONData(payloadToWrite);
                    if (line.length && contents.length + line.length + 1 <= 32768) {
                        [contents appendData:line];
                        [contents appendBytes:"\n" length:1];
                        if ([contents writeToFile:path atomically:YES]) {
                            NSURL *fileURL = [NSURL fileURLWithPath:path];
                            [fileURL setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:nil];
                        }
                    }
                } @catch (__unused NSException *error) {
                }
            }
        });
#else
        (void)payloadToWrite;
#endif
    }
}

std::string restoreStartupAuthorization() {
    @autoreleasepool {
        std::uint64_t generation = 0;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            if (gState.startupRestoreAttempted || gState.inFlight || gState.authorized) {
                NSMutableDictionary *skipped = errorResult(@"本次启动已尝试恢复授权");
                skipped[@"startup_skipped"] = @YES;
                return jsonForDictionary(skipped);
            }
            gState.startupRestoreAttempted = true;
            generation = ++gState.generation;
        }

        if (!ensureDeviceIdentity()) {
            return jsonForDictionary(errorResult(@"无法读取设备安全密钥，请确认钥匙串权限后重试"));
        }

        NSString *permanentToken = nil;
        NSString *offlineToken = nil;
        NSString *sessionJSON = nil;
        {
            std::lock_guard<std::mutex> slock(gStorageMutex);
            permanentToken = readSecretLocked(kAccountPermanentLicense);
            offlineToken = readSecretLocked(kAccountOfflineLicense);
            sessionJSON = readSecretLocked(kAccountSession);
            std::lock_guard<std::mutex> lock(gStateMutex);
            loadClockWatermarkLocked();
        }

        const std::string deviceId = gDeviceIdentity.deviceIdHex;
        VerifiedOfflineLicense perm = permanentToken.length
            ? verifyOfflineLicenseToken(cpp(permanentToken), deviceId)
            : VerifiedOfflineLicense{};
        VerifiedOfflineLicense offline = offlineToken.length
            ? verifyOfflineLicenseToken(cpp(offlineToken), deviceId)
            : VerifiedOfflineLicense{};

        NSDictionary *savedSession = sessionJSON ? dictionaryFromJSON(cpp(sessionJSON)) : nil;
        std::string sessionToken = cpp(strictString(savedSession[@"session"]));
        long long sessionExp = 0, savedVip = 0;
        nonNegativeInteger(savedSession[@"session_exp"], sessionExp);
        nonNegativeInteger(savedSession[@"vip"], savedVip);

        bool granted = false;
        bool permanent = false;
        double grantedExp = 0;
        bool stateChanged = false;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            if (gState.generation != generation) {
                NSMutableDictionary *obsolete = errorResult(@"本次恢复已被更新的请求取代");
                obsolete[@"superseded"] = @YES;
                return jsonForDictionary(obsolete);
            }
            const double now = effectiveWallLocked();
            const double mono = steadyNow();

            if (perm.valid && perm.permanent) {
                granted = true;
                permanent = true;
            }
            if (offline.valid && !offline.permanent && offline.expWall > now) {
                granted = true;
                gState.offlineExpWall = offline.expWall;
                grantedExp = offline.expWall;
            }
            if (!sessionToken.empty() && static_cast<double>(sessionExp) > now) {
                granted = true;
                gState.sessionToken = sessionToken;
                gState.sessionExpWall = static_cast<double>(sessionExp);
                gState.sessionSteadyDeadline = mono + std::max(0.0, static_cast<double>(sessionExp) - now);
                gState.nextHeartbeatSteady = mono + 5.0;  // Quick sync heartbeat once online
                if (grantedExp <= 0) grantedExp = static_cast<double>(sessionExp);
            }
            if (savedVip > 0) {
                gState.vipWall = static_cast<double>(savedVip);
            }
            stateChanged = (gState.authorized != granted);
            gState.authorized = granted;
            gState.permanentOffline = permanent;
        }
        if (stateChanged) notifyAuthorizationChanged(granted);

        if (granted) {
            NSMutableDictionary *ok = [@{
                @"ok": @YES,
                @"response_verified": @YES,
                @"code": @200,
                @"api": @"startup_restore",
                @"permanent": @(permanent),
                @"offline_exp": @(static_cast<long long>(grantedExp)),
                @"request_generation": @(generation)
            } mutableCopy];
            return jsonForDictionary(ok);
        }

        NSMutableDictionary *manual = errorResult(@"请输入卡密并点击验证");
        manual[@"no_saved_license"] = @YES;
        manual[@"request_generation"] = @(generation);
        return jsonForDictionary(manual);
    }
}

namespace {

struct BizEnvelope {
    NSDictionary *result = nil;
    NSDictionary *msgDict = nil;
    id rawMsg = nil;
    long long code = 0;
};

BizEnvelope unpackBizEnvelope(NSDictionary *envelope) {
    BizEnvelope biz;
    biz.result = [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
    positiveInteger(biz.result[@"code"], biz.code);
    biz.rawMsg = biz.result[@"msg"];
    biz.msgDict = [biz.rawMsg isKindOfClass:NSDictionary.class] ? (NSDictionary *)biz.rawMsg : nil;
    if (biz.code == 200) {
        persistAmapKeyIfPresent(biz.msgDict);
    }
    return biz;
}

void ackPermanentReceiptIfNeeded(const std::string& serial, const std::string& sessionToken) {
    if (serial.empty()) return;
    NSString *ackedSerial = nil;
    {
        std::lock_guard<std::mutex> slock(gStorageMutex);
        ackedSerial = readSecretLocked(kAccountPermanentReceiptSerial);
    }
    if ([ackedSerial isEqualToString:ns(serial)]) return;

    V2CallOutcome ack = executeV2Call("permanent_entitlement", @{@"receipt": ns(serial)}, sessionToken, false);
    if (ack.transportOk) {
        std::lock_guard<std::mutex> slock(gStorageMutex);
        writeSecretLocked(kAccountPermanentReceiptSerial, ns(serial));
    }
}

bool tryActivatePermanentLicense(NSString *licenseToken,
                                 NSDictionary *msgDict,
                                 const std::string& sessionToken,
                                 bool *outNewlyGranted = nullptr,
                                 std::string *outSerial = nullptr) {
    if (licenseToken.length == 0 || !ensureDeviceIdentity()) return false;
    VerifiedOfflineLicense verified = verifyOfflineLicenseToken(cpp(licenseToken), gDeviceIdentity.deviceIdHex);
    if (!verified.valid || !verified.permanent) return false;

    bool newlyGranted = false;
    bool stateChanged = false;
    {
        std::lock_guard<std::mutex> slock(gStorageMutex);
        writeSecretLocked(kAccountPermanentLicense, licenseToken);
    }
    {
        std::lock_guard<std::mutex> lock(gStateMutex);
        newlyGranted = !gState.permanentOffline;
        stateChanged = !gState.authorized;
        gState.authorized = true;
        gState.permanentOffline = true;
    }
    if (stateChanged) notifyAuthorizationChanged(true);

    std::string serial = verified.serial;
    if (serial.empty() && msgDict) {
        serial = cpp(trimmed(strictString(msgDict[@"serial"])));
    }
    ackPermanentReceiptIfNeeded(serial, sessionToken);
    if (outNewlyGranted) *outNewlyGranted = newlyGranted;
    if (outSerial) *outSerial = serial;
    return true;
}

NSString *extractCandidatePermanentToken(NSDictionary *envelope, const BizEnvelope& biz) {
    NSString *token = strictString(envelope[@"offline_license"]);
    if (!token.length && biz.msgDict) {
        token = strictString(biz.msgDict[@"permanent_offline_license"])
            ?: strictString(biz.msgDict[@"offline_license"])
            ?: strictString(biz.msgDict[@"license"])
            ?: strictString(biz.msgDict[@"token"]);
    }
    if (!token.length && biz.result) {
        token = strictString(biz.result[@"permanent_offline_license"])
            ?: strictString(biz.result[@"offline_license"])
            ?: strictString(biz.result[@"license"]);
    }
    return token;
}

}  // namespace

// 前置声明：本函数要挂看门狗，而 scheduleInFlightWatchdog 的定义在会话调用区（靠后）。
// 注意必须声明在 jjcloud 命名空间内、匿名 namespace 之外，否则会形成两个不同实体
// （匿名 namespace 内的版本具有内部链接且名字不同），调用处会报 ambiguous。
static void scheduleInFlightWatchdog(std::uint64_t generation, std::uint64_t leaseId);

std::string performLoginJSON(const std::string& cardInput, const std::string& machine) {
    (void)machine;  // GOGO v2 derives device identity strictly from P-256 device_key.
    @autoreleasepool {
        const std::string card = cpp(trimmed(ns(cardInput)));
        if (card.empty()) {
            return jsonForDictionary(errorResult(@"请输入卡密"));
        }

        std::uint64_t generation = 0;
        std::uint64_t leaseId = 0;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            gState.startupRestoreAttempted = true;
            generation = ++gState.generation;
            leaseId = ++gState.callLeaseId;
            gState.inFlight = true;
            // verify 是唯一可能长时间持有 inFlight 的入口。弱网下它一旦挂住，
            // 心跳与云端读写会被全部锁死到下次启动，因此必须同样纳入超时回收。
            scheduleInFlightWatchdog(generation, leaseId);
            // Preserve any existing valid permanent/offline license until server explicitly revokes.
        }

        auto finishFailedAttempt = [&](bool hardRevoked) {
            if (hardRevoked) {
                revokeAuthorization(true);
                return;
            }
            bool expiredNow = false;
            {
                std::lock_guard<std::mutex> lock(gStateMutex);
                if (gState.generation == generation && gState.callLeaseId == leaseId) {
                    gState.inFlight = false;
                }
                expiredNow = expireAuthorizationLocked();
            }
            if (expiredNow) notifyAuthorizationChanged(false);
        };

        V2CallOutcome outcome = executeV2Call("kmlogon", @{@"kami": ns(card)}, "", false);
        if (!outcome.transportOk || !outcome.envelope) {
            finishFailedAttempt(outcome.revoked);
            NSMutableDictionary *err = errorResult(outcome.errorMessage ?: @"验证失败，请重试", false, outcome.httpStatus);
            if (!outcome.serverErrorCode.empty()) err[@"server_error"] = ns(outcome.serverErrorCode);
            err[@"do_not_retry"] = @(outcome.doNotAutoRetry);
            err[@"request_generation"] = @(generation);
            return jsonForDictionary(err);
        }

        NSDictionary *envelope = outcome.envelope;
        const BizEnvelope biz = unpackBizEnvelope(envelope);

        NSMutableDictionary *response = [@{
            @"ok": @NO,
            @"response_verified": @YES,
            @"code": @(biz.code),
            @"api": @"kmlogon",
            @"request_generation": @(generation)
        } mutableCopy];

        if (biz.code != 200) {
            NSString *msgText = strictString(biz.rawMsg);
            if (!msgText.length) {
                if (biz.code == 403) msgText = @"卡密无效、已到期或已绑定其他设备";
                else if (biz.code == 404) msgText = @"当前设备无有效卡密";
                else msgText = @"服务器未批准本次验证";
            }
            response[@"error"] = msgText;
            finishFailedAttempt(false);
            return jsonForDictionary(response);
        }

        long long vip = 0, sessionExp = 0;
        nonNegativeInteger(biz.msgDict[@"vip"], vip);
        nonNegativeInteger(envelope[@"session_exp"], sessionExp);
        NSString *sessionNS = strictString(envelope[@"session"]) ?: @"";
        NSString *offlineLicenseNS = extractCandidatePermanentToken(envelope, biz) ?: @"";

        VerifiedOfflineLicense verifiedOffline;
        if (offlineLicenseNS.length > 0 && ensureDeviceIdentity()) {
            verifiedOffline = verifyOfflineLicenseToken(cpp(offlineLicenseNS), gDeviceIdentity.deviceIdHex);
        }

        double now = 0;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            now = effectiveWallLocked();
        }
        const bool sessionValid = (sessionNS.length > 0 && static_cast<double>(sessionExp) > now);
        const bool offlineValid = (verifiedOffline.valid && (verifiedOffline.permanent || verifiedOffline.expWall > now));
        const bool accepted = (sessionValid || offlineValid) && (vip == 0 || static_cast<double>(vip) > now);

        if (!accepted) {
            response[@"error"] = @"卡密已到期或未获得有效会话凭证";
            finishFailedAttempt(false);
            return jsonForDictionary(response);
        }

        // Persist ONLY session & signed offline_license (never kami!).
        if (sessionValid) {
            persistSessionToKeychain(cpp(sessionNS), static_cast<double>(sessionExp), static_cast<double>(vip));
        }
        if (offlineValid && !verifiedOffline.permanent) {
            std::lock_guard<std::mutex> slock(gStorageMutex);
            writeSecretLocked(kAccountOfflineLicense, offlineLicenseNS);
        }

        bool stateChanged = false;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            if (gState.generation != generation) {
                response[@"ok"] = @NO;
                response[@"error"] = @"本次验证已被更新的请求取代";
                response[@"superseded"] = @YES;
                return jsonForDictionary(response);
            }
            const double curWall = effectiveWallLocked();
            const double mono = steadyNow();
            stateChanged = !gState.authorized;
            gState.authorized = true;
            gState.inFlight = false;
            gState.vipWall = vip > 0 ? static_cast<double>(vip) : (offlineValid ? verifiedOffline.expWall : static_cast<double>(sessionExp));
            if (sessionValid) {
                gState.sessionToken = cpp(sessionNS);
                gState.sessionExpWall = static_cast<double>(sessionExp);
                gState.sessionSteadyDeadline = mono + std::max(0.0, static_cast<double>(sessionExp) - curWall);
                gState.nextHeartbeatSteady = mono + std::min(kHeartbeatIntervalSeconds,
                                                             std::max(30.0, (static_cast<double>(sessionExp) - curWall) * 0.6));
            }
            if (offlineValid && !verifiedOffline.permanent) {
                gState.offlineExpWall = verifiedOffline.expWall;
            }
        }

        if (offlineValid && verifiedOffline.permanent) {
            tryActivatePermanentLicense(offlineLicenseNS, biz.msgDict, sessionValid ? cpp(sessionNS) : "");
        }

        response[@"ok"] = @YES;
        if (vip > 0) response[@"vip"] = @(vip);
        if (sessionValid) response[@"session_exp"] = @(sessionExp);
        if (offlineValid) response[@"offline_exp"] = @(static_cast<long long>(verifiedOffline.expWall));
        if (stateChanged) notifyAuthorizationChanged(true);
        return jsonForDictionary(response);
    }
}

// 互斥标志看门狗：inFlight 一旦因异常路径漏复位，心跳会被永久挡在门外。
// 回收时必须推进 callLeaseId，否则原持有者迟到的完成仍会命中旧栅栏，
// 把新持有者的 inFlight 清掉 —— 这就是双请求并发与假性会话失效的来源。
static void scheduleInFlightWatchdog(std::uint64_t generation, std::uint64_t leaseId) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                       std::lock_guard<std::mutex> lock(gStateMutex);
                       if (gState.generation == generation &&
                           gState.callLeaseId == leaseId &&
                           gState.inFlight) {
                           gState.inFlight = false;
                           ++gState.callLeaseId;
                       }
                   });
}

// 一次云端调用的租约。valid 为 false 时，clearedExpiredSession 表明
// 失败原因是会话刚刚过期而非本来就没有会话，调用方据此决定是否落盘清理。
struct CallLease {
    std::string sessionToken;
    std::uint64_t generation = 0;
    std::uint64_t leaseId = 0;
    bool valid = false;
    bool clearedExpiredSession = false;
};

// 调用方必须持有 gStateMutex。
static bool claimLiveSessionForCallLocked(CallLease *outLease) {
    if (!outLease) return false;
    *outLease = CallLease{};
    if (!liveAuthorizationLocked() || gState.inFlight || gState.sessionToken.empty()) {
        return false;
    }
    // liveAuthorizationLocked() 在 24h 离线授权仍有效时会返回 true，
    // 即便 session 已过 steady 截止。这里必须单独再判，否则会带着过期 token 发请求。
    if (effectiveWallLocked() >= gState.sessionExpWall ||
        steadyNow() >= gState.sessionSteadyDeadline) {
        gState.sessionToken.clear();
        gState.sessionExpWall = 0;
        gState.sessionSteadyDeadline = 0;
        outLease->clearedExpiredSession = true;
        return false;
    }
    outLease->sessionToken = gState.sessionToken;
    outLease->generation = gState.generation;
    outLease->leaseId = ++gState.callLeaseId;
    outLease->valid = true;
    gState.inFlight = true;
    scheduleInFlightWatchdog(outLease->generation, outLease->leaseId);
    return true;
}

// 只认 leaseId。generation 变化说明 verify/revoke 介入过，此时 inFlight 已由别人持有，
// 我们不能再动它，更不能清 session —— 否则会把正在进行的调用打断。
static void finishSessionCallOutcome(const CallLease &lease,
                                     const V2CallOutcome &outcome,
                                     bool isHeartbeat) {
    bool shouldNotifyRevoke = false;
    bool clearAllArtifacts = false;
    bool clearSessionArtifact = false;
    {
        std::lock_guard<std::mutex> lock(gStateMutex);
        if (gState.generation == lease.generation && gState.callLeaseId == lease.leaseId) {
            if (gState.inFlight) gState.inFlight = false;
            if (!outcome.transportOk) {
                if (outcome.revoked) {
                    shouldNotifyRevoke = gState.authorized;
                    gState.authorized = false;
                    gState.permanentOffline = false;
                    gState.sessionToken.clear();
                    gState.sessionExpWall = 0;
                    gState.sessionSteadyDeadline = 0;
                    gState.offlineExpWall = 0;
                    ++gState.generation;
                    clearAllArtifacts = true;
                } else if (outcome.sessionExpired) {
                    gState.sessionToken.clear();
                    gState.sessionExpWall = 0;
                    gState.sessionSteadyDeadline = 0;
                    shouldNotifyRevoke = expireAuthorizationLocked();
                    clearSessionArtifact = true;
                } else if (isHeartbeat) {
                    gState.nextHeartbeatSteady = steadyNow() + 60.0;
                }
            } else if (isHeartbeat) {
                gState.nextHeartbeatSteady = steadyNow() + kHeartbeatIntervalSeconds;
            }
        }
    }
    // 钥匙串 IO 一律放到锁外，避免持 gStateMutex 做磁盘操作
    if (clearAllArtifacts) clearPersistedAuthArtifacts();
    else if (clearSessionArtifact) persistSessionToKeychain("", 0, 0);
    if (shouldNotifyRevoke) {
        notifyAuthorizationChanged(false);
#if JJV_AUTH_UI_ENABLED
        notifyLeaseExpiredUI();
#endif
    }
}

std::string performLocationSyncJSON(double latitude, double longitude, const std::string& address, bool active) {
    @autoreleasepool {
        if (!std::isfinite(latitude) || !std::isfinite(longitude) ||
            std::fabs(latitude) > 90.0 || std::fabs(longitude) > 180.0) {
            NSMutableDictionary *invalid = errorResult(@"坐标超出有效范围，无法写入云端");
            invalid[@"api"] = @"location_sync";
            return jsonForDictionary(invalid);
        }

        CallLease lease;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            claimLiveSessionForCallLocked(&lease);
        }
        // 会话刚过期也必须落盘清理，否则钥匙串会一直留着过期串，下次冷启动又被恢复
        if (lease.clearedExpiredSession) persistSessionToKeychain("", 0, 0);
        if (!lease.valid) {
            NSMutableDictionary *skipped = errorResult(lease.clearedExpiredSession
                                                       ? @"在线会话已过期，请重新验证卡密"
                                                       : @"当前无活跃在线会话，无法写入云端");
            skipped[@"skipped"] = @YES;
            skipped[@"session_expired"] = @(lease.clearedExpiredSession);
            skipped[@"api"] = @"location_sync";
            return jsonForDictionary(skipped);
        }

        NSMutableDictionary *params = [@{
            @"active" : @(active ? 1 : 0),
            @"latitude" : @(latitude),
            @"longitude" : @(longitude),
            @"address" : ns(address),
            @"source" : @"dyyli-location-tweak"
        } mutableCopy];

        V2CallOutcome outcome = executeV2Call("location_sync", params, lease.sessionToken, active);
        finishSessionCallOutcome(lease, outcome, false);

        if (!outcome.transportOk || !outcome.envelope) {
            NSMutableDictionary *err =
                errorResult(outcome.errorMessage ?: @"定位写入云端失败", false, outcome.httpStatus);
            err[@"api"] = @"location_sync";
            err[@"transport_ok"] = @(outcome.transportOk);
            err[@"revoked"] = @(outcome.revoked);
            err[@"session_expired"] = @(outcome.sessionExpired);
            if (!outcome.serverErrorCode.empty()) err[@"server_error"] = ns(outcome.serverErrorCode);
            return jsonForDictionary(err);
        }

        const BizEnvelope biz = unpackBizEnvelope(outcome.envelope);
        NSMutableDictionary *ok = [@{
            @"ok" : @(biz.code == 200),
            @"response_verified" : @YES,
            @"code" : @(biz.code),
            @"api" : @"location_sync",
            @"active" : @(active ? 1 : 0),
            @"latitude" : @(latitude),
            @"longitude" : @(longitude),
            @"address" : ns(address)
        } mutableCopy];
        return jsonForDictionary(ok);
    }
}

// ---- 云端定位配置读取辅助 ----
static bool DYYLIExtractDouble(NSDictionary *source, NSArray<NSString *> *keys, double *out) {
    if (!source || !out) return false;
    for (NSString *key in keys) {
        id value = source[key];
        if ([value isKindOfClass:[NSNumber class]]) {
            if (CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) continue;
            double num = [(NSNumber *)value doubleValue];
            if (!std::isfinite(num)) continue;
            *out = num;
            return true;
        }
        if ([value isKindOfClass:[NSString class]]) {
            NSString *text = [(NSString *)value stringByTrimmingCharactersInSet:
                                                   [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (text.length == 0) continue;
            NSScanner *scanner = [NSScanner scannerWithString:text];
            double parsed = 0;
            if ([scanner scanDouble:&parsed] && scanner.isAtEnd && std::isfinite(parsed)) {
                *out = parsed;
                return true;
            }
        }
    }
    return false;
}

static NSString *DYYLIExtractString(NSDictionary *source, NSArray<NSString *> *keys) {
    if (!source) return nil;
    for (NSString *key in keys) {
        id value = source[key];
        if ([value isKindOfClass:[NSString class]] && [(NSString *)value length] > 0) {
            return (NSString *)value;
        }
    }
    return nil;
}

static bool DYYLIExtractBool(NSDictionary *source, NSArray<NSString *> *keys, bool *out) {
    if (!source || !out) return false;
    for (NSString *key in keys) {
        id value = source[key];
        if ([value isKindOfClass:[NSNumber class]]) {
            *out = [(NSNumber *)value boolValue];
            return true;
        }
        if ([value isKindOfClass:[NSString class]]) {
            NSString *lower = [(NSString *)value lowercaseString];
            if ([lower isEqualToString:@"1"] || [lower isEqualToString:@"true"] ||
                [lower isEqualToString:@"yes"]) {
                *out = true;
                return true;
            }
            if ([lower isEqualToString:@"0"] || [lower isEqualToString:@"false"] ||
                [lower isEqualToString:@"no"]) {
                *out = false;
                return true;
            }
        }
    }
    return false;
}

std::string performLocationFetchJSON() {
    @autoreleasepool {
        CallLease lease;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            claimLiveSessionForCallLocked(&lease);
        }
        // 与 sync 对齐：过期会话必须同时从钥匙串移除
        if (lease.clearedExpiredSession) persistSessionToKeychain("", 0, 0);
        if (!lease.valid) {
            NSMutableDictionary *skipped = errorResult(lease.clearedExpiredSession
                                                       ? @"在线会话已过期，请重新验证卡密"
                                                       : @"当前无活跃在线会话，无法读取云端定位");
            skipped[@"skipped"] = @YES;
            skipped[@"session_expired"] = @(lease.clearedExpiredSession);
            skipped[@"api"] = @"location_get";
            return jsonForDictionary(skipped);
        }

        V2CallOutcome outcome = executeV2Call("location_get", @{}, lease.sessionToken, false);
        finishSessionCallOutcome(lease, outcome, false);

        if (!outcome.transportOk || !outcome.envelope) {
            NSMutableDictionary *err =
                errorResult(outcome.errorMessage ?: @"读取云端定位失败", false, outcome.httpStatus);
            err[@"api"] = @"location_get";
            err[@"transport_ok"] = @(outcome.transportOk);
            err[@"revoked"] = @(outcome.revoked);
            err[@"session_expired"] = @(outcome.sessionExpired);
            if (!outcome.serverErrorCode.empty()) err[@"server_error"] = ns(outcome.serverErrorCode);
            return jsonForDictionary(err);
        }

        const BizEnvelope biz = unpackBizEnvelope(outcome.envelope);
        // 服务端可能把定位放在 result.msg 里，也可能直接摊在 result 上，两种都认
        NSDictionary *payload = biz.msgDict ?: biz.result;

        double latitude = 0;
        double longitude = 0;
        bool active = true;
        bool hasLat = DYYLIExtractDouble(payload, @[ @"latitude", @"lat", @"y" ], &latitude);
        bool hasLon = DYYLIExtractDouble(payload, @[ @"longitude", @"lng", @"lon", @"x" ], &longitude);
        (void)DYYLIExtractBool(payload, @[ @"active", @"enabled", @"mock_active" ], &active);
        NSString *address = DYYLIExtractString(payload, @[ @"address", @"addr", @"name" ]);

        NSMutableDictionary *response = [@{
            @"api" : @"location_get",
            @"response_verified" : @YES,
            @"code" : @(biz.code),
        } mutableCopy];

        const bool valid = (biz.code == 200) && hasLat && hasLon &&
                           latitude >= -90.0 && latitude <= 90.0 &&
                           longitude >= -180.0 && longitude <= 180.0;
        response[@"ok"] = @(valid);
        response[@"found"] = @(valid);
        if (valid) {
            response[@"latitude"] = @(latitude);
            response[@"longitude"] = @(longitude);
            response[@"address"] = address ?: @"";
            response[@"active"] = @(active);
        } else if (biz.code == 200) {
            response[@"error"] = @"云端尚未保存定位配置";
        } else {
            response[@"error"] = @"服务端未返回有效定位";
        }
        return jsonForDictionary(response);
    }
}

std::string performHeartbeatJSON() {
    @autoreleasepool {
        CallLease lease;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            // 改走统一申领：steady 截止守卫在这里自然生效。
            // 原先只判 liveAuthorizationLocked()，而它在 24h 离线授权有效时恒真，
            // 结果会带着已过期的 session 发心跳，绕过防改表回拨守卫。
            claimLiveSessionForCallLocked(&lease);
        }
        if (lease.clearedExpiredSession) persistSessionToKeychain("", 0, 0);
        if (!lease.valid) {
            NSMutableDictionary *skipped = errorResult(@"当前无活跃在线会话");
            skipped[@"skipped"] = @YES;
            skipped[@"session_expired"] = @(lease.clearedExpiredSession);
            return jsonForDictionary(skipped);
        }

        V2CallOutcome outcome = executeV2Call("heartbeat", @{}, lease.sessionToken, isMockCurrentlyActive());
        // isHeartbeat = true：nextHeartbeatSteady 的调度差异收敛到统一收尾里
        finishSessionCallOutcome(lease, outcome, true);

        if (!outcome.transportOk || !outcome.envelope) {
            NSMutableDictionary *err = errorResult(outcome.errorMessage ?: @"心跳校验失败", false, outcome.httpStatus);
            err[@"api"] = @"heartbeat";
            err[@"revoked"] = @(outcome.revoked);
            err[@"session_expired"] = @(outcome.sessionExpired);
            if (!outcome.serverErrorCode.empty()) err[@"server_error"] = ns(outcome.serverErrorCode);
            return jsonForDictionary(err);
        }

        const BizEnvelope biz = unpackBizEnvelope(outcome.envelope);

        bool newlyGrantedPermanent = false;
        const bool grantedPermanentNow = tryActivatePermanentLicense(
            extractCandidatePermanentToken(outcome.envelope, biz),
            biz.msgDict,
            lease.sessionToken,
            &newlyGrantedPermanent);

        NSMutableDictionary *ok = [@{
            @"ok": @(biz.code == 200),
            @"response_verified": @YES,
            @"code": @(biz.code),
            @"api": @"heartbeat",
            @"permanent_granted": @(grantedPermanentNow),
            @"permanent_newly_granted": @(newlyGrantedPermanent)
        } mutableCopy];
        if (biz.msgDict) ok[@"msg"] = biz.msgDict;
        return jsonForDictionary(ok);
    }
}

std::string performPermanentEntitlementSyncJSON() {
    @autoreleasepool {
        if (!ensureDeviceIdentity()) {
            return jsonForDictionary(errorResult(@"无法读取设备安全密钥"));
        }

        std::string currentSession;
        {
            std::lock_guard<std::mutex> lock(gStateMutex);
            if (!gState.sessionToken.empty() && effectiveWallLocked() < gState.sessionExpWall) {
                currentSession = gState.sessionToken;
            }
        }

        V2CallOutcome outcome = executeV2Call("permanent_entitlement", @{}, currentSession, false);
        if (!outcome.transportOk || !outcome.envelope) {
            if (outcome.revoked) revokeAuthorization(true);
            NSMutableDictionary *err = errorResult(outcome.errorMessage ?: @"永久授权同步失败", false, outcome.httpStatus);
            err[@"api"] = @"permanent_entitlement";
            err[@"revoked"] = @(outcome.revoked);
            if (!outcome.serverErrorCode.empty()) err[@"server_error"] = ns(outcome.serverErrorCode);
            return jsonForDictionary(err);
        }

        const BizEnvelope biz = unpackBizEnvelope(outcome.envelope);
        NSString *status = strictString(biz.msgDict[@"status"]) ?: strictString(biz.result[@"status"]) ?: @"none";
        if ([status isEqualToString:@"revoked"]) {
            {
                std::lock_guard<std::mutex> slock(gStorageMutex);
                deleteSecretLocked(kAccountPermanentLicense);
                deleteSecretLocked(kAccountPermanentReceiptSerial);
            }
            bool lostAuthorization = false;
            {
                std::lock_guard<std::mutex> lock(gStateMutex);
                if (gState.permanentOffline) {
                    gState.permanentOffline = false;
                    lostAuthorization = expireAuthorizationLocked();
                }
            }
            if (lostAuthorization) notifyAuthorizationChanged(false);

            NSMutableDictionary *rev = errorResult(@"永久离线授权已被管理员停止，请重新验证卡密", true, biz.code);
            rev[@"api"] = @"permanent_entitlement";
            rev[@"status"] = @"revoked";
            rev[@"revoked"] = @(lostAuthorization);
            return jsonForDictionary(rev);
        }

        bool newlyGranted = false;
        std::string serial;
        if (tryActivatePermanentLicense(extractCandidatePermanentToken(outcome.envelope, biz),
                                        biz.msgDict,
                                        currentSession,
                                        &newlyGranted,
                                        &serial)) {
            NSMutableDictionary *granted = [@{
                @"ok": @YES,
                @"response_verified": @YES,
                @"code": @(biz.code ?: 200),
                @"api": @"permanent_entitlement",
                @"status": @"received",
                @"granted": @YES,
                @"newly_granted": @(newlyGranted),
                @"permanent": @YES
            } mutableCopy];
            if (!serial.empty()) granted[@"serial"] = ns(serial);
            return jsonForDictionary(granted);
        }

        return jsonForDictionary(@{
            @"ok": @(biz.code == 200),
            @"response_verified": @YES,
            @"code": @(biz.code),
            @"api": @"permanent_entitlement",
            @"status": status,
            @"granted": @NO,
            @"permanent": @(isPermanentOfflineAuthorized())
        });
    }
}

std::string performIniJSON() {
    @autoreleasepool {
        V2CallOutcome outcome = executeV2Call("ini", @{}, "", false);
        if (!outcome.transportOk || !outcome.envelope) {
            NSMutableDictionary *err = errorResult(outcome.errorMessage ?: @"获取配置失败", false, outcome.httpStatus);
            err[@"api"] = @"ini";
            return jsonForDictionary(err);
        }
        const BizEnvelope biz = unpackBizEnvelope(outcome.envelope);
        NSMutableDictionary *res = [@{
            @"ok": @(biz.code == 200),
            @"response_verified": @YES,
            @"code": @(biz.code),
            @"api": @"ini"
        } mutableCopy];
        if (biz.msgDict) res[@"msg"] = biz.msgDict;
        return jsonForDictionary(res);
    }
}

std::string performNoticeJSON() {
    @autoreleasepool {
        V2CallOutcome outcome = executeV2Call("notice", @{}, "", false);
        if (!outcome.transportOk || !outcome.envelope) {
            NSMutableDictionary *err = errorResult(outcome.errorMessage ?: @"获取公告失败", false, outcome.httpStatus);
            err[@"api"] = @"notice";
            return jsonForDictionary(err);
        }
        const BizEnvelope biz = unpackBizEnvelope(outcome.envelope);
        NSString *notice = strictString(biz.msgDict[@"app_gg"])
            ?: strictString(biz.result[@"app_gg"])
            ?: strictString(biz.msgDict[@"notice"])
            ?: strictString(biz.rawMsg);
        NSMutableDictionary *res = [@{
            @"ok": @(biz.code == 200),
            @"response_verified": @YES,
            @"code": @(biz.code),
            @"api": @"notice"
        } mutableCopy];
        if (notice) res[@"app_gg"] = notice;
        return jsonForDictionary(res);
    }
}

void recordAuthorizationConstructor() {
    recordDiagnostic(@"ctor", @{@"ctor_seen": @YES});
}

std::string startupDiagnosticsJSON() {
    bool authorized = isAuthorized();
    NSDictionary *snapshot;
    {
        std::lock_guard<std::mutex> lock(gDiagnosticMutex);
        NSMutableDictionary *copy = gDiagnosticSnapshot ? [gDiagnosticSnapshot mutableCopy] :
            [@{@"version": buildVersionString(), @"protocol": @"gogo-v2", @"ctor_seen": @NO, @"bootstrap_seen": @NO, @"ui": @"not_started"} mutableCopy];
        copy[@"version"] = buildVersionString();
        copy[@"protocol"] = @"gogo-v2";
        copy[@"authorized"] = @(authorized);
        copy[@"permanent_offline"] = @(isPermanentOfflineAuthorized());
        copy[@"log_file"] = diagnosticLogFileName();
        std::string devPrefix = currentDeviceIdPrefix();
        if (!devPrefix.empty()) copy[@"device_prefix"] = ns(devPrefix);
        snapshot = [copy copy];
    }
    return jsonForDictionary(snapshot);
}

RuntimeConfig currentRuntimeConfig() {
    return trustedConfig();
}

bool setRuntimeConfig(const RuntimeConfig& requested) {
    RuntimeConfig trusted = trustedConfig();
    const bool matches = requested.baseURL == trusted.baseURL && requested.appID == trusted.appID &&
                         !requested.enforceExitOnFail;
    if (!matches) revokeAuthorization(false);
    return matches;
}

bool autoPopupEnabled() {
    return JJV_AUTH_UI_ENABLED;
}

bool isAuthorized() {
    bool changed = false, authorized = false;
    {
        std::lock_guard<std::mutex> lock(gStateMutex);
        changed = expireAuthorizationLocked();
        authorized = gState.authorized;
    }
    if (changed) {
        notifyAuthorizationChanged(false);
#if JJV_AUTH_UI_ENABLED
        notifyLeaseExpiredUI();
#endif
    }
    return authorized;
}

void showVerificationPopup() {
#if JJV_AUTH_UI_ENABLED
    showAuthPopupUI();
#endif
}

void initializeAuthorization() {
#if JJV_AUTH_UI_ENABLED
    initializeAuthUI();
#endif
}

#ifdef JJV_AUTH_TESTING
namespace testing {

void setTransport(Transport transport) {
    std::lock_guard<std::mutex> lock(gTestMutex);
    gTestTransport = std::move(transport);
}

void setServerSigningPublicKey(const std::string& publicKeyB64) {
    std::lock_guard<std::mutex> lock(gTestMutex);
    if (gTestServerSigningKey) {
        CFRelease(gTestServerSigningKey);
        gTestServerSigningKey = nullptr;
    }
    gTestServerSigningPubB64 = publicKeyB64;
    auto raw = base64UrlDecode(publicKeyB64);
    if (raw) {
        gTestServerSigningKey = importP256PublicKey(*raw);
    }
}

void setTimes(double wallSeconds, double monotonicSeconds) {
    std::lock_guard<std::mutex> lock(gTestMutex);
    gTestWall = wallSeconds;
    gTestSteady = monotonicSeconds;
}

void resetMemory(bool preserveKeychain) {
    {
        std::lock_guard<std::mutex> lock(gStateMutex);
        gState = AuthorizationState{};
    }
    if (!preserveKeychain) {
        std::lock_guard<std::mutex> slock(gStorageMutex);
        [gTestKeychain removeAllObjects];
        if (gDeviceIdentity.privateKey) {
            CFRelease(gDeviceIdentity.privateKey);
            gDeviceIdentity = DeviceIdentity{};
        }
    }
}

std::string restoreStartup() { return restoreStartupAuthorization(); }
std::string syncPermanentEntitlement() { return performPermanentEntitlementSyncJSON(); }
std::string heartbeat() { return performHeartbeatJSON(); }

}  // namespace testing
#endif

}  // namespace jjcloud
