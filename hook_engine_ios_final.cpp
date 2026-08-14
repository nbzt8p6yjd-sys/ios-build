/*
 * iOS DST 私有服在线联机注入器 v1.1
 * 在原有"皮肤解锁注入"(IOSVISION v6.1) 基础上，新增三合一在线联机 hook：
 *  1) 域名重定向：把 klei / epic 相关域名解析到我们的服务器 47.122.115.99
 *  2) 证书绕过：让 libcurl / OpenSSL 不校验我们自签证书（多层兜底）
 *  3) socket 重定向：把游戏发往我们服务器的外部游戏 UDP 引到中继端口 12000
 * 目标：完全替代官方在线联机（房间列表 + 跨网中继），iPhone↔iPhone/Android 异地联机。
 *
 * v1.1 诊断加固：
 *  - 最优先构造函数(dst_load_marker, priority 100)在 dyld 加载阶段就建好 Documents
 *    目录并写入 "=== DYLIB LOADED ===" 标记，确保即使后续崩溃也能证明 dylib 已加载。
 *  - 安装 SIGILL/SIGSEGV/SIGBUS/SIGABRT/SIGTRAP 信号处理器 + NSUncaughtExceptionHandler，
 *    任何崩溃都会把原因追加写入 dst_hook.log（避免"闪退且零日志"无法定位）。
 *  - hook 逐个记录成败，失败不致命（继续运行原有功能）。
 *
 * 编译见 .github/workflows/build-ios.yml，产出 libIOSVISION.dylib。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dlfcn.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <Security/Security.h>

#include "dobby.h"
#include <setjmp.h>

// ---- DobbyHook 超时保护 ----
// arm64e 上 hook 某些 libsystem 符号（尤其 sendto/connect/bind）可能死锁卡死 dylib 构造函数，
// 导致主线程进不了 main() → app 白屏。用 sigsetjmp+alarm(3s) 兜底：任一个 hook 卡住就跳过，
// 绝不阻塞构造函数。
static sigjmp_buf g_hook_jmp;
static void dst_hook_alrm(int sig) { (void)sig; siglongjmp(g_hook_jmp, 1); }

// 当前是否启用 socket 重定向 hook（sendto/connect/bind）。
// 这些 libsystem 函数在 arm64e 上 DobbyHook 会卡死构造函数 → 白屏，故默认关闭。
// 实现跨网 UDP 中继需另寻方案（fishhook / 中继端口对齐游戏原 RakNet 端口免 hook），与联机后端一并设计。
#define ENABLE_SOCKET_HOOK 0

// ---- 服务器配置 ----
#define DST_SERVER_IP   "47.122.115.99"
#define DST_RELAY_PORT  12000

// ---- 文件日志（真机反馈用，写 Documents/dst_hook.log） ----
static FILE* g_log = NULL;

// 确保日志目录存在并打开文件（首次启动 iOS 可能还没建 Documents，必须先 mkdir）
static void dst_ensure_log() {
    if (g_log) return;
    @autoreleasepool {
        NSString* home = NSHomeDirectory();
        NSString* dir  = [home stringByAppendingPathComponent:@"Documents"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                      withIntermediateDirectories:YES
                                                       attributes:nil
                                                            error:nil];
        NSString* path = [dir stringByAppendingPathComponent:@"dst_hook.log"];
        g_log = fopen([path UTF8String], "a");
    }
}

// 紧急日志：不依赖 g_log，单独开文件追加后关闭（供崩溃处理器使用，最稳妥）
static void dst_panic(const char* msg) {
    @autoreleasepool {
        NSString* home = NSHomeDirectory();
        NSString* dir  = [home stringByAppendingPathComponent:@"Documents"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                      withIntermediateDirectories:YES
                                                       attributes:nil
                                                            error:nil];
        NSString* path = [dir stringByAppendingPathComponent:@"dst_hook.log"];
        FILE* f = fopen([path UTF8String], "a");
        if (f) { fprintf(f, "[PANIC] %s\n", msg ? msg : "(null)"); fflush(f); fclose(f); }
    }
}

static void dst_log(const char* fmt, ...) {
    dst_ensure_log();
    if (g_log) {
        va_list ap; va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fprintf(g_log, "\n");
        fflush(g_log);
    }
}

#define LOGD(fmt, ...) do { fprintf(stderr, "[DSTHOOK] " fmt "\n", ##__VA_ARGS__); dst_log(fmt, ##__VA_ARGS__); } while(0)
#define LOGE(fmt, ...) do { fprintf(stderr, "[DSTHOOK ERR] " fmt "\n", ##__VA_ARGS__); dst_log("[ERR] " fmt, ##__VA_ARGS__); } while(0)

// ---- 崩溃信号 / 异常捕获：让任何崩溃都留痕 ----
static void dst_signal_handler(int sig) {
    const char* name =
        (sig == SIGILL)  ? "SIGILL"  :
        (sig == SIGSEGV) ? "SIGSEGV" :
        (sig == SIGBUS)  ? "SIGBUS"  :
        (sig == SIGABRT) ? "SIGABRT" :
        (sig == SIGTRAP) ? "SIGTRAP" : "SIG?";
    dst_panic([[NSString stringWithFormat:@"CRASH signal=%s (可能是 hook/PAC 相关)", name] UTF8String]);
    _exit(1);
}

// 未捕获 Objective-C 异常的 C 处理函数（NSSetUncaughtExceptionHandler 只接受 C 函数指针，不能传 block）
static void dst_uncaught_handler(NSException* e) {
    @autoreleasepool {
        NSString* desc = e ? [e description] : @"(null)";
        dst_panic([[NSString stringWithFormat:@"NSException: %@", desc] UTF8String]);
    }
}

// ============ 最优先构造函数：加载标记 + 崩溃捕获 ============
// priority 100 保证在 iosvision_init / dst_online_init 之前运行，
// 这样即便后面任何构造函数或 hook 崩溃，至少能证明 dylib 已成功加载。
__attribute__((constructor(100)))
static void dst_load_marker() {
    dst_ensure_log();
    LOGD("=== DYLIB LOADED (libIOSVISION v1.1) ===");
    signal(SIGILL,  dst_signal_handler);
    signal(SIGSEGV, dst_signal_handler);
    signal(SIGBUS,  dst_signal_handler);
    signal(SIGABRT, dst_signal_handler);
    signal(SIGTRAP, dst_signal_handler);
    NSSetUncaughtExceptionHandler(dst_uncaught_handler);
    LOGD("crash handlers installed");
}

// ---- 工具：是否私网/回环（这里其实用不到，重定向只看目的 IP 是否等于服务器） ----
static int is_internal(uint32_t ip_host) {
    uint8_t a=(ip_host>>24)&0xff, b=(ip_host>>16)&0xff;
    if (ip_host == 0x7f000001) return 1;
    if (a==10) return 1;
    if (a==172 && b>=16 && b<=31) return 1;
    if (a==192 && b==168) return 1;
    if (a==169 && b==254) return 1;
    if (ip_host == 0) return 1;
    return 0;
}

// 服务器 IP（网络字节序，便于直接比较 sin_addr.s_addr）
static uint32_t g_server_ip = 0;

// ============ 1) 域名重定向：getaddrinfo ============
typedef int (*getaddrinfo_t)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
static getaddrinfo_t orig_getaddrinfo = NULL;
static int fake_getaddrinfo(const char* hostname, const char* servname, const struct addrinfo* hints, struct addrinfo** res) {
    int r = orig_getaddrinfo(hostname, servname, hints, res);
    if (r == 0 && hostname) {
        if (strstr(hostname,"klei.com") || strstr(hostname,"kleientertainment.com") ||
            strstr(hostname,"epicgames.com") || strstr(hostname,"eos.") ||
            strstr(hostname,"epicgc") || strstr(hostname,"kraken")) {
            int n=0;
            for (struct addrinfo* ai = *res; ai; ai = ai->ai_next) {
                if (ai->ai_family == AF_INET) {
                    struct sockaddr_in* sin = (struct sockaddr_in*)ai->ai_addr;
                    sin->sin_addr.s_addr = g_server_ip;
                    n++;
                }
            }
            LOGD("getaddrinfo hijack %s -> %s (%d addrs)", hostname, DST_SERVER_IP, n);
        }
    }
    return r;
}

// ============ 2) 证书绕过（三层兜底） ============
// 2a) libcurl：强制 SSL_VERIFYPEER / SSL_VERIFYHOST = 0
#define CURLOPT_SSL_VERIFYPEER 64L
#define CURLOPT_SSL_VERIFYHOST 81L
typedef int (*curl_easy_setopt_t)(void*, int, ...);
static curl_easy_setopt_t orig_curl_easy_setopt = NULL;
static int fake_curl_easy_setopt(void* handle, int option, ...) {
    va_list ap; va_start(ap, option);
    void* val = va_arg(ap, void*);
    va_end(ap);
    if ((long)option == CURLOPT_SSL_VERIFYPEER || (long)option == CURLOPT_SSL_VERIFYHOST) {
        LOGD("curl SSL_VERIFY disabled opt=%ld", (long)option);
        return orig_curl_easy_setopt(handle, option, 0L);
    }
    return orig_curl_easy_setopt(handle, option, val);
}

// 2b) OpenSSL：X509_verify_cert 直接返回成功
typedef int (*x509_verify_t)(void*);
static x509_verify_t orig_x509_verify = NULL;
static int fake_x509_verify(void* ctx) {
    LOGD("X509_verify_cert bypass=1");
    return 1;
}

// 2c) 系统 Security.framework（兜底，对 libcurl 通常不生效，但无害）
// 注意：新版 SDK 中 SecTrustRef 是 Obj-C 对象类型，这里用 void* 避免 ARC/类型冲突。
typedef OSStatus (*dst_sec_witherr_t)(void*, bool*);
static dst_sec_witherr_t orig_sec_witherr = NULL;
static OSStatus fake_sec_witherr(void* trust, bool* result) {
    (void)trust;
    if (result) *result = true;
    return errSecSuccess;
}
typedef OSStatus (*dst_sec_trust_t)(void*, SecTrustResultType*);
static dst_sec_trust_t orig_sec = NULL;
static OSStatus fake_sec(void* trust, SecTrustResultType* result) {
    (void)trust;
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

#if ENABLE_SOCKET_HOOK
// ============ 3) socket 重定向 ============
// 只重定向「目的 IP == 我们服务器 且 端口非 {80,443,8080,12000}」的 UDP。
// 这样：joiner 拿 getIP 返回的 47.122.115.99:12000 直连中继；host 发往 klei 域名的
// 游戏 UDP（被解析成 47.122.115.99，原端口）也被引到 12000 中继；DNS 等发往其他 IP 的
// UDP 完全不动，避免误伤。
typedef ssize_t (*sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
static sendto_t orig_sendto = NULL;
static ssize_t fake_sendto(int socket, const void* buffer, size_t length, int flags, const struct sockaddr* dest_addr, socklen_t dest_len) {
    if (dest_addr && dest_addr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)(void*)dest_addr;
        int port = ntohs(sin->sin_port);
        if (sin->sin_addr.s_addr == g_server_ip && port != 80 && port != 443 && port != 8080 && port != DST_RELAY_PORT) {
            struct sockaddr_in na;
            memcpy(&na, sin, sizeof(na));
            na.sin_port = htons(DST_RELAY_PORT);
            LOGD("sendto redirect port %d -> %d", port, DST_RELAY_PORT);
            return orig_sendto(socket, buffer, length, flags, (const struct sockaddr*)&na, sizeof(na));
        }
    }
    return orig_sendto(socket, buffer, length, flags, dest_addr, dest_len);
}

typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
static connect_t orig_connect = NULL;
static int fake_connect(int socket, const struct sockaddr* addr, socklen_t len) {
    int type=0; socklen_t tl=sizeof(type);
    getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &tl);
    if (type == SOCK_DGRAM && addr && addr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)(void*)addr;
        int port = ntohs(sin->sin_port);
        if (sin->sin_addr.s_addr == g_server_ip && port != 80 && port != 443 && port != 8080 && port != DST_RELAY_PORT) {
            struct sockaddr_in na;
            memcpy(&na, sin, sizeof(na));
            na.sin_port = htons(DST_RELAY_PORT);
            LOGD("connect(UDP) redirect port %d -> %d", port, DST_RELAY_PORT);
            return orig_connect(socket, (const struct sockaddr*)&na, sizeof(na));
        }
    }
    return orig_connect(socket, addr, len);
}

typedef int (*bind_t)(int, const struct sockaddr*, socklen_t);
static bind_t orig_bind = NULL;
static int fake_bind(int socket, const struct sockaddr* addr, socklen_t len) {
    int r = orig_bind(socket, addr, len);
    int type=0; socklen_t tl=sizeof(type);
    getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &tl);
    if (r == 0 && type == SOCK_DGRAM && addr && addr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)(void*)addr;
        if (sin->sin_addr.s_addr == INADDR_ANY) {
            // host 监听 socket：额外 connect 到中继，让 host 的响应流量也走中继
            struct sockaddr_in na;
            memset(&na, 0, sizeof(na));
            na.sin_family = AF_INET;
            na.sin_addr.s_addr = g_server_ip;
            na.sin_port = htons(DST_RELAY_PORT);
            int cr = connect(socket, (const struct sockaddr*)&na, sizeof(na));
            LOGD("bind(INADDR_ANY UDP fd=%d)+connect relay cr=%d", socket, cr);
        }
    }
    return r;
}
#endif

// ============ hook 安装 ============
static void* try_hook(const char* name, void* fake, void** orig) {
    void* addr = dlsym(RTLD_DEFAULT, name);
    if (!addr) { LOGD("hook skip(no-sym): %s", name); return NULL; }
    void (*oalrm)(int) = signal(SIGALRM, dst_hook_alrm);
    void* ret = NULL;
    if (sigsetjmp(g_hook_jmp, 1) == 0) {
        alarm(3);
        int r = DobbyHook(addr, fake, orig);
        alarm(0); signal(SIGALRM, oalrm);
        LOGD("hook %s %s", name, r==0 ? "OK" : "FAIL");
        if (r != 0) { LOGE("DobbyHook FAILED for %s (r=%d) — 该 hook 未生效，但不影响其他功能", name, r); }
        ret = addr;
    } else {
        alarm(0); signal(SIGALRM, oalrm);
        LOGE("hook %s TIMEOUT — skipped (arm64e/PAC deadlock?)，已跳过以免构造函数卡死白屏", name);
    }
    return ret;
}

static void dst_online_init() {
    dst_ensure_log();
    g_server_ip = inet_addr(DST_SERVER_IP);
    LOGD("=== DST online hook init (server=%s relay=%d) ===", DST_SERVER_IP, DST_RELAY_PORT);
    try_hook("getaddrinfo", (void*)fake_getaddrinfo, (void**)&orig_getaddrinfo);
#if ENABLE_SOCKET_HOOK
    try_hook("sendto", (void*)fake_sendto, (void**)&orig_sendto);
    try_hook("connect", (void*)fake_connect, (void**)&orig_connect);
    try_hook("bind", (void*)fake_bind, (void**)&orig_bind);
#endif
    try_hook("curl_easy_setopt", (void*)fake_curl_easy_setopt, (void**)&orig_curl_easy_setopt);
    try_hook("X509_verify_cert", (void*)fake_x509_verify, (void**)&orig_x509_verify);
    try_hook("SecTrustEvaluateWithError", (void*)fake_sec_witherr, (void**)&orig_sec_witherr);
    try_hook("SecTrustEvaluate", (void*)fake_sec, (void**)&orig_sec);
    LOGD("=== DST online hook done ===");
}

__attribute__((constructor))
static void dst_online_ctor() {
    dst_online_init();
}

// ============ 原有：皮肤解锁注入 (IOSVISION v6.1) ============
// 启动时执行一次，完全跟随 pending_keyvalues_prod 的 OfflineID：
// - pending_keyvalues_prod 不存在 → 跳过（第一次启动）
// - OfflineID 有值 → inventory_cache_prod 的 OfflineUserID 设为该值
// - OfflineID 为空 → OfflineUserID 也设为空
// - ID已匹配 → 跳过不覆盖
// 只执行一次，不影响游戏性能

// 从 JSON 文件中提取指定字段
static NSString* extract_field_from_file(NSString* path, NSString* field) {
    if (!path || ![[NSFileManager defaultManager] fileExistsAtPath:path]) return nil;
    NSData* data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;

    NSError* error = nil;
    NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error || !json) return nil;

    // 字段存在就返回（包括空字符串）
    if ([json objectForKey:field]) {
        return [json objectForKey:field];
    }
    return nil;
}

// 从 pending_keyvalues_prod 读取 OfflineID
static NSString* find_game_userid() {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* home = NSHomeDirectory();
    NSString* pendingPath = [home stringByAppendingPathComponent:@"Documents/DoNotStarveTogether/client_save/pending_keyvalues_prod"];

    if (![fm fileExistsAtPath:pendingPath]) return nil;
    return extract_field_from_file(pendingPath, @"OfflineID");
}

// 处理缓存文件：ID有值就替换，空值就设为空字符串
static bool patch_cache(NSString* cachePath, NSString* userId) {
    NSData* data = [NSData dataWithContentsOfFile:cachePath];
    if (!data) return false;

    NSError* error = nil;
    NSMutableDictionary* json = [NSJSONSerialization JSONObjectWithData:data
                                                                options:NSJSONReadingMutableContainers
                                                                  error:&error];
    if (error || !json) return false;

    // 和 pending_keyvalues_prod 一致：有值就设值，空就设空字符串
    [json setObject:(userId ? userId : @"") forKey:@"OfflineUserID"];

    NSData* patchedData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&error];
    if (error || !patchedData) return false;

    return [patchedData writeToFile:cachePath atomically:YES];
}

// 入口：启动时执行一次
__attribute__((constructor))
static void iosvision_init() {
    LOGD("IOSVISION v6.1 - One shot");

    NSFileManager* fm = [NSFileManager defaultManager];

    // 1. 从 bundle 读取全皮肤缓存
    NSString* bundlePath = [[NSBundle mainBundle] pathForResource:@"inventory_cache_prod" ofType:nil];
    if (!bundlePath || ![fm fileExistsAtPath:bundlePath]) {
        LOGE("inventory_cache_prod not found in bundle!");
        return;
    }

    // 2. 从游戏文件读取ID（nil=文件不存在，@""=空字符串）
    NSString* userId = find_game_userid();
    LOGD("Game ID: %s", userId ? [userId UTF8String] : "(file not found)");

    // 如果 pending_keyvalues_prod 不存在，说明是第一次启动
    // 不放文件，等下次启动游戏保存后再处理
    if (!userId) {
        LOGD("pending_keyvalues_prod not found, skip (first launch)");
        return;
    }

    // 3. 放文件到游戏存档目录
    NSString* home = NSHomeDirectory();
    NSString* targetDir = [home stringByAppendingPathComponent:@"Documents/DoNotStarveTogether/client_save"];

    [fm createDirectoryAtPath:targetDir withIntermediateDirectories:YES attributes:nil error:nil];
    if (![fm fileExistsAtPath:targetDir]) {
        LOGE("Cannot create target dir!");
        return;
    }

    NSString* cachePath = [targetDir stringByAppendingPathComponent:@"inventory_cache_prod"];

    // 检查是否已存在且ID匹配，匹配则跳过
    if ([fm fileExistsAtPath:cachePath]) {
        NSString* existingId = extract_field_from_file(cachePath, @"OfflineUserID");
        // 两者相等就跳过（包括都是空字符串的情况）
        if (existingId && userId && [existingId isEqualToString:userId]) {
            LOGD("Skip (ID already matches)");
            // 删除签名文件
            NSArray* sigFiles = @[
                [targetDir stringByAppendingPathComponent:@"inventory_cache_prod_sig"],
                [targetDir stringByAppendingPathComponent:@"pending_keyvalues_prod_sig"],
            ];
            for (NSString* sigPath in sigFiles) {
                if ([fm fileExistsAtPath:sigPath]) {
                    [fm removeItemAtPath:sigPath error:nil];
                }
            }
            LOGD("Done.");
            return;
        }
    }

    [fm removeItemAtPath:cachePath error:nil];
    NSError* error = nil;
    [fm copyItemAtPath:bundlePath toPath:cachePath error:&error];
    if (error) {
        LOGE("Copy failed: %s", [[error localizedDescription] UTF8String]);
        return;
    }

    // 和 pending_keyvalues_prod 的 OfflineID 保持一致
    patch_cache(cachePath, userId);

    // 删除签名文件
    NSArray* sigFiles = @[
        [targetDir stringByAppendingPathComponent:@"inventory_cache_prod_sig"],
        [targetDir stringByAppendingPathComponent:@"pending_keyvalues_prod_sig"],
    ];
    for (NSString* sigPath in sigFiles) {
        if ([fm fileExistsAtPath:sigPath]) {
            [fm removeItemAtPath:sigPath error:nil];
        }
    }

    LOGD("Done.");
}
