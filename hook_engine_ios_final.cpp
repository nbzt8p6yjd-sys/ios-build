/*
 * iOS DST 私有服在线联机注入器 v2.0  (fishhook 版，arm64e 安全)
 *
 * 设计目标：完全替代官方在线联机，让游戏原生 UI（建房 / 直连）直接跨网可用，
 *          不再依赖任何 Lua 房间屏，也不再使用 Dobby（Dobby 在 iOS arm64e 上
 *          PAC 跳板不兼容 → 白屏 / SIGBUS 崩，已弃用）。
 *
 * 核心机制（二进制层面，透明）：
 *  - 用 fishhook 对 libsystem 的 connect / sendto / bind 做 GOT 重绑定。
 *    fishhook 只改间接符号指针、不碰指令、不踩 PAC，因此在 arm64e 上安全。
 *  - 游戏（DST）所有「非回环的外部 UDP」一律重写目的地址为我们的中继
 *    (47.122.115.99:12000)，由云端中继做 N-way 字节转发，实现 iPhone↔iPhone 跨网。
 *  - 回环(127.0.0.0/8)UDP 不动  → 房主本机 client↔server 正常（本地建房不受影响）。
 *  - TCP(HTTPS 登录 / 其他)不动  → 我们的登录接口(47.122.115.99:3000)照常走，不被误伤。
 *  - 房主侧：其游戏服务器 bind(INADDR_ANY UDP) 时，主动向中继发一个 1 字节注册包，
 *    让中继记录房主出口地址；这样加入者连到中继后，中继能把流量转发给房主（NAT 打洞）。
 *
 * 登录/域名/证书：HTTP 走主二进制 URL 改写（已做），本 dylib 不再处理，避免多余 hook。
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dlfcn.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <Security/Security.h>

#include "fishhook.h"

// ---- 中继配置（与 server/relay/relay_server.py 的 RELAY_BASE_PORT 对齐）----
#define DST_RELAY_IP   "47.122.115.99"
#define DST_RELAY_PORT 12000

static uint32_t g_relay_ip = 0;   // 网络字节序，便于直接比较 sin_addr.s_addr

// ---- 文件日志（真机反馈用，写 Documents/dst_hook.log） ----
static FILE* g_log = NULL;

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
    dst_panic([[NSString stringWithFormat:@"CRASH signal=%s", name] UTF8String]);
    _exit(1);
}

static void dst_uncaught_handler(NSException* e) {
    @autoreleasepool {
        NSString* desc = e ? [e description] : @"(null)";
        dst_panic([[NSString stringWithFormat:@"NSException: %@", desc] UTF8String]);
    }
}

// ============ 最优先构造函数：加载标记 + 崩溃捕获 ============
__attribute__((constructor(100)))
static void dst_load_marker() {
    dst_ensure_log();
    LOGD("=== DYLIB LOADED (libIOSVISION v2.0 / fishhook) ===");
    signal(SIGILL,  dst_signal_handler);
    signal(SIGSEGV, dst_signal_handler);
    signal(SIGBUS,  dst_signal_handler);
    signal(SIGABRT, dst_signal_handler);
    signal(SIGTRAP, dst_signal_handler);
    NSSetUncaughtExceptionHandler(dst_uncaught_handler);
    LOGD("crash handlers installed");
}

// ---- 地址判定 ----
// 重要：sin_addr.s_addr 是「网络字节序」，必须先 ntohl 转主机序再按字节比较，
// 否则 127.0.0.1 会被误判为非回环 → 回环流量被错重定到中继（已踩坑：建房时
// 服务端回客户端的 ping 应答被改写到中继，客户端永远收不到 → "服务器无应答")。
static int is_loopback(uint32_t ip_net) {
    uint32_t ip = ntohl(ip_net);
    return (ip & 0xFF000000u) == 0x7F000000u;   // 127.0.0.0/8
}
static int is_relay(uint32_t ip_net, int port) {
    return ip_net == g_relay_ip && port == DST_RELAY_PORT;   // 二者皆网络序，直接比
}

// ---- 诊断日志（仅建房/联机排错用，限行数避免刷屏）----
// 建房失败排查核心：记录每次 UDP bind/connect/sendto 的目的地址/地址族/是否被重定向，
// 重点看清分片对等体(instance_2 的服务端实例)启动时到底在连/发往哪个地址
// （127.0.0.1 回环 / 设备真实 IP / IPv6?），从而定位 SOCKET_FAILED_TEST_SEND 成因。
static int g_diag_total = 0;   // 回环/绑定等关键信息行数（宽松）
static int g_diag_ext   = 0;   // 外部(重定到中继)流量采样行数（限量，保预算）
static void dst_diag(const char* tag, int fd, int fam, const struct sockaddr* addr, int flag) {
    // flag 含义随 tag：sendto/connect = 是否被重定到中继；bind = 是否 INADDR_ANY
    int is_ext = (fam == AF_INET && flag);  // 被重定到中继 = 外部流量，限量采样
    if (is_ext) { if (g_diag_ext++ > 150) return; }
    else        { if (g_diag_total++ > 2000) return; }
    char ip[64] = "?"; int port = 0;
    if (fam == AF_INET && addr) {
        const struct sockaddr_in* s = (const struct sockaddr_in*)(const void*)addr;
        inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
        port = ntohs(s->sin_port);
    } else if (fam == AF_INET6) {
        snprintf(ip, sizeof(ip), "[v6]");
    }
    LOGD("[DIAG] %s fd=%d fam=%d %s:%d flag=%d", tag, fd, fam, ip, port, flag);
}

// ============ fishhook：UDP 透明重定向到中继 ============
typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
typedef ssize_t (*sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef int (*bind_t)(int, const struct sockaddr*, socklen_t);

static connect_t orig_connect = NULL;
static sendto_t orig_sendto   = NULL;
static bind_t   orig_bind     = NULL;

// 取 socket 类型（SOCK_DGRAM / SOCK_STREAM），用于区分 UDP 与 TCP
static int sock_type(int fd) {
    int type = 0; socklen_t tl = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0) return type;
    return 0;
}

// 把目的地址改写为中继；返回 1 表示已改写（调用方改用 na），0 表示应原样透传
static int rewrite_to_relay(const struct sockaddr* addr, struct sockaddr_in* na) {
    if (!addr || addr->sa_family != AF_INET) return 0;
    const struct sockaddr_in* sin = (const struct sockaddr_in*)(const void*)addr;
    uint32_t ip = sin->sin_addr.s_addr;
    int port = ntohs(sin->sin_port);
    if (is_loopback(ip)) return 0;          // 回环不碰：本地 client↔server / 分片自测
    if (is_relay(ip, port)) return 0;       // 已是中继：避免自环
    memcpy(na, sin, sizeof(*na));
    na->sin_addr.s_addr = g_relay_ip;
    na->sin_port = htons(DST_RELAY_PORT);
    return 1;
}

static int fake_connect(int socket, const struct sockaddr* addr, socklen_t len) {
    if (sock_type(socket) == SOCK_DGRAM) {
        struct sockaddr_in na;
        int red = rewrite_to_relay(addr, &na);
        dst_diag("connect", socket, addr ? addr->sa_family : 0, addr, red);
        if (red) {
            LOGD("connect(UDP) -> relay");
            return orig_connect(socket, (const struct sockaddr*)&na, sizeof(na));
        }
    }
    return orig_connect(socket, addr, len);
}

static ssize_t fake_sendto(int socket, const void* buffer, size_t length, int flags,
                            const struct sockaddr* dest_addr, socklen_t dest_len) {
    if (sock_type(socket) == SOCK_DGRAM) {
        struct sockaddr_in na;
        int red = rewrite_to_relay(dest_addr, &na);
        dst_diag("sendto", socket, dest_addr ? dest_addr->sa_family : 0, dest_addr, red);
        if (red) {
            return orig_sendto(socket, buffer, length, flags,
                               (const struct sockaddr*)&na, sizeof(na));
        }
    }
    return orig_sendto(socket, buffer, length, flags, dest_addr, dest_len);
}

static int fake_bind(int socket, const struct sockaddr* addr, socklen_t len) {
    int r = orig_bind(socket, addr, len);
    if (r == 0 && sock_type(socket) == SOCK_DGRAM && addr) {
        int fam = addr->sa_family;
        int is_any = 0;
        if (fam == AF_INET) {
            const struct sockaddr_in* sin = (const struct sockaddr_in*)(const void*)addr;
            is_any = (sin->sin_addr.s_addr == INADDR_ANY);
        }
        // 记录所有 UDP bind（含回环 127.0.0.1 与 IPv6 ::1），便于看清分片对等体的绑定地址
        dst_diag("bind", socket, fam, addr, is_any);
        // 房主游戏服务器监听 0.0.0.0(UDP)：主动发 1 字节注册包到中继，
        // 让中继记录房主出口地址，加入者才能被转发过来（NAT 打洞）。
        if (fam == AF_INET && is_any) {
            struct sockaddr_in na;
            memset(&na, 0, sizeof(na));
            na.sin_family = AF_INET;
            na.sin_addr.s_addr = g_relay_ip;
            na.sin_port = htons(DST_RELAY_PORT);
            const char probe = 0;
            ssize_t s = orig_sendto(socket, &probe, 1, 0,
                                    (const struct sockaddr*)&na, sizeof(na));
            LOGD("bind(UDP INADDR_ANY) fd=%d -> relay register (s=%zd)", socket, s);
        }
    }
    return r;
}

static void dst_online_init() {
    dst_ensure_log();
    g_relay_ip = inet_addr(DST_RELAY_IP);
    LOGD("=== DST UDP relay init (relay=%s:%d) ===", DST_RELAY_IP, DST_RELAY_PORT);

    struct rebinding rebinds[] = {
        {"connect", (void*)fake_connect, (void**)&orig_connect},
        {"sendto",  (void*)fake_sendto,  (void**)&orig_sendto},
        {"bind",    (void*)fake_bind,    (void**)&orig_bind},
    };
    int rc = rebind_symbols(rebinds, sizeof(rebinds)/sizeof(rebinds[0]));
    LOGD("rebind_symbols rc=%d (0=OK)", rc);
    LOGD("=== DST UDP relay done ===");
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

static NSString* extract_field_from_file(NSString* path, NSString* field) {
    if (!path || ![[NSFileManager defaultManager] fileExistsAtPath:path]) return nil;
    NSData* data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;

    NSError* error = nil;
    NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error || !json) return nil;

    if ([json objectForKey:field]) {
        return [json objectForKey:field];
    }
    return nil;
}

static NSString* find_game_userid() {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* home = NSHomeDirectory();
    NSString* pendingPath = [home stringByAppendingPathComponent:@"Documents/DoNotStarveTogether/client_save/pending_keyvalues_prod"];

    if (![fm fileExistsAtPath:pendingPath]) return nil;
    return extract_field_from_file(pendingPath, @"OfflineID");
}

static bool patch_cache(NSString* cachePath, NSString* userId) {
    NSData* data = [NSData dataWithContentsOfFile:cachePath];
    if (!data) return false;

    NSError* error = nil;
    NSMutableDictionary* json = [NSJSONSerialization JSONObjectWithData:data
                                                                options:NSJSONReadingMutableContainers
                                                                  error:&error];
    if (error || !json) return false;

    [json setObject:(userId ? userId : @"") forKey:@"OfflineUserID"];

    NSData* patchedData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&error];
    if (error || !patchedData) return false;

    return [patchedData writeToFile:cachePath atomically:YES];
}

__attribute__((constructor))
static void iosvision_init() {
    LOGD("IOSVISION v6.1 - One shot");

    NSFileManager* fm = [NSFileManager defaultManager];

    NSString* bundlePath = [[NSBundle mainBundle] pathForResource:@"inventory_cache_prod" ofType:nil];
    if (!bundlePath || ![fm fileExistsAtPath:bundlePath]) {
        LOGE("inventory_cache_prod not found in bundle!");
        return;
    }

    NSString* userId = find_game_userid();
    LOGD("Game ID: %s", userId ? [userId UTF8String] : "(file not found)");

    if (!userId) {
        LOGD("pending_keyvalues_prod not found, skip (first launch)");
        return;
    }

    NSString* home = NSHomeDirectory();
    NSString* targetDir = [home stringByAppendingPathComponent:@"Documents/DoNotStarveTogether/client_save"];

    [fm createDirectoryAtPath:targetDir withIntermediateDirectories:YES attributes:nil error:nil];
    if (![fm fileExistsAtPath:targetDir]) {
        LOGE("Cannot create target dir!");
        return;
    }

    NSString* cachePath = [targetDir stringByAppendingPathComponent:@"inventory_cache_prod"];

    if ([fm fileExistsAtPath:cachePath]) {
        NSString* existingId = extract_field_from_file(cachePath, @"OfflineUserID");
        if (existingId && userId && [existingId isEqualToString:userId]) {
            LOGD("Skip (ID already matches)");
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

    patch_cache(cachePath, userId);

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
