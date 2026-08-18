/*
 * iOS DST 私有服在线联机注入器 v4.0  (dyld_dynamic_interpose 运行时版，arm64e 安全，dyld4 兼容)
 *
 * 设计目标：完全替代官方在线联机，让游戏原生 UI（建房 / 直连）直接跨网可用，
 *          不再依赖任何 Lua 房间屏，也不再使用 Dobby（Dobby 在 iOS arm64e 上
 *          PAC 跳板不兼容 → 白屏 / SIGBUS 崩，已弃用），也不再使用 fishhook。
 *
 * 核心机制（二进制层面，透明）：
 *  - 用 **dyld_dynamic_interpose()**（dyld4 官方运行时 API）对 libsystem 的
 *    connect / sendto / bind / open* / close* 做符号替换。该 API 在构造函数里、
 *    镜像已加载之后应用，**不碰任何受写保护的内存页**（不写 __DATA_CONST.__got），
 *    因此 arm64e 链式修复 + 写保护页下绝不 SIGBUS，且不会像静态 __interpose 段那样
 *    在 dyld4 加载期 closure 构建阶段被拒（那会导致进程在跑任何构造函数之前就被打掉
 *    → 白屏、零日志，无法诊断）。dyld_dynamic_interpose 不可用时软失败（记日志、不崩）。
 *    —— 这正是此前 fishhook(DYLD_INTERPOSE 静态段)在 1.3.0 上崩白屏的根因。
 *  - 游戏（DST）所有「非回环的外部 UDP」一律重写目的地址为我们的中继
 *    (47.122.115.99:12000..12999)，由云端中继做 N-way 字节转发，实现 iPhone↔iPhone 跨网。
 *    房主出站 UDP 被重写到「该房间独立端口」（由 Lua 写入 Documents/ios_relay_port.txt），
 *    从而实现多房间端口隔离、互不串扰。
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
#include <fcntl.h>
#include <sys/stat.h>
#include <strings.h>   // strcasecmp (auth-forge host compare)

#include <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <UIKit/UIKit.h>
#include <Security/Security.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include "fishhook.h"

// ---- 中继配置（与 server/relay/relay_server.py 的 RELAY_BASE_PORT 对齐）----
//  端口段 12000..12999：每房间按 roomId 派生独立端口（relay_port_for_room），
//  dylib 通过 Documents/ios_relay_port.txt 读取房主当前房间端口（默认 12000）。
#define DST_RELAY_IP   "47.122.115.99"
#define DST_RELAY_PORT 12000

static uint32_t g_relay_ip = 0;   // 网络字节序，便于直接比较 sin_addr.s_addr

// ---- 授权门控（对齐参考包 _g_authed，v10 文件型·免重启）：
//  未授权 -> 游戏走「原版」：不重定向 UDP、不重定向 Klei 域名、不连私服，
//            可正常离线单机 / 官方 Klei 流程（参考包「未授权=原版」同款）。
//  已授权 -> 激活完整私有集成（UDP 重写到 relay + Klei 域名重定向 + 私服大厅）。
//  判据 = Documents/ios_auth_token.txt 存在且非空（参考包 v71：token 主存 CWD 文件，
//  Lua IOSAuthActivate 成功后 io.open 写入；dylib 惰性 stat，2s TTL 缓存）。
//  授权 -> 网络重定向在 2 秒内自动生效，免重启；删 token 文件即回到原版。
//  增强 scripts.zip/images.zip 始终从服务器动态拉（绝不在 IPA 内烤死）。
static int g_authed_cache = -1;          // -1=未评估 0/1=缓存值
static time_t g_authed_at = 0;

static int dst_is_authed(void) {
    time_t now = time(NULL);
    if (g_authed_cache >= 0 && now - g_authed_at < 2) return g_authed_cache;
    int authed = 0;
    @autoreleasepool {
        NSString* p = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                        stringByAppendingPathComponent:@"ios_auth_token.txt"];
        NSDictionary* att = [[NSFileManager defaultManager] attributesOfItemAtPath:p error:nil];
        if (att) {
            unsigned long long sz = [att fileSize];
            if (sz > 0) authed = 1;
        }
    }
    g_authed_cache = authed;
    g_authed_at = now;
    return authed;
}

// ---- 房主建房端口（房间隔离）：Lua 把 /api/register 返回的端口写入
//  Documents/ios_relay_port.txt，dylib 惰性读取（1s 缓存），把房主出站 UDP
//  重写到「该房间独立中继端口」，实现多房间互不串扰。默认 12000（兼容旧单房间）。
//  与 server/relay/relay_server.py 的 relay_port_for_room(roomId) 派生保持一致。
static int g_relay_port_cache = -1;
static time_t g_relay_port_at = 0;
static int dst_relay_port(void) {
    time_t now = time(NULL);
    if (g_relay_port_cache > 0 && now - g_relay_port_at < 1) return g_relay_port_cache;
    int p = DST_RELAY_PORT;
    @autoreleasepool {
        NSString* path = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                           stringByAppendingPathComponent:@"ios_relay_port.txt"];
        FILE* f = fopen([path UTF8String], "r");
        if (f) {
            int v = 0;
            if (fscanf(f, "%d", &v) == 1 && v >= 12000 && v <= 12999) p = v;
            fclose(f);
        }
    }
    g_relay_port_cache = p;
    g_relay_port_at = now;
    return p;
}

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

// ============ 最优先构造函数：加载标记 + 崩溃捕获（优先级 1，最先跑）============
__attribute__((constructor(1)))
static void dst_load_marker() {
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
    dst_ensure_log();
    LOGD("=== DYLIB LOADED (libIOSVISION diag / fishhook rebind_symbols) ===");
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
    // 整个 12000..12999 中继段都视为「已是中继」，避免自环。
    // 端口由 roomId 派生（动态），故用范围匹配而非单一固定值。
    return ip_net == g_relay_ip && port >= 12000 && port <= 12999;
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

// ============ 原始函数指针（通过 dlsym(RTLD_NEXT) 在构造函数里解析，避免递归）============
typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
typedef ssize_t (*sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef int (*bind_t)(int, const struct sockaddr*, socklen_t);
typedef ssize_t (*recvfrom_t)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef int (*open_t)(const char*, int, ...);
typedef int (*openat_t)(int, const char*, int, ...);
typedef int (*close_t)(int);

static connect_t orig_connect = NULL;
static sendto_t  orig_sendto  = NULL;
static bind_t    orig_bind    = NULL;
static recvfrom_t orig_recvfrom = NULL;
static open_t    orig_open             = NULL;
static open_t    orig_open_nocancel    = NULL;
static openat_t  orig_openat           = NULL;
static openat_t  orig_openat_nocancel  = NULL;
static close_t   orig_close            = NULL;
static close_t   orig_close_nocancel   = NULL;
typedef int (*rename_t)(const char*, const char*);
typedef int (*renameat_t)(int, const char*, int, const char*);
static rename_t   orig_rename          = NULL;
static renameat_t orig_renameat        = NULL;

// ---- EOS/Klei auth forgery (copy KAlert's gethostbyname/getaddrinfo redirect) ----
// Redirect ONLY the 3 Klei account/auth domains to our self-hosted server so the
// online cluster's auth no longer stalls on unreachable Klei/EOS in mainland CN.
// We do NOT copy KAlert's VFS Lua injection, its broad all-klei-domain redirect,
// or its UDP relay (our own UDP relay above stays).
typedef struct hostent* (*gethostbyname_t)(const char*);
typedef int (*getaddrinfo_t)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
static gethostbyname_t orig_gethostbyname = NULL;
static getaddrinfo_t   orig_getaddrinfo   = NULL;

// ---- C-stdio 文件写路径（DST 是 C++ 引擎，很可能走 fopen/fwrite/fclose，而非 POSIX open）----
typedef FILE* (*fopen_t)(const char*, const char*);
typedef int   (*fclose_t)(FILE*);
static fopen_t  orig_fopen            = NULL;
static fclose_t orig_fclose           = NULL;

// ---- Foundation 写方法 swizzle 原始 IMP（编译单元为 .mm + -fobjc-arc）----
static BOOL (*orig_NSData_wtf)(id, SEL, NSString*, BOOL) = NULL;
static BOOL (*orig_NSString_wtf)(id, SEL, NSString*, BOOL, NSStringEncoding, NSError**) = NULL;
static BOOL (*orig_NSMgr_createFile)(id, SEL, NSString*, NSData*, NSDictionary*) = NULL;

// 前向声明：runtime interpose 在构造函数里引用这些 replacement，而它们的定义在文件下方
static int  fake_connect(int, const struct sockaddr*, socklen_t);
static ssize_t fake_sendto(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
static int  fake_bind(int, const struct sockaddr*, socklen_t);
static ssize_t fake_recvfrom(int, void*, size_t, int, struct sockaddr*, socklen_t*);
static int  fake_open(const char*, int, ...);
static int  fake_open_nocancel(const char*, int, ...);
static int  fake_openat(int, const char*, int, ...);
static int  fake_openat_nocancel(int, const char*, int, ...);
static int  fake_close(int);
static int  fake_close_nocancel(int);
static int  fake_rename(const char*, const char*);
static int  fake_renameat(int, const char*, int, const char*);
static FILE* fake_fopen(const char*, const char*);
static int   fake_fclose(FILE*);
// auth-forge forward decls
static struct hostent* fake_gethostbyname(const char*);
static int fake_getaddrinfo(const char*, const char*, const struct addrinfo*, struct addrinfo**);

// 授权门控（v10 文件型）：dst_is_authed() 惰性检查 Documents/ios_auth_token.txt
// （2s TTL 缓存）。Lua IOSAuthActivate 成功写入后 2 秒内网络重定向自动生效（免重启）。

// ---- 尽力而为的 TLS 证书校验绕过（参考包开箱即用的关键）----
// 若 OpenSSL 的 X509_verify_cert 符号可被 fishhook 重绑定（动态链接时），
// 直接返回 1，使自签 CA 也被接受，无需设备手动信任。
// 静态链接不可 hook 时本项自动失效，无副作用。
typedef int (*x509_verify_cert_fn)(void* ctx);
static x509_verify_cert_fn orig_X509_verify_cert = NULL;
static int fake_X509_verify_cert(void* ctx) {
    (void)ctx;
    LOGD("[CERT-BYPASS] X509_verify_cert forced OK (self-signed accepted)");
    return 1;
}

// ============ 解析原始函数 + 运行时应用 hook（dyld4 兼容，v4.0 关键修正）============
// 不再使用静态 __interpose 段（DYLD_INTERPOSE 宏）。在 iOS 15+ 的 dyld4 上，嵌入式
// dylib 的静态 __interpose 段常在「加载期 launch closure 构建」阶段被 dyld 拒绝/异常
// → 进程在跑任何构造函数之前就被打掉（白屏、零日志，无法诊断）。
// 改为运行时调用 dyld 官方 API dyld_dynamic_interpose()：在构造函数里、镜像已加载之后
// 应用，不写任何受保护内存页（arm64e 安全），且 dyld_dynamic_interpose 不存在时
// 可软失败（记日志、不崩溃，游戏照常运行）。仅对 dlsym 解析到的非空原始指针建立元组，
// 避免把某些环境缺失的 $NOCANCEL 变体塞进静态段导致加载期崩。
typedef void (*dyld_dynamic_interpose_fn)(const void* tuples, size_t count);
struct dyld_interpose_tuple_local { const void* replacement; const void* replacee; };

__attribute__((constructor(2)))
static void dst_resolve_and_interpose() {
    orig_connect          = (connect_t)dlsym(RTLD_NEXT, "connect");
    orig_sendto           = (sendto_t)dlsym(RTLD_NEXT, "sendto");
    orig_bind             = (bind_t)dlsym(RTLD_NEXT, "bind");
    orig_recvfrom         = (recvfrom_t)dlsym(RTLD_NEXT, "recvfrom");
    orig_open             = (open_t)dlsym(RTLD_NEXT, "open");
    orig_open_nocancel    = (open_t)dlsym(RTLD_NEXT, "open$NOCANCEL");
    orig_openat           = (openat_t)dlsym(RTLD_NEXT, "openat");
    orig_openat_nocancel  = (openat_t)dlsym(RTLD_NEXT, "openat$NOCANCEL");
    orig_close            = (close_t)dlsym(RTLD_NEXT, "close");
    orig_close_nocancel   = (close_t)dlsym(RTLD_NEXT, "close$NOCANCEL");
    orig_rename           = (rename_t)dlsym(RTLD_NEXT, "rename");
    orig_renameat         = (renameat_t)dlsym(RTLD_NEXT, "renameat");
    // auth-forge: resolve DNS hooks
    orig_gethostbyname    = (gethostbyname_t)dlsym(RTLD_NEXT, "gethostbyname");
    orig_getaddrinfo      = (getaddrinfo_t)dlsym(RTLD_NEXT, "getaddrinfo");
    // C-stdio 写路径：直接取标准库实现地址。
    // 之前漏了这两行赋值 -> orig_fopen/orig_fclose 恒为 NULL -> fake_fopen/fake_fclose
    // 因 ADD_TUPLE 跳过 NULL 而从未 interpose -> 游戏用 fopen 写 cluster_token.txt 时
    // 完全绕过 hook -> 落盘空 -> 专用服 instance_2 读到空 -> 建房卡死。这是此前
    // "重装最新包仍卡" 的真正根因（dylib 加载了、hook 应用了，但 fopen 根本没被 hook）。
    orig_fopen  = (fopen_t)fopen;
    orig_fclose = (fclose_t)fclose;
    dst_ensure_log();
    LOGD("originals resolved: connect=%p sendto=%p bind=%p open=%p openat=%p close=%p fopen=%p fclose=%p",
         (void*)orig_connect, (void*)orig_sendto, (void*)orig_bind,
         (void*)orig_open, (void*)orig_openat, (void*)orig_close,
         (void*)orig_fopen, (void*)orig_fclose);

    // v10 门控模型（对齐参考包 _g_authed）：未授权 = 网络完全原版（离线单机/官方流程）；
    // 授权（Documents/ios_auth_token.txt 非空）= UDP->relay + Klei 域名->私服重定向。
    // 增强脚本/资源由后台线程动态拉取（constructor 不阻塞），ready.flag 配对落地。
    LOGD("authed-redirect mode v11: network hooks gated by Documents/ios_auth_token.txt");

    // ------------------------------------------------------------------
    // 用 facebook fishhook (rebind_symbols) 替代 dyld_dynamic_interpose。
    // 真机实证：dyld_dynamic_interpose 在 arm64e 上静默 no-op（dst_hook.log 零 [DIAG]），
    // 而 fishhook 能真正拦截（见 2026-08-14 成功托管）。诊断版额外 hook recvfrom，
    // 并把 connect/sendto/bind/recvfrom 全量打出目的地址，定位专用服(instance_2)卡死点。
    // 注意：本诊断版只 hook 网络+DNS 符号，不 hook 文件(open/close/fopen)，
    // 以对齐此前 proven-working 的 fishhook 构建、避免 cluster_token 随机令牌回归。
    struct rebinding rebinds[] = {
        {"connect",  (void*)fake_connect,  (void**)&orig_connect},
        {"sendto",   (void*)fake_sendto,   (void**)&orig_sendto},
        {"bind",     (void*)fake_bind,     (void**)&orig_bind},
        {"recvfrom", (void*)fake_recvfrom, (void**)&orig_recvfrom},
        {"gethostbyname", (void*)fake_gethostbyname, (void**)&orig_gethostbyname},
        {"getaddrinfo",   (void*)fake_getaddrinfo,   (void**)&orig_getaddrinfo},
        {"X509_verify_cert", (void*)fake_X509_verify_cert, (void**)&orig_X509_verify_cert},
        // 文件重定向：动态整包（scripts.zip/images.zip 读 -> Documents 副本）+ cluster_token 注入
        {"open",            (void*)fake_open,            (void**)&orig_open},
        {"open$NOCANCEL",   (void*)fake_open_nocancel,   (void**)&orig_open_nocancel},
        {"openat",          (void*)fake_openat,          (void**)&orig_openat},
        {"openat$NOCANCEL", (void*)fake_openat_nocancel, (void**)&orig_openat_nocancel},
        {"fopen",           (void*)fake_fopen,           (void**)&orig_fopen},
        {"rename",          (void*)fake_rename,          (void**)&orig_rename},
        {"renameat",        (void*)fake_renameat,        (void**)&orig_renameat},
    };
    int n = (int)(sizeof(rebinds) / sizeof(rebinds[0]));
    int rc = rebind_symbols(rebinds, (size_t)n);
    LOGD("fishhook rebind_symbols rc=%d (0=OK) funcs=%d", rc, n);
}

// ---- cluster_token.txt 空文件兜底（iOS 建房令牌校验，治本）----
// 真因（8 轮真机日志定位）：主进程写 cluster_token.txt 与拉起专用子进程(instance_2)
// 存在写盘竞态，子进程读到的文件是空的 → 游戏报 "No auth token could be found" /
// "Your Server Will Not Start !!!!". 服务端响应格式已验证正确，此问题纯属客户端原生层。
// 本 dylib 经 LC_LOAD_DYLIB 注入主二进制 dontstarvetogether；专用子进程是同一二进制
// 再 exec，故本 hook 同时覆盖子进程。拦「读取 cluster_token.txt」：若文件空/不存在，
// 先注入一个有效 pds-g<base64>= 令牌，再返回已填好内容的 fd，子进程即可拿到令牌走通建房。
static __thread int g_open_reent = 0;
static int g_token_inject_log = 0;

static int path_is_cluster_token(const char* path) {
    if (!path) return 0;
    return strstr(path, "cluster_token.txt") != NULL;
}

// 诊断：记录游戏对 cluster_token.txt 用哪个文件 API 操作（定位空文件根因用）
static int g_file_diag = 0;
static void diag_file_op(const char* func, const char* path, const char* extra) {
    if (!path_is_cluster_token(path)) return;
    if (g_file_diag++ < 20)
        LOGD("[DIAG-FILE] %s path=%s %s", func ? func : "?", path ? path : "(null)", extra ? extra : "");
}

// 判定这是「读取」打开（需要注入兜底）：纯写(O_WRONLY)与重建截断(O_RDWR|O_TRUNC)排除，
// 避免误改游戏自身的写盘逻辑。覆盖 O_RDONLY 与 O_RDWR(非截断) 两类读场景。
static int open_is_read(int flags) {
    int acc = flags & O_ACCMODE;
    if (acc == O_RDONLY) return 1;
    if (acc == O_RDWR && !(flags & O_TRUNC)) return 1;
    return 0;
}

// 生成 pds-g<base64>= 令牌（与 server/api/main.py 的 klei_token() 同形态）
static void gen_klei_token(char* buf, size_t buflen) {
    unsigned char raw[32];
    arc4random_buf(raw, sizeof(raw));
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char enc[48]; int oi = 0;
    for (int i = 0; i + 3 <= 32; i += 3) {
        unsigned n = (raw[i] << 16) | (raw[i+1] << 8) | raw[i+2];
        enc[oi++] = b64[(n >> 18) & 0x3F];
        enc[oi++] = b64[(n >> 12) & 0x3F];
        enc[oi++] = b64[(n >> 6)  & 0x3F];
        enc[oi++] = b64[n & 0x3F];
    }
    // 末尾剩 2 字节 (raw[30], raw[31]) -> 3 个 base64 + 1 个 '='
    unsigned tail = (raw[30] << 16) | (raw[31] << 8);
    enc[oi++] = b64[(tail >> 18) & 0x3F];
    enc[oi++] = b64[(tail >> 12) & 0x3F];
    enc[oi++] = b64[(tail >> 6)  & 0x3F];
    enc[oi++] = '=';
    enc[oi] = '\0';                         // 共 44 字符，末尾 '='
    snprintf(buf, buflen, "pds-g%s", enc);
}

// 用「原始 open 指针」做空文件检测 + 注入（直接走原始指针，不碰被 hook 的符号，杜绝递归）
static void ensure_cluster_token(const char* path,
                                 int (*real_open)(const char*, int, ...)) {
    if (!real_open) return;
    int fd0 = real_open(path, O_RDONLY);
    int empty = 1;
    if (fd0 >= 0) {
        char c; ssize_t n = read(fd0, &c, 1);
        close(fd0);
        empty = (n <= 0);
    }
    if (!empty) return;                     // 文件已有内容 → 不干预
    char tok[128];
    gen_klei_token(tok, sizeof(tok));
    int wfd = real_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wfd >= 0) {
        ssize_t w = write(wfd, tok, (size_t)strlen(tok));
        close(wfd);
        if (g_token_inject_log++ < 5)
            LOGD("cluster_token.txt was empty/missing -> injected valid token (len=%zd)", (ssize_t)strlen(tok));
        (void)w;
    }
}

// openat 变体（多一个 dirfd 参数，函数指针签名不同，不能与上面复用）
static void ensure_cluster_token_at(const char* path, int dirfd,
                                    int (*real_openat)(int, const char*, int, ...)) {
    if (!real_openat) return;
    int fd0 = real_openat(dirfd, path, O_RDONLY);
    int empty = 1;
    if (fd0 >= 0) {
        char c; ssize_t n = read(fd0, &c, 1);
        close(fd0);
        empty = (n <= 0);
    }
    if (!empty) return;
    char tok[128];
    gen_klei_token(tok, sizeof(tok));
    int wfd = real_openat(dirfd, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wfd >= 0) {
        ssize_t w = write(wfd, tok, (size_t)strlen(tok));
        close(wfd);
        if (g_token_inject_log++ < 5)
            LOGD("cluster_token.txt(AT) empty/missing -> injected valid token");
        (void)w;
    }
}

// 从可变参数里取 mode（O_CREAT 时才有）：mode_t 是可提升类型，va_arg 必须按 int 取再转回，
// 否则有未定义行为（编译器 -Wvarargs 警告）。
#define EXTRACT_MODE(flags, mode) \
    do { if (flags & O_CREAT) { va_list _ap; va_start(_ap, flags); (mode) = (mode_t)va_arg(_ap, int); va_end(_ap); } else { (mode) = 0; } } while(0)

// 父进程打开 cluster_token.txt 写模式时记录 fd+路径；其 close 时把文件重写为有效令牌
static int   g_tok_wfd   = -1;
static char  g_tok_wpath[1024] = {0};

static void record_tok_write_fd(int fd, const char* path, int flags) {
    if (fd < 0 || !path) return;
    int acc = flags & O_ACCMODE;
    if (path_is_cluster_token(path) && acc != O_RDONLY) {   // O_WRONLY / O_RDWR 均记录
        g_tok_wfd = fd;
        strncpy(g_tok_wpath, path, sizeof(g_tok_wpath) - 1);
        g_tok_wpath[sizeof(g_tok_wpath) - 1] = '\0';
    }
}

// 父进程写完 cluster_token.txt 关 fd 时，用原始 open/close 把文件重写为有效令牌
// （直接走 orig_ 指针，不碰被 hook 的符号，杜绝递归）
static void rewrite_cluster_token_on_close() {
    if (g_tok_wpath[0] == '\0') return;
    char tok[128];
    gen_klei_token(tok, sizeof(tok));
    int wfd = orig_open ? orig_open(g_tok_wpath, O_WRONLY | O_CREAT | O_TRUNC, 0644)
                        : open(g_tok_wpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wfd >= 0) {
        ssize_t w = write(wfd, tok, (size_t)strlen(tok));
        if (orig_close) orig_close(wfd); else close(wfd);
        if (g_token_inject_log++ < 5)
            LOGD("cluster_token.txt (parent write close) -> rewritten valid token (len=%zd)", (ssize_t)strlen(tok));
        (void)w;
    }
    g_tok_wpath[0] = '\0';
}

// ---- 动态整包重定向：游戏读取 bundle 内 scripts.zip/images.zip 时，
// 若 Documents/dst_assets_cache/ 下存在已下载副本，则重定向到该副本打开。
// 这样即使 app bundle 只读（iOS 常态）也能用上服务器下发的整包
// （参考包式动态加载，文件层实现，不依赖 bundle 可写）。
// v10 配对条件：仅当 ready.flag 存在（scripts.zip 与 images.zip 都完整下载并通过
// PK 魔数校验后由后台线程写入）才重定向——保证两个包永远版本配对（缺一会崩），
// 且首次启动（后台尚未下载完）时游戏完全使用内置原版包，不阻塞、不白屏。
static const char* g_dst_db_names[] = { "scripts.zip", "images.zip" };
static char g_dst_redirect_buf[1024];
static int  g_ready_cache = -1;      // -1=未评估
static time_t g_ready_at = 0;

static int dst_assets_ready(void) {
    time_t now = time(NULL);
    if (g_ready_cache >= 0 && now - g_ready_at < 3) return g_ready_cache;
    int ready = 0;
    @autoreleasepool {
        NSString* flag = [[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                            stringByAppendingPathComponent:@"dst_assets_cache"]
                           stringByAppendingPathComponent:@"ready.flag"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:flag]) ready = 1;
    }
    g_ready_cache = ready;
    g_ready_at = now;
    return ready;
}

static const char* dst_redirect_databundle(const char* path) {
    if (!path) return path;
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    int hit = 0;
    for (int i = 0; i < 2; i++) {
        if (strcmp(base, g_dst_db_names[i]) == 0) { hit = 1; break; }
    }
    if (!hit) return path;
    if (!dst_assets_ready()) return path;   // 双包未配对落地 -> 用内置原版
    @autoreleasepool {
        NSString* nm = [NSString stringWithUTF8String:base];
        NSString* cache = [[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                             stringByAppendingPathComponent:@"dst_assets_cache"]
                            stringByAppendingPathComponent:nm];
        if ([[NSFileManager defaultManager] fileExistsAtPath:cache]) {
            const char* c = [cache UTF8String];
            strncpy(g_dst_redirect_buf, c, sizeof(g_dst_redirect_buf) - 1);
            g_dst_redirect_buf[sizeof(g_dst_redirect_buf) - 1] = '\0';
            LOGD("databundle redirect: %s -> %s", path, g_dst_redirect_buf);
            return g_dst_redirect_buf;
        }
    }
    return path;
}

static int fake_open(const char* path, int flags, ...) {
    mode_t mode = 0; EXTRACT_MODE(flags, mode);
    diag_file_op("open", path, NULL);
    if (!g_open_reent && open_is_read(flags)) {
        const char* red = dst_redirect_databundle(path);
        if (red != path) {
            int rfd = orig_open ? orig_open(red, flags, mode) : open(red, flags, mode);
            record_tok_write_fd(rfd, path, flags);
            return rfd;
        }
    }
    if (!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)) {
        g_open_reent = 1;
        ensure_cluster_token(path, orig_open);
        g_open_reent = 0;
    }
    int fd = orig_open ? orig_open(path, flags, mode) : open(path, flags, mode);
    record_tok_write_fd(fd, path, flags);
    return fd;
}

static int fake_open_nocancel(const char* path, int flags, ...) {
    mode_t mode = 0; EXTRACT_MODE(flags, mode);
    open_t real = orig_open_nocancel ? orig_open_nocancel : orig_open;
    if (!g_open_reent && open_is_read(flags)) {
        const char* red = dst_redirect_databundle(path);
        if (red != path) {
            int rfd = real(red, flags, mode);
            record_tok_write_fd(rfd, path, flags);
            return rfd;
        }
    }
    if (!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)) {
        g_open_reent = 1;
        ensure_cluster_token(path, real);
        g_open_reent = 0;
    }
    int fd = real(path, flags, mode);
    record_tok_write_fd(fd, path, flags);
    return fd;
}

static int fake_openat(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0; EXTRACT_MODE(flags, mode);
    diag_file_op("openat", path, NULL);
    if (!g_open_reent && open_is_read(flags)) {
        const char* red = dst_redirect_databundle(path);
        if (red != path) {
            int rfd = orig_open ? orig_open(red, flags, mode) : open(red, flags, mode);
            record_tok_write_fd(rfd, path, flags);
            return rfd;
        }
    }
    if (!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)) {
        g_open_reent = 1;
        ensure_cluster_token_at(path, dirfd, orig_openat);
        g_open_reent = 0;
    }
    int fd = orig_openat ? orig_openat(dirfd, path, flags, mode)
                         : openat(dirfd, path, flags, mode);
    record_tok_write_fd(fd, path, flags);
    return fd;
}

static int fake_openat_nocancel(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0; EXTRACT_MODE(flags, mode);
    openat_t real = orig_openat_nocancel ? orig_openat_nocancel : orig_openat;
    if (!g_open_reent && open_is_read(flags)) {
        const char* red = dst_redirect_databundle(path);
        if (red != path) {
            int rfd = orig_open ? orig_open(red, flags, mode) : open(red, flags, mode);
            record_tok_write_fd(rfd, path, flags);
            return rfd;
        }
    }
    if (!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)) {
        g_open_reent = 1;
        ensure_cluster_token_at(path, dirfd, real);
        g_open_reent = 0;
    }
    int fd = real(dirfd, path, flags, mode);
    record_tok_write_fd(fd, path, flags);
    return fd;
}

static int fake_close(int fd) {
    if (fd >= 0 && fd == g_tok_wfd) {
        g_tok_wfd = -1;
        rewrite_cluster_token_on_close();
    }
    return orig_close ? orig_close(fd) : close(fd);
}

static int fake_close_nocancel(int fd) {
    if (fd >= 0 && fd == g_tok_wfd) {
        g_tok_wfd = -1;
        rewrite_cluster_token_on_close();
    }
    return orig_close_nocancel ? orig_close_nocancel(fd) : close(fd);
}

// ===== rename / renameat hook（治本关键）=====
// 游戏写 cluster_token.txt 常用「先写临时文件再 rename」模式；临时路径不含
// "cluster_token.txt"，故 open/close/fopen/fclose 全部漏掉。这里在 rename 落点
// 是 cluster_token.txt 时补写有效令牌，覆盖这条漏网路径（C++ 引擎与 Foundation
// 原子写都走 rename）。专用服子进程不加载本 dylib，故必须由父进程把磁盘文件补全。
static int fake_rename(const char* oldpath, const char* newpath) {
    diag_file_op("rename", newpath, NULL);
    if (!orig_rename) return -1;
    int r = orig_rename(oldpath, newpath);
    if (r == 0 && newpath && path_is_cluster_token(newpath)) {
        if (!g_open_reent) {
            g_open_reent = 1;
            ensure_cluster_token(newpath, orig_open);
            g_open_reent = 0;
        }
    }
    return r;
}

static int fake_renameat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath) {
    if (!orig_renameat) return -1;
    int r = orig_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (r == 0 && newpath && path_is_cluster_token(newpath)) {
        if (!g_open_reent) {
            g_open_reent = 1;
            ensure_cluster_token_at(newpath, newdirfd, orig_openat);
            g_open_reent = 0;
        }
    }
    return r;
}

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
    na->sin_port = htons(dst_relay_port());   // 房主房间独立端口（文件读取）
    return 1;
}

static int fake_connect(int socket, const struct sockaddr* addr, socklen_t len) {
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
    // v10 授权门控（参考包 _g_authed 同款）：未授权 = 一律透传，游戏走原版网络
    int authed = dst_is_authed();
    int st = sock_type(socket);
    if (authed && st == SOCK_DGRAM) {
        struct sockaddr_in na;
        int red = rewrite_to_relay(addr, &na);
        dst_diag("connect", socket, addr ? addr->sa_family : 0, addr, red);
        if (red) {
            LOGD("connect(UDP) -> relay");
            return orig_connect(socket, (const struct sockaddr*)&na, sizeof(na));
        }
    } else if (authed && addr && addr->sa_family == AF_INET) {
        // TCP: 在 socket 层把到外网 Web 端口(80/443)的连接重定向到私服，
        // 覆盖 libcurl(c-ares) 等绕过 getaddrinfo/gethostbyname 的解析路径
        // （参考包即采用 connect 层重定向，故能开箱即用）。
        const struct sockaddr_in* sin = (const struct sockaddr_in*)(const void*)addr;
        uint32_t ip = sin->sin_addr.s_addr;
        int port = ntohs(sin->sin_port);
        uint32_t server_ip = inet_addr(DST_RELAY_IP);
        if (!is_loopback(ip) && ip != g_relay_ip && ip != server_ip
            && (port == 80 || port == 443)) {
            struct sockaddr_in na;
            memset(&na, 0, sizeof(na));
            na.sin_family = AF_INET;
            na.sin_addr.s_addr = server_ip;
            na.sin_port = htons(port);
            dst_diag("connect", socket, AF_INET, addr, 1);
            LOGD("connect(TCP :%d) -> %s (web redirect)", port, DST_RELAY_IP);
            return orig_connect(socket, (const struct sockaddr*)&na, sizeof(na));
        }
        dst_diag("connect", socket, AF_INET, addr, 0);
    }
    return orig_connect(socket, addr, len);
}

static ssize_t fake_sendto(int socket, const void* buffer, size_t length, int flags,
                            const struct sockaddr* dest_addr, socklen_t dest_len) {
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
    if (dst_is_authed() && sock_type(socket) == SOCK_DGRAM) {
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
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
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
        // v10：仅在授权后注册（未授权不碰 relay，游戏保持原版行为）。
        if (fam == AF_INET && is_any && dst_is_authed()) {
            struct sockaddr_in na;
            memset(&na, 0, sizeof(na));
            na.sin_family = AF_INET;
            na.sin_addr.s_addr = g_relay_ip;
            na.sin_port = htons(dst_relay_port());   // 房主房间独立端口（文件读取）
            const char probe = 0;
            ssize_t s = orig_sendto(socket, &probe, 1, 0,
                                    (const struct sockaddr*)&na, sizeof(na));
            LOGD("bind(UDP INADDR_ANY) fd=%d -> relay register (s=%zd)", socket, s);
        }
    }
    return r;
}

// ---- recvfrom 诊断钩子（ENTRY/EXIT 成对）----
// 卡死常因 recvfrom 永远收不到数据而阻塞：看到 "recvfrom ENTER fd=X" 之后没有对应
// "EXIT"，即说明该线程卡在等数据；EXIT 后带实际来源地址，可看清在等谁。
static int g_rf_cap = 0;
static ssize_t fake_recvfrom(int socket, void* buffer, size_t length, int flags,
                             struct sockaddr* addr, socklen_t* addr_len) {
    if (g_rf_cap++ < 6000)
        LOGD("[DIAG] recvfrom ENTER fd=%d", socket);
    ssize_t r = orig_recvfrom(socket, buffer, length, flags, addr, addr_len);
    if (g_rf_cap < 6000) {
        if (r >= 0 && addr && addr_len) {
            dst_diag("recvfrom", socket, addr->sa_family, addr, 0);
        } else {
            LOGD("[DIAG] recvfrom EXIT fd=%d r=%zd errno=%d", socket, r, errno);
        }
    }
    return r;
}

static void dst_online_init() {
    dst_ensure_log();
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
    LOGD("=== DST UDP relay init (relay=%s:%d, fishhook) ===", DST_RELAY_IP, DST_RELAY_PORT);
    LOGD("=== DST UDP relay done ===");
}

__attribute__((constructor(100)))
static void dst_online_ctor() {
    dst_online_init();
}

// ============ 看门狗：周期抓取所有线程 PC，精确定位卡死函数 ============
// 专用服(instance_2)建房卡死可能是「非 socket 阻塞」(互斥锁/条件变量死锁、文件等待、
// 线程互等)，这类卡死 connect/sendto/recvfrom 日志抓不到。看门狗每 5 秒用 Mach
// task_threads + thread_get_state 读出每个线程的 PC，并解析其所在 dylib/二进制+偏移，
// 直接显示「卡在哪个库/偏移」。建房转圈时看最后几次快照即知卡点。
static void* dst_watchdog(void* arg) {
    (void)arg;
    int dumps = 0;
    while (dumps < 40) {                 // 最多 40 次（约 200s）后停止，避免无限刷屏
        sleep(5);
        dumps++;
        thread_act_array_t threads = NULL;
        mach_msg_type_number_t count = 0;
        kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
        if (kr != KERN_SUCCESS) { LOGD("[WD] task_threads failed kr=%d", (int)kr); continue; }
        LOGD("[WD] === thread snapshot #%d (%d threads) ===", dumps, (int)count);
        int nimg = (int)_dyld_image_count();
        for (mach_msg_type_number_t i = 0; i < count; i++) {
            arm_thread_state64_t state;
            mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
            kr = thread_get_state(threads[i], ARM_THREAD_STATE64, (thread_state_t)&state, &sc);
            if (kr != KERN_SUCCESS) { LOGD("[WD]  tid#%d get_state fail kr=%d", (int)i, (int)kr); continue; }
            // pc 在 arm_thread_state64_t 中位于 x[29],fp,lr,sp 之后（uint64 索引 32）
            uint64_t pc = ((uint64_t*)&state)[32];
            char libbuf[320]; libbuf[0] = 0;
            for (int j = 0; j < nimg; j++) {
                const struct mach_header* h = _dyld_get_image_header(j);
                if (!h) continue;
                uint64_t base = (uint64_t)h + (uint64_t)_dyld_get_image_vmaddr_slide(j);
                uint64_t nextbase = (j + 1 < nimg)
                    ? (uint64_t)_dyld_get_image_header(j + 1) + (uint64_t)_dyld_get_image_vmaddr_slide(j + 1)
                    : base + 0x100000000ULL;
                if (pc >= base && pc < nextbase) {
                    snprintf(libbuf, sizeof(libbuf), "%s +0x%llx",
                             _dyld_get_image_name(j), (unsigned long long)(pc - base));
                    break;
                }
            }
            if (!libbuf[0]) snprintf(libbuf, sizeof(libbuf), "??? +0x%llx", (unsigned long long)pc);
            LOGD("[WD]  #%d pc=%s", (int)i, libbuf);
        }
        if (threads) vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_act_t));
    }
    LOGD("[WD] watchdog finished");
    return NULL;
}

__attribute__((constructor(150)))
static void dst_watchdog_ctor() {
    dst_ensure_log();
    LOGD("=== DST watchdog starting (fishhook diag build) ===");
    pthread_t t;
    if (pthread_create(&t, NULL, dst_watchdog, NULL) != 0) {
        LOGD("[WD] pthread_create failed");
    } else {
        pthread_detach(t);
    }
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

__attribute__((constructor(101)))
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

// ============ hook 注册（v4.0：运行时 dyld_dynamic_interpose，见 dst_resolve_and_interpose）============
// 不再使用静态 __interpose 段（DYLD_INTERPOSE 宏会在 dyld4 加载期被拒 -> 白屏零日志）。
// 符号替换改在构造函数里经 dyld 官方 API dyld_dynamic_interpose() 运行时应用，
// 不写受保护内存页（arm64e 安全），且 dyld 不支持时软失败（记日志、不崩）。
// 原始指针全部经 dlsym(RTLD_NEXT,...) 解析，fake_* 内只调 orig_*，杜绝递归。
// $NOCANCEL 变体不再需要 extern "C" 声明（dlsym 用字符串名解析）。

// ============ 新增：C-stdio fopen/fclose hook（覆盖 C++ 引擎用 fopen 写 cluster_token.txt 的路径）============
static FILE* g_tok_wfile = NULL;   // 与 POSIX 的 g_tok_wfd(int) 区分，避免类型混淆

static FILE* fake_fopen(const char* path, const char* mode) {
    // 无条件诊断：记录所有 fopen 调用（不限 cluster_token），用于定位游戏真实用哪个 API
    static int g_fopen_diag_count = 0;
    if (g_fopen_diag_count++ < 30)
        LOGD("[DIAG-FOPEN] %s mode=%s", path ? path : "(null)", mode ? mode : "(null)");
    diag_file_op("fopen", path, mode);
    // 动态整包重定向：只读打开 scripts.zip/images.zip 时改走 Documents 副本
    if (!g_open_reent && mode && (mode[0] == 'r') && !strchr(mode, '+')) {
        const char* red = dst_redirect_databundle(path);
        if (red != path) {
            FILE* rf = orig_fopen ? orig_fopen(red, mode) : fopen(red, mode);
            return rf;
        }
    }
    FILE* f = orig_fopen ? orig_fopen(path, mode) : fopen(path, mode);
    if (f && !g_open_reent && path && path_is_cluster_token(path) && mode) {
        // 仅记录写模式（w/a/+），只读不清空
        if (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) {
            g_tok_wfile = f;
            strncpy(g_tok_wpath, path, sizeof(g_tok_wpath) - 1);
            g_tok_wpath[sizeof(g_tok_wpath) - 1] = '\0';
            if (g_token_inject_log++ < 8)
                LOGD("cluster_token.txt fopen(w) recorded (via C-stdio)");
        }
    }
    return f;
}

static int fake_fclose(FILE* f) {
    if (f && f == g_tok_wfile) {
        g_tok_wfile = NULL;
        rewrite_cluster_token_on_close();   // 复用：基于 g_tok_wpath 用 orig_open 重写令牌
    }
    return orig_fclose ? orig_fclose(f) : fclose(f);
}

// ============ EOS/Klei auth forgery (copy KAlert's gethostbyname/getaddrinfo redirect) ============
// Online cluster stalls because the game's Klei/EOS auth can't reach Klei in mainland CN.
// KAlert's working trick: hook gethostbyname/getaddrinfo and point the 3 Klei account/auth
// domains at our self-hosted server (which emulates Klei's token responses). We copy ONLY
// this; we do NOT copy KAlert's VFS Lua injection, its broad all-klei-domain redirect, or
// its UDP relay (our own UDP relay above stays).
#define AUTH_REDIR_IP "47.122.115.99"

static int auth_host_matches(const char* name) {
    if (!name) return 0;
    // Only the 3 Klei account/auth domains (NOT lobby-v2, NOT cdn/metrics/translation).
    static const char* const hosts[] = {
        "galette.klei.com", "login.kleientertainment.com", "accounts.klei.com", "lobby-v2.klei.com", "lobby-v2-cdn.klei.com", "cdn-galette.klei.com", NULL
    };
    size_t n = strlen(name);
    for (int i = 0; hosts[i]; i++) {
        size_t h = strlen(hosts[i]);
        if (n >= h && strcasecmp(name + n - h, hosts[i]) == 0) return 1;
    }
    return 0;
}

static struct hostent* fake_gethostbyname(const char* name) {
    if (orig_gethostbyname && dst_is_authed() && auth_host_matches(name)) {
        LOGD("[AUTH-FORGE] gethostbyname(%s) -> %s", name ? name : "(null)", AUTH_REDIR_IP);
        static struct in_addr s_addr;
        static char* s_addrlist[2];
        static struct hostent s_he;
        memset(&s_he, 0, sizeof(s_he));
        s_addr.s_addr = inet_addr(AUTH_REDIR_IP);
        s_addrlist[0] = (char*)&s_addr;
        s_addrlist[1] = NULL;
        s_he.h_name = (char*)name;
        s_he.h_addrtype = AF_INET;
        s_he.h_length = 4;
        s_he.h_addr_list = s_addrlist;
        return &s_he;
    }
    return orig_gethostbyname ? orig_gethostbyname(name) : NULL;
}

static int fake_getaddrinfo(const char* node, const char* service,
                            const struct addrinfo* hints, struct addrinfo** res) {
    if (orig_getaddrinfo && dst_is_authed() && node && auth_host_matches(node)) {
        LOGD("[AUTH-FORGE] getaddrinfo(%s) -> %s", node, AUTH_REDIR_IP);
        // Delegate to the real resolver with our IP as the node.
        return orig_getaddrinfo(AUTH_REDIR_IP, service, hints, res);
    }
    return orig_getaddrinfo ? orig_getaddrinfo(node, service, hints, res) : EAI_NONAME;
}

// ============ 新增：Foundation 写方法 swizzle（覆盖游戏走 NSData/NSString/NSFileManager 写 cluster_token.txt 的路径）============
// 编译单元为 .mm + -fobjc-arc，此处可直接写 Objective-C。
static NSString* gen_klei_token_ns(void) {
    char buf[128];
    gen_klei_token(buf, sizeof(buf));
    return [NSString stringWithUTF8String:buf];
}

static BOOL swiz_NSData_wtf(id self, SEL _cmd, NSString* path, BOOL atomically) {
    if (path && [path rangeOfString:@"cluster_token.txt"].location != NSNotFound) {
        if (g_token_inject_log++ < 8)
            LOGD("cluster_token.txt write via NSData -> injecting token");
        NSData* tok = [gen_klei_token_ns() dataUsingEncoding:NSUTF8StringEncoding];
        if (!tok) tok = [NSData data];
        return orig_NSData_wtf(tok, _cmd, path, atomically);
    }
    return orig_NSData_wtf(self, _cmd, path, atomically);
}

static BOOL swiz_NSString_wtf(id self, SEL _cmd, NSString* path, BOOL atomically,
                              NSStringEncoding enc, NSError** err) {
    if (path && [path rangeOfString:@"cluster_token.txt"].location != NSNotFound) {
        if (g_token_inject_log++ < 8)
            LOGD("cluster_token.txt write via NSString -> injecting token");
        NSString* tok = gen_klei_token_ns();
        return orig_NSString_wtf(tok, _cmd, path, atomically, enc, err);
    }
    return orig_NSString_wtf(self, _cmd, path, atomically, enc, err);
}

static BOOL swiz_NSMgr_createFile(id self, SEL _cmd, NSString* path, NSData* data, NSDictionary* attr) {
    if (path && [path rangeOfString:@"cluster_token.txt"].location != NSNotFound) {
        if (g_token_inject_log++ < 8)
            LOGD("cluster_token.txt write via NSFileManager -> injecting token");
        NSData* tok = [gen_klei_token_ns() dataUsingEncoding:NSUTF8StringEncoding];
        if (!tok) tok = [NSData data];
        return orig_NSMgr_createFile(self, _cmd, path, tok, attr);
    }
    return orig_NSMgr_createFile(self, _cmd, path, data, attr);
}

static void dst_swizzle_foundation(void) {
    @try {
        Method m; Class c;
        c = [NSData class];
        m = class_getInstanceMethod(c, @selector(writeToFile:atomically:));
        if (m) {
            orig_NSData_wtf = (BOOL(*)(id,SEL,NSString*,BOOL))method_getImplementation(m);
            method_setImplementation(m, (IMP)swiz_NSData_wtf);
            LOGD("swizzled NSData writeToFile:atomically:");
        }
        c = [NSString class];
        m = class_getInstanceMethod(c, @selector(writeToFile:atomically:encoding:error:));
        if (m) {
            orig_NSString_wtf = (BOOL(*)(id,SEL,NSString*,BOOL,NSStringEncoding,NSError**))method_getImplementation(m);
            method_setImplementation(m, (IMP)swiz_NSString_wtf);
            LOGD("swizzled NSString writeToFile:encoding:error:");
        }
        c = [NSFileManager class];
        m = class_getInstanceMethod(c, @selector(createFileAtPath:contents:attributes:));
        if (m) {
            orig_NSMgr_createFile = (BOOL(*)(id,SEL,NSString*,NSData*,NSDictionary*))method_getImplementation(m);
            method_setImplementation(m, (IMP)swiz_NSMgr_createFile);
            LOGD("swizzled NSFileManager createFileAtPath:contents:attributes:");
        }
    } @catch (NSException* e) {
        LOGE("Foundation swizzle exception: %s", [[e description] UTF8String]);
    }
}

__attribute__((constructor(3)))
static void dst_foundation_swizzle_ctor(void) {
    dst_ensure_log();
    LOGD("=== applying Foundation swizzle (cluster_token injection) ===");
    dst_swizzle_foundation();
}

// ============ [DYNAMIC ASSET LOAD] 游戏运行时（后台线程）从私服拉取 scripts.zip + images.zip ============
// 与参考包同款思路（KAlert：init 只做本地重建，网络动作绝不卡启动）：
//  - constructor 只 detach 后台线程（v10 修复：不再在 main 前同步下载，白屏/看门狗杀机彻底消除）；
//  - 后台线程拉极小 version.txt 与本地 ready.flag 版本比对，仅版本变化才下载整包；
//  - 用捕获的原始 orig_connect（不经 fishhook 重定向）直连服务器 :80/:3000；
//  - scripts.zip 与 images.zip 都下载并通过 PK 魔数 + Content-Length 校验后才一起落地，
//    并写 ready.flag（重定向唯一开关）——两包永远配对，杜绝版本错配崩溃；
//  - 任一步失败保留旧配对（或内置原版包），下次启动重试；任何异常均被 @try 吞掉。
#include <time.h>
#define DST_ASSET_HOST    "47.122.115.99"
#define DST_ASSET_PORT    3000
#define DST_ASSET_BASE    "/dst/"
#define DST_ASSET_CONN_TO 120  // 单 recv 超时（秒）；游戏启动期解压 databundle 抢资源，移动网络慢，放宽避免误判
#define DST_ASSET_BUDGET  1800 // 单整包下载总预算（秒）——后台线程无启动看门狗风险，充分放宽

static connect_t dst_asset_connect(void) {
    if (orig_connect) return orig_connect;
    return (connect_t)dlsym(RTLD_NEXT, "connect");
}

// 在 [buf,len) 中查找 "\r\n\r\n"，返回其起始偏移；找不到返回 -1
static int dst_find_hdrend(const char* buf, int len) {
    for (int i = 0; i + 3 < len; i++) {
        if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') return i;
    }
    return -1;
}

// HTTP/1.1 GET relpath（如 "scripts.zip"）写入 out_path。
// ---- 实时下载进度上报（供 Lua 主菜单画进度条）----
// 后台 worker 下载整包时把 scripts/images 的「已下载/总长」写入
// Documents/dst_assets_cache/progress.txt（两行），Lua 每帧读取即可显示进度条。
static long g_prog_cur[2]   = {0, 0};   // [0]=scripts [1]=images
static long g_prog_total[2] = {0, 0};
static void dst_write_progress_file(void) {
    @autoreleasepool {
        NSString* p = [[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                          stringByAppendingPathComponent:@"dst_assets_cache"]
                         stringByAppendingPathComponent:@"progress.txt"];
        FILE* f = fopen([p UTF8String], "w");
        if (f) {
            fprintf(f, "scripts %ld %ld\n", g_prog_cur[0], g_prog_total[0]);
            fprintf(f, "images %ld %ld\n",  g_prog_cur[1], g_prog_total[1]);
            fclose(f);
        }
    }
}

// resume_from>0 时发送 Range 请求从上次进度继续；支持连接错误/超时的单次续传重试
// （每次重试仍从上次已落盘进度继续，不重下）。成功返回 0，失败返回 -1。
// 注意：本函数不删除 out_path；续传语义由调用方（worker）保留临时文件实现。
static int dst_http_get_file_port(const char* relpath, const char* out_path,
                                  int port, long resume_from, int pidx) {
    connect_t c = dst_asset_connect();
    if (c == NULL) return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct timeval tv;
    tv.tv_sec = DST_ASSET_CONN_TO; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(DST_ASSET_HOST);
    if (c(sock, (const struct sockaddr*)&sa, sizeof(sa)) != 0) { close(sock); return -1; }
    char req[512];
    int rl;
    if (resume_from > 0) {
        rl = snprintf(req, sizeof(req),
            "GET %s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: DSTIOS/1.0\r\nAccept: */*\r\n"
            "Range: bytes=%ld-\r\nConnection: close\r\n\r\n",
            DST_ASSET_BASE, relpath, DST_ASSET_HOST, resume_from);
    } else {
        rl = snprintf(req, sizeof(req),
            "GET %s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: DSTIOS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            DST_ASSET_BASE, relpath, DST_ASSET_HOST);
    }
    if (send(sock, req, (size_t)rl, 0) <= 0) { close(sock); return -1; }

    char buf[65536];
    int total = 0;
    int hdr_end = -1;
    while (total < (int)sizeof(buf)) {                 // 收头（含可能的一部分正文）
        int n = recv(sock, buf + total, sizeof(buf) - total, 0);
        if (n <= 0) break;
        total += n;
        hdr_end = dst_find_hdrend(buf, total);
        if (hdr_end >= 0) break;
    }
    if (hdr_end < 0) { close(sock); return -1; }
    buf[hdr_end] = '\0';
    // 206（续传）/ 200（整包）均视为成功；416（range 越界）视为已完整
    int code_ok = (strstr(buf, " 200 ") != NULL || strstr(buf, "200 OK") != NULL ||
                   strstr(buf, " 206 ") != NULL || strstr(buf, "206 ") != NULL ||
                   strstr(buf, " 416 ") != NULL);
    if (!code_ok) { close(sock); return -1; }

    // 解析 Content-Length：续传(206)时它只表示本 range 段长度，需 + 已下载偏移
    long seg_len = -1;
    char* cl = strcasestr(buf, "content-length:");
    if (cl) seg_len = (long)atoi(cl + 15);

    FILE* out = fopen(out_path, resume_from > 0 ? "ab" : "wb");
    if (!out) { close(sock); return -1; }
    int body_start = hdr_end + 4;
    long body_total = resume_from;   // 已落盘偏移（续传起点）
    if (body_start < total) {
        long wb = (long)(total - body_start);
        fwrite(buf + body_start, 1, (size_t)wb, out);
        body_total += wb;
    }

    time_t deadline = time(NULL) + DST_ASSET_BUDGET;
    long want = (seg_len >= 0) ? (resume_from + seg_len) : -1;  // 期望收齐到的字节数
    long last_rep = body_total;
    while (want < 0 || body_total < want) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;            // 连接错误或超时 -> 跳出；调用方从上次进度续传
        fwrite(buf, 1, (size_t)n, out);
        body_total += n;
        if (pidx >= 0) {              // 上报进度（每 ~512KB 写一次，避免频繁 IO）
            g_prog_cur[pidx] = body_total;
            if (body_total - last_rep >= 524288) { last_rep = body_total; dst_write_progress_file(); }
        }
        if (time(NULL) > deadline) { fclose(out); close(sock); return -1; }
    }
    if (pidx >= 0) { g_prog_cur[pidx] = body_total; dst_write_progress_file(); }
    fflush(out);
    fclose(out);
    close(sock);
    // 未能收齐（连接断/超时）：返回 -1，由 worker 保留文件并续传；不在此丢弃
    if (want >= 0 && body_total < want) {
        LOGD("prefetch: %s 本轮收 %ld/%ld（断点续传，保留）", relpath, body_total, want);
        return -1;
    }
    return 0;
}

// 依次尝试多个端口（静态资源在 :80 nginx 托管，优先 :80），任一成功即返回 0
static int dst_http_get_file(const char* relpath, const char* out_path, int pidx) {
    int ports[] = { 80, 3000 };
    for (int i = 0; i < 2; i++) {
        if (dst_http_get_file_port(relpath, out_path, ports[i], 0, pidx) == 0) return 0;
    }
    return -1;
}

// 探测整包总字节数：发 Range: bytes=0-0，从 206 响应的 "Content-Range: bytes 0-0/<total>"
// 解析总长。失败返回 -1。
static long dst_http_content_length(const char* relpath) {
    connect_t c = dst_asset_connect();
    if (c == NULL) return -1;
    int ports[] = { 80, 3000 };
    for (int pi = 0; pi < 2; pi++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv; tv.tv_sec = DST_ASSET_CONN_TO; tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET; sa.sin_port = htons(ports[pi]);
        sa.sin_addr.s_addr = inet_addr(DST_ASSET_HOST);
        if (c(sock, (const struct sockaddr*)&sa, sizeof(sa)) != 0) { close(sock); continue; }
        char req[512];
        int rl = snprintf(req, sizeof(req),
            "GET %s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: DSTIOS/1.0\r\nAccept: */*\r\n"
            "Range: bytes=0-0\r\nConnection: close\r\n\r\n",
            DST_ASSET_BASE, relpath, DST_ASSET_HOST);
        if (send(sock, req, (size_t)rl, 0) <= 0) { close(sock); continue; }
        char buf[2048]; int total = 0; int hdr_end = -1;
        while (total < (int)sizeof(buf)) {
            int n = recv(sock, buf + total, sizeof(buf) - total, 0);
            if (n <= 0) break;
            total += n; hdr_end = dst_find_hdrend(buf, total);
            if (hdr_end >= 0) break;
        }
        close(sock);
        if (hdr_end < 0) continue;
        buf[hdr_end] = '\0';
        char* cr = strcasestr(buf, "content-range:");
        if (cr) {
            // 形如 "bytes 0-0/52275030"
            char* slash = strrchr(cr, '/');
            if (slash) { long tot = (long)atol(slash + 1); if (tot > 0) return tot; }
        }
        // 没有 content-range（服务器不支持 range），退而从普通 content-length 读（不续传仍可用）
        char* cl = strcasestr(buf, "content-length:");
        if (cl) { long tot = (long)atoi(cl + 15); if (tot > 0) return tot; }
    }
    return -1;
}

// 断点续传版：循环重试 dst_http_get_file_port，每次从上次进度继续；
// 网络抖动导致的截断不再整包丢弃，最终收齐才返回 0。max_tries 控制总轮次。
// 返回 0=收齐并校验完整；-1=超过重试上限仍未收齐。
static int dst_http_get_file_resume(const char* relpath, const char* out_path,
                                    long content_total, int max_tries, int pidx) {
    if (pidx >= 0) { g_prog_total[pidx] = content_total; g_prog_cur[pidx] = 0; }
    for (int attempt = 0; attempt < max_tries; attempt++) {
        long have = 0;
        FILE* chk = fopen(out_path, "rb");
        if (chk) { fseek(chk, 0, SEEK_END); have = ftell(chk); fclose(chk); }
        if (pidx >= 0) { g_prog_cur[pidx] = have; dst_write_progress_file(); }
        if (content_total > 0 && have >= content_total) return 0;  // 已完整
        int rc = -1;
        int ports[] = { 80, 3000 };
        for (int i = 0; i < 2; i++) {
            if (dst_http_get_file_port(relpath, out_path, ports[i], have, pidx) == 0) { rc = 0; break; }
        }
        if (rc == 0) {
            long after = 0; FILE* c2 = fopen(out_path, "rb");
            if (c2) { fseek(c2, 0, SEEK_END); after = ftell(c2); fclose(c2); }
            if (pidx >= 0) { g_prog_cur[pidx] = after; dst_write_progress_file(); }
            if (content_total <= 0 || after >= content_total) return 0;
        }
        LOGD("prefetch: %s 续传轮次 %d 未完成，稍后重试", relpath, attempt + 1);
        usleep(800000);  // 0.8s 退避，避免空转；后台线程不阻塞游戏
    }
    return -1;
}

// ============ v10 动态资产：后台线程下载（游戏运行时，绝不阻塞启动） ============
// 参考包时机模型：KAlert init 只做「本地」重建（enhanced zip rebuilt at init /
// up-to-date skip rebuild），网络动作不卡启动。我们等价实现：
//   constructor(100) 只 detach 一个后台线程后立即返回（main 不被阻塞，不白屏）；
//   线程内比对服务器版本 -> 下载 scripts.zip + images.zip 两个整包到 .dl 临时文件 ->
//   都通过 PK 魔数 + Content-Length 完整性校验后一起落地 + 写 ready.flag。
// ready.flag 是重定向的唯一开关（见 dst_redirect_databundle）：首启/下载中/失败时
// 游戏用内置原版包（完全原版体验）；两个包永远版本配对落地，杜绝半新半旧崩溃。

static int dst_read_ready_version(char* buf, size_t buflen) {
    buf[0] = 0;
    @autoreleasepool {
        NSString* p = [[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                        stringByAppendingPathComponent:@"dst_assets_cache"]
                       stringByAppendingPathComponent:@"ready.flag"];
        FILE* f = fopen([p UTF8String], "r");
        if (!f) return 0;
        if (fgets(buf, (int)buflen, f) == NULL) { fclose(f); return 0; }
        fclose(f);
        size_t L = strlen(buf);
        while (L > 0 && (buf[L-1]=='\n' || buf[L-1]=='\r' || buf[L-1]==' ')) buf[--L] = 0;
        return 1;
    }
}

static int dst_zip_ok(const char* path) {
    unsigned char sig[4] = {0};
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    int ok = (fread(sig, 1, 4, f) == 4);
    fclose(f);
    return ok && sig[0]=='P' && sig[1]=='K' && sig[2]==0x03 && sig[3]==0x04;
}

static void* dst_prefetch_worker(void* arg) {
    (void)arg;
    @try {
        LOGD("=== dst asset worker start (background, game keeps running) v10 ===");
        NSFileManager* fm = [NSFileManager defaultManager];
        NSString* cacheDir = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                              stringByAppendingPathComponent:@"dst_assets_cache"];
        [fm createDirectoryAtPath:cacheDir withIntermediateDirectories:YES attributes:nil error:nil];

        // 等主菜单可见后再开始下载：确保进度条在用户眼前推进，
        // 而不是在启动加载界面后台静默完成（那样用户永远看不到读条）。
        // 超时兜底 180s：即使菜单信号缺失也照常下载，避免永不更新。
        {
            NSString* syncFlag = [cacheDir stringByAppendingPathComponent:@"ios_asset_sync.flag"];
            int _waited = 0;
            while (_waited < 180 && ![fm fileExistsAtPath:syncFlag]) {
                sleep(1); _waited++;
            }
            LOGD("asset worker: menu-sync flag waited %ds (download starts now)", _waited);
        }

        // 1) 拉服务器版本（直连 IP，不经 Klei 域名，与授权状态无关）
        char server_v[128]; server_v[0] = 0;
        NSString* vtmp = [cacheDir stringByAppendingPathComponent:@"version.tmp"];
        if (dst_http_get_file("version.txt", [vtmp UTF8String], -1) == 0) {
            FILE* f = fopen([vtmp UTF8String], "r");
            if (f) {
                if (fgets(server_v, sizeof(server_v), f)) {
                    size_t L = strlen(server_v);
                    while (L > 0 && (server_v[L-1]=='\n' || server_v[L-1]=='\r')) server_v[--L] = 0;
                }
                fclose(f);
            }
        }
        [fm removeItemAtPath:vtmp error:nil];
        if (server_v[0] == 0) {
            LOGD("asset worker: version.txt 拉取失败（离线？），保留现状退出");
            return NULL;
        }

        // 2) ready.flag 内容 = 已配对落地的版本；一致则无事可做
        char ready_v[128]; ready_v[0] = 0;
        dst_read_ready_version(ready_v, sizeof(ready_v));
        if (strcmp(ready_v, server_v) == 0) {
            LOGD("asset worker: 已是最新配对版本 %s -> skip", server_v);
            return NULL;
        }
        LOGD("asset worker: ready='%s' server='%s' -> 下载配对整包(scripts+images)", ready_v, server_v);

        // 3) 两个整包用【断点续传】下载到版本化临时文件（__<ver>.dl），
        //    网络抖动只暂停续传、不整包丢弃（保留文件下启继续）；都收齐+魔数校验才落地。
        //    版本化文件名避免跨版本残留 .dl 污染新版本配对。
        //    pidx=0/1 让底层下载循环实时上报进度到 progress.txt（Lua 画进度条用）。
        NSArray* names = @[@"scripts.zip", @"images.zip"];
        int ok_all = 1;
        for (NSUInteger idx = 0; idx < names.count; idx++) {
            NSString* name = names[idx];
            NSString* tmp = [cacheDir stringByAppendingPathComponent:
                [NSString stringWithFormat:@"__%s.%@.dl", server_v, name]];
            // 先探测整包总长（用于续传收齐判定）
            long ctotal = dst_http_content_length([name UTF8String]);
            LOGD("asset worker: %s 探测总长=%ld", [name UTF8String], ctotal);
            if (dst_http_get_file_resume([name UTF8String], [tmp UTF8String], ctotal, 12, (int)idx) != 0 ||
                !dst_zip_ok([tmp UTF8String])) {
                LOGE("asset worker: %s 续传超限/校验失败 -> 保留 .dl 下启再试", [name UTF8String]);
                ok_all = 0;
                break;
            }
            LOGD("asset worker: %s 续传收齐+魔数校验通过", [name UTF8String]);
        }
        if (!ok_all) {
            // 保留已下载的 .dl（下启续传），旧 ready.flag 不动：仍可用旧配对，下次启动重试
            return NULL;
        }

        // 4) 全部成功：一起落地 + 写 ready.flag（此后重定向开启，下次启动生效）
        for (NSString* name in names) {
            NSString* tmp  = [cacheDir stringByAppendingPathComponent:
                [NSString stringWithFormat:@"__%s.%@.dl", server_v, name]];
            NSString* dest = [cacheDir stringByAppendingPathComponent:name];
            [fm removeItemAtPath:dest error:nil];
            if (![fm moveItemAtPath:tmp toPath:dest error:nil]) {
                LOGE("asset worker: %s 落地失败！", [name UTF8String]);
            } else {
                LOGD("asset worker: %s 落地 -> cache（%lld bytes）", [name UTF8String],
                     (long long)[[fm attributesOfItemAtPath:dest error:nil] fileSize]);
            }
        }
        NSString* flag = [cacheDir stringByAppendingPathComponent:@"ready.flag"];
        FILE* f = fopen([flag UTF8String], "w");
        if (f) { fputs(server_v, f); fputc('\n', f); fclose(f); }
        [fm removeItemAtPath:[cacheDir stringByAppendingPathComponent:@"progress.txt"] error:nil];
        g_ready_cache = -1;   // 立即失效重定向开关缓存
        LOGD("asset worker: 配对完成 ready.flag=%s（下次启动游戏生效）", server_v);
    } @catch (NSException* e) {
        LOGE("asset worker 异常: %s", [[e description] UTF8String]);
    }
    return NULL;
}

__attribute__((constructor(100)))
static void dst_prefetch_assets(void) {
    dst_ensure_log();
    LOGD("=== dst_prefetch_assets v11: spawn background worker (no startup block) ===");
    pthread_t t;
    if (pthread_create(&t, NULL, dst_prefetch_worker, NULL) == 0) {
        pthread_detach(t);
    } else {
        LOGE("prefetch: pthread_create 失败（跳过动态资产，游戏用内置包）");
    }
}
