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

static int fake_open(const char* path, int flags, ...) {
    mode_t mode = 0; EXTRACT_MODE(flags, mode);
    diag_file_op("open", path, NULL);
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
    na->sin_port = htons(DST_RELAY_PORT);
    return 1;
}

static int fake_connect(int socket, const struct sockaddr* addr, socklen_t len) {
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
    int st = sock_type(socket);
    if (st == SOCK_DGRAM) {
        struct sockaddr_in na;
        int red = rewrite_to_relay(addr, &na);
        dst_diag("connect", socket, addr ? addr->sa_family : 0, addr, red);
        if (red) {
            LOGD("connect(UDP) -> relay");
            return orig_connect(socket, (const struct sockaddr*)&na, sizeof(na));
        }
    } else {
        // TCP connect 之前是静默直通 → 专用服若卡在某个 TCP 连接（注册主服/Steam/令牌交换）
        // 完全不可见。现全量记录目的地址，卡死时「最后一条 connect」即元凶。
        dst_diag("connect", socket, addr ? addr->sa_family : 0, addr, 0);
    }
    return orig_connect(socket, addr, len);
}

static ssize_t fake_sendto(int socket, const void* buffer, size_t length, int flags,
                            const struct sockaddr* dest_addr, socklen_t dest_len) {
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
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
        "galette.klei.com", "login.kleientertainment.com", "accounts.klei.com", NULL
    };
    size_t n = strlen(name);
    for (int i = 0; hosts[i]; i++) {
        size_t h = strlen(hosts[i]);
        if (n >= h && strcasecmp(name + n - h, hosts[i]) == 0) return 1;
    }
    return 0;
}

static struct hostent* fake_gethostbyname(const char* name) {
    if (orig_gethostbyname && auth_host_matches(name)) {
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
    if (orig_getaddrinfo && node && auth_host_matches(node)) {
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

