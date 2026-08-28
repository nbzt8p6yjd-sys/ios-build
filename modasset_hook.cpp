// libMODASSET.dylib —— iOS 模组资源适配专用 dylib（独立于 libIOSVISION.dylib，互不影响）
//
// 【已查清的事实】
// 1. 安卓 libDontStarve.so 与 iOS dontstarvetogether 主二进制的字符串完全一致：
//      DEV=databundles/klump.zip / shaders / fonts / anim_dynamic / bigportraits / images / scripts.zip
//      "Mounting file system databundles/scripts.zip %s."
//    即两端 C++ 的挂载逻辑相同，iOS 也确实挂载了 scripts.zip（日志为 successful）。
// 2. 但安卓 C++ 能取到模组资源而 iOS 不能：
//      安卓: MiniMapComponent::AddAtlas( scripts/mods/建家党狂喜/images/.../zx_well.xml )   <- 成功
//      iOS : MiniMapComponent 相关日志 0 条，C++ 拿不到无效句柄 ->
//            MapLayerRenderData.cpp(104/107/110/996) 断言崩溃
// 3. 因此差异在"挂载之后按路径取文件"这一步，最可能是 iOS 的 zip 解析器对
//    zip 内中文文件名（模组目录全是中文）的解码与安卓不同（=UTF-8 flag 处理差异）。
//
// 【本 dylib 的做法】
// 在文件打开层兜底：路径命中 "scripts/mods/" 且物理上不存在时，
// 由本 dylib 自己按原始字节解析 data/databundles/scripts.zip 的 central directory
// （不做任何编码转换，直接字节比较，天然规避中文/UTF-8 问题），
// 把该条目解压到缓存目录，再返回缓存路径。
// 模组文件原地保留在 zip 内，不搬运、不改写。
//
// 编译：clang++ -arch arm64 -target arm64-apple-ios12.0 -isysroot $SDK \
//        -dynamiclib -fobjc-arc -std=c++17 -I. -framework Foundation -lz \
//        -install_name @rpath/libMODASSET.dylib \
//        modasset_hook.cpp fishhook.c -o libMODASSET.dylib

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include "fishhook.h"

// ---------------- 日志 ----------------
static FILE *g_log = NULL;
static void ma_log(const char *fmt, ...) {
    if (!g_log) {
        @autoreleasepool {
            NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                      withIntermediateDirectories:YES
                                                       attributes:nil
                                                            error:nil];
            g_log = fopen([[dir stringByAppendingPathComponent:@"modasset_hook.log"] UTF8String], "a");
        }
    }
    if (!g_log) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    fputc('\n', g_log);
    fflush(g_log);
    va_end(ap);
}

// ---------------- zip 索引 ----------------
typedef struct { char *name; uint64_t lho; uint32_t csize; uint32_t usize; uint16_t method; } ma_ent;
static ma_ent *g_ents = NULL;
static int g_n = 0, g_cap = 0, g_ready = 0;   // g_ready: 0未试 1就绪 -1失败
static FILE *g_zf = NULL;

static void ma_add(const char *n, uint64_t lho, uint32_t cs, uint32_t us, uint16_t m) {
    if (g_n >= g_cap) {
        g_cap = g_cap ? g_cap * 2 : 8192;
        g_ents = (ma_ent *)realloc(g_ents, (size_t)g_cap * sizeof(ma_ent));
        if (!g_ents) { g_cap = 0; g_n = 0; return; }
    }
    ma_ent *e = &g_ents[g_n++];
    e->name = strdup(n); e->lho = lho; e->csize = cs; e->usize = us; e->method = m;
}

static int ma_eocd(FILE *f, uint64_t *cd_off, uint32_t *cd_size, uint32_t *nent) {
    if (fseek(f, 0, SEEK_END)) return -1;
    long sz = ftell(f); if (sz < 22) return -1;
    long back = sz < 70000 ? sz : 70000;
    if (fseek(f, sz - back, SEEK_SET)) return -1;
    unsigned char *buf = (unsigned char *)malloc((size_t)back);
    if (!buf) return -1;
    if (fread(buf, 1, (size_t)back, f) != (size_t)back) { free(buf); return -1; }
    int rc = -1;
    for (long i = back - 22; i >= 0; i--) {
        if (buf[i] == 0x50 && buf[i+1] == 0x4b && buf[i+2] == 0x05 && buf[i+3] == 0x06) {
            uint16_t tn; uint32_t ts, to;
            memcpy(&tn, buf + i + 10, 2);
            memcpy(&ts, buf + i + 12, 4);
            memcpy(&to, buf + i + 16, 4);
            *cd_off = (uint64_t)to; *cd_size = ts; *nent = tn; rc = 0; break;
        }
    }
    free(buf); return rc;
}

// 索引按“参数给定的相对名字”建立（如 scripts/mods/…），比较时直接 strcmp 原始字节
static int ma_index() {
    if (g_ready) return g_ready == 1 ? 0 : -1;
    g_ready = -1;
    @autoreleasepool {
        NSString *zp = [[[NSBundle mainBundle] bundlePath]
                        stringByAppendingPathComponent:@"data/databundles/scripts.zip"];
        FILE *f = fopen([zp fileSystemRepresentation], "rb");
        if (!f) { ma_log("[MODASSET] zip open failed: %s", [zp UTF8String]); return -1; }
        uint64_t cd_off = 0; uint32_t cd_size = 0, nent = 0;
        if (ma_eocd(f, &cd_off, &cd_size, &nent)) { ma_log("[MODASSET] eocd not found"); fclose(f); return -1; }
        if (fseek(f, (long)cd_off, SEEK_SET)) { fclose(f); return -1; }
        unsigned char *cd = (unsigned char *)malloc((size_t)cd_size);
        if (!cd) { fclose(f); return -1; }
        if (fread(cd, 1, (size_t)cd_size, f) != (size_t)cd_size) { free(cd); fclose(f); return -1; }
        uint32_t off = 0;
        for (uint32_t i = 0; i < nent && off + 46 <= cd_size; i++) {
            if (cd[off] != 0x50 || cd[off+1] != 0x4b || cd[off+2] != 0x01 || cd[off+3] != 0x02) break;
            uint16_t method, nlen, elen, clen; uint32_t cs, us, lho;
            memcpy(&method, cd + off + 10, 2);
            memcpy(&cs, cd + off + 20, 4);
            memcpy(&us, cd + off + 24, 4);
            memcpy(&nlen, cd + off + 28, 2);
            memcpy(&elen, cd + off + 30, 2);
            memcpy(&clen, cd + off + 32, 2);
            memcpy(&lho, cd + off + 42, 4);
            char nm[1024];
            uint32_t cp = nlen < 1023 ? nlen : 1023;
            memcpy(nm, cd + off + 46, cp); nm[cp] = 0;
            ma_add(nm, lho, cs, us, method);
            off += 46 + nlen + elen + clen;
        }
        free(cd);
        g_zf = f; g_ready = 1;
        ma_log("[MODASSET] indexed %d entries", g_n);
        return 0;
    }
}

static ma_ent *ma_find(const char *name) {
    for (int i = 0; i < g_n; i++) if (strcmp(g_ents[i].name, name) == 0) return &g_ents[i];
    return NULL;
}

static NSString *ma_cache_dir() {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    NSString *base = ([dirs count] ? [dirs objectAtIndex:0]
                                   : [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]);
    NSString *d = [base stringByAppendingPathComponent:@"dst_modcache"];
    [[NSFileManager defaultManager] createDirectoryAtPath:d
                            withIntermediateDirectories:YES attributes:nil error:nil];
    return d;
}

static int ma_extract(ma_ent *e, const char *dst) {
    if (!g_zf || !e) return -1;
    if (fseek(g_zf, (long)e->lho, SEEK_SET)) return -1;
    unsigned char lh[30];
    if (fread(lh, 1, 30, g_zf) != 30) return -1;
    if (lh[0] != 0x50 || lh[1] != 0x4b || lh[2] != 0x03 || lh[3] != 0x04) return -1;
    uint16_t nlen, elen;
    memcpy(&nlen, lh + 26, 2); memcpy(&elen, lh + 28, 2);
    if (fseek(g_zf, (long)(e->lho + 30 + nlen + elen), SEEK_SET)) return -1;

    @autoreleasepool {
        NSString *s = [NSString stringWithUTF8String:dst];
        [[NSFileManager defaultManager] createDirectoryAtPath:[s stringByDeletingLastPathComponent]
                              withIntermediateDirectories:YES attributes:nil error:nil];
    }
    FILE *out = fopen(dst, "wb");
    if (!out) return -1;
    int ok = 0;
    if (e->method == 0) {
        unsigned char b[65536]; uint32_t rem = e->csize;
        while (rem) {
            size_t n = rem < sizeof(b) ? rem : sizeof(b);
            if (fread(b, 1, n, g_zf) != n) { ok = -1; break; }
            fwrite(b, 1, n, out); rem -= (uint32_t)n;
        }
    } else {
        unsigned char ib[65536], ob[131072];
        z_stream zs; memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) { fclose(out); return -1; }
        uint32_t rem = e->csize; int rc = Z_OK;
        while (rem > 0) {
            size_t n = rem < sizeof(ib) ? rem : sizeof(ib);
            if (fread(ib, 1, n, g_zf) != n) { ok = -1; break; }
            rem -= (uint32_t)n;
            zs.next_in = ib; zs.avail_in = (uInt)n;
            while (zs.avail_in > 0) {
                zs.next_out = ob; zs.avail_out = sizeof(ob);
                rc = inflate(&zs, Z_NO_FLUSH);
                size_t got = sizeof(ob) - zs.avail_out;
                if (got) fwrite(ob, 1, got, out);
                if (rc != Z_OK && rc != Z_STREAM_END) break;
            }
            if (rc != Z_OK && rc != Z_STREAM_END) { ok = -1; break; }
        }
        inflateEnd(&zs);
    }
    fclose(out);
    return ok;
}

// 重定向：命中 scripts/mods/ 且物理不存在 -> 从 zip 解出
static char g_buf[2048];
static const char *ma_redirect(const char *path) {
    if (!path || !*path) return path;
    const char *hit = strstr(path, "scripts/mods/");
    if (!hit) return path;
    if (access(path, F_OK) == 0) return path;          // 物理存在，不干预
    if (ma_index() != 0) return path;
    ma_ent *e = ma_find(hit);
    if (!e) { ma_log("[MODASSET] not in zip: %s", hit); return path; }
    @autoreleasepool {
        NSString *c = [ma_cache_dir() stringByAppendingPathComponent:[NSString stringWithUTF8String:hit]];
        if (![[NSFileManager defaultManager] fileExistsAtPath:c]) {
            if (ma_extract(e, [c fileSystemRepresentation]) != 0) {
                ma_log("[MODASSET] extract FAILED: %s", hit);
                return path;
            }
        }
        strncpy(g_buf, [c fileSystemRepresentation], 2047);
    }
    g_buf[2047] = 0;
    ma_log("[MODASSET] redirect %s -> %s", hit, g_buf);
    return g_buf;
}

// ---------------- hooks ----------------
typedef int (*open_t)(const char *, int, ...);
typedef int (*openat_t)(int, const char *, int, ...);
typedef FILE *(*fopen_t)(const char *, const char *);
typedef int (*access_t)(const char *, int);
typedef int (*stat_t)(const char *, struct stat *);

static open_t   r_open = NULL,  r_open_nocancel = NULL;
static openat_t r_openat = NULL, r_openat_nocancel = NULL;
static fopen_t  r_fopen = NULL;
static access_t r_access = NULL;
static stat_t   r_stat = NULL;

static __thread int g_reent = 0;   // 防递归

static int ma_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    int ro = ((flags & O_ACCMODE) == O_RDONLY) || ((flags & O_ACCMODE) == O_RDWR);
    if (!g_reent && ro && path) {
        g_reent = 1;
        const char *red = ma_redirect(path);
        g_reent = 0;
        if (red != path) return r_open ? r_open(red, flags, mode) : open(red, flags, mode);
    }
    return r_open ? r_open(path, flags, mode) : open(path, flags, mode);
}
static int ma_open_nocancel(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    open_t real = r_open_nocancel ? r_open_nocancel : r_open;
    int ro = ((flags & O_ACCMODE) == O_RDONLY) || ((flags & O_ACCMODE) == O_RDWR);
    if (!g_reent && ro && path) {
        g_reent = 1;
        const char *red = ma_redirect(path);
        g_reent = 0;
        if (red != path) return real(red, flags, mode);
    }
    return real ? real(path, flags, mode) : open(path, flags, mode);
}
static int ma_openat(int dfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    int ro = ((flags & O_ACCMODE) == O_RDONLY) || ((flags & O_ACCMODE) == O_RDWR);
    if (!g_reent && ro && path && path[0] != '/') {
        g_reent = 1;
        const char *red = ma_redirect(path);
        g_reent = 0;
        if (red != path) return r_open ? r_open(red, flags, mode) : open(red, flags, mode);
    }
    return r_openat ? r_openat(dfd, path, flags, mode) : openat(dfd, path, flags, mode);
}
static int ma_openat_nocancel(int dfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    openat_t real = r_openat_nocancel ? r_openat_nocancel : r_openat;
    int ro = ((flags & O_ACCMODE) == O_RDONLY) || ((flags & O_ACCMODE) == O_RDWR);
    if (!g_reent && ro && path && path[0] != '/') {
        g_reent = 1;
        const char *red = ma_redirect(path);
        g_reent = 0;
        if (red != path) return r_open ? r_open(red, flags, mode) : open(red, flags, mode);
    }
    return real ? real(dfd, path, flags, mode) : openat(dfd, path, flags, mode);
}
static FILE *ma_fopen(const char *path, const char *mode) {
    if (!g_reent && path && mode && mode[0] == 'r') {
        g_reent = 1;
        const char *red = ma_redirect(path);
        g_reent = 0;
        if (red != path) return r_fopen ? r_fopen(red, mode) : fopen(red, mode);
    }
    return r_fopen ? r_fopen(path, mode) : fopen(path, mode);
}
static int ma_access(const char *path, int am) {
    if (!g_reent && path) {
        g_reent = 1;
        const char *red = ma_redirect(path);
        g_reent = 0;
        if (red != path) return r_access ? r_access(red, am) : access(red, am);
    }
    return r_access ? r_access(path, am) : access(path, am);
}
static int ma_stat(const char *path, struct stat *sb) {
    if (!g_reent && path) {
        g_reent = 1;
        const char *red = ma_redirect(path);
        g_reent = 0;
        if (red != path) return r_stat ? r_stat(red, sb) : stat(red, sb);
    }
    return r_stat ? r_stat(path, sb) : stat(path, sb);
}

__attribute__((constructor))
static void ma_init() {
    ma_log("[MODASSET] libMODASSET loaded (pid %d)", (int)getpid());
    r_open   = (open_t)dlsym(RTLD_NEXT, "open");
    r_open_nocancel = (open_t)dlsym(RTLD_NEXT, "open$NOCANCEL");
    r_openat = (openat_t)dlsym(RTLD_NEXT, "openat");
    r_openat_nocancel = (openat_t)dlsym(RTLD_NEXT, "openat$NOCANCEL");
    r_fopen  = (fopen_t)dlsym(RTLD_NEXT, "fopen");
    r_access = (access_t)dlsym(RTLD_NEXT, "access");
    r_stat   = (stat_t)dlsym(RTLD_NEXT, "stat");

    struct rebinding rb[] = {
        {"open",              (void *)ma_open,              (void **)&r_open},
        {"open$NOCANCEL",     (void *)ma_open_nocancel,     (void **)&r_open_nocancel},
        {"openat",            (void *)ma_openat,            (void **)&r_openat},
        {"openat$NOCANCEL",   (void *)ma_openat_nocancel,   (void **)&r_openat_nocancel},
        {"fopen",             (void *)ma_fopen,             (void **)&r_fopen},
        {"access",            (void *)ma_access,            (void **)&r_access},
        {"stat",              (void *)ma_stat,              (void **)&r_stat},
    };
    rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));
    ma_log("[MODASSET] hooks installed");
}
