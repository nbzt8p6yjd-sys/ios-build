/*
 * iOS DST 私有服在线联机注入器 v5.0  (精简版)
 * 删除：后台自动下载/看门狗/诊断日志/recvfrom钩子
 * 保留：皮肤函数/网络hook/文件hook/DNS hook/databundle重定向/cluster_token注入
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
#include <strings.h>
#include <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <UIKit/UIKit.h>
#include <Security/Security.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <pthread.h>
#include "fishhook.h"

#define DST_RELAY_IP   "47.122.115.99"
#define DST_RELAY_PORT 12000
static uint32_t g_relay_ip = 0;

// ---- 授权门控 ----
static int g_authed_cache = -1;
static time_t g_authed_at = 0;
static int dst_is_authed(void) {
    time_t now = time(NULL);
    if (g_authed_cache >= 0 && now - g_authed_at < 2) return g_authed_cache;
    int authed = 0;
    @autoreleasepool {
        NSString* p = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                        stringByAppendingPathComponent:@"ios_auth_token.txt"];
        NSDictionary* att = [[NSFileManager defaultManager] attributesOfItemAtPath:p error:nil];
        if (att && [att fileSize] > 0) authed = 1;
    }
    g_authed_cache = authed; g_authed_at = now; return authed;
}

// ---- relay port ----
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
        if (f) { int v=0; if (fscanf(f,"%d",&v)==1 && v>=12000 && v<=12999) p=v; fclose(f); }
    }
    g_relay_port_cache = p; g_relay_port_at = now; return p;
}

// ---- log ----
static FILE* g_log = NULL;
static void dst_ensure_log() {
    if (g_log) return;
    @autoreleasepool {
        NSString* dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        g_log = fopen([[dir stringByAppendingPathComponent:@"dst_hook.log"] UTF8String], "a");
    }
}
static void dst_log(const char* fmt, ...) {
    dst_ensure_log();
    if (g_log) { va_list ap; va_start(ap,fmt); vfprintf(g_log,fmt,ap); va_end(ap); fprintf(g_log,"\n"); fflush(g_log); }
}
#define LOGD(fmt, ...) do { dst_log(fmt, ##__VA_ARGS__); } while(0)
#define LOGE(fmt, ...) do { dst_log("[ERR] " fmt, ##__VA_ARGS__); } while(0)

static void dst_signal_handler(int sig) {
    const char* name = (sig==SIGILL)?"SIGILL":(sig==SIGSEGV)?"SIGSEGV":(sig==SIGBUS)?"SIGBUS":(sig==SIGABRT)?"SIGABRT":(sig==SIGTRAP)?"SIGTRAP":"SIG?";
    dst_ensure_log(); if (g_log) { fprintf(g_log,"[PANIC] CRASH signal=%s\n",name); fflush(g_log); } _exit(1);
}
static void dst_uncaught_handler(NSException* e) {
    dst_ensure_log(); if (g_log && e) { fprintf(g_log,"[PANIC] NSException: %s\n",[[e description] UTF8String]); fflush(g_log); }
}

__attribute__((constructor(1)))
static void dst_load_marker() {
    if (g_relay_ip == 0) g_relay_ip = inet_addr(DST_RELAY_IP);
    dst_ensure_log();
    LOGD("=== DYLIB v5.0 (simplified: no bg-download, no watchdog, skin kept) ===");
    signal(SIGILL,dst_signal_handler); signal(SIGSEGV,dst_signal_handler);
    signal(SIGBUS,dst_signal_handler); signal(SIGABRT,dst_signal_handler);
    signal(SIGTRAP,dst_signal_handler); NSSetUncaughtExceptionHandler(dst_uncaught_handler);
}

static int is_loopback(uint32_t ip_net) { uint32_t ip=ntohl(ip_net); return (ip&0xFF000000u)==0x7F000000u; }
static int is_relay(uint32_t ip_net, int port) { return ip_net==g_relay_ip && port>=12000 && port<=12999; }

// ---- originals ----
typedef int (*connect_t)(int, const struct sockaddr*, socklen_t);
typedef ssize_t (*sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef int (*bind_t)(int, const struct sockaddr*, socklen_t);
typedef int (*open_t)(const char*, int, ...);
typedef int (*openat_t)(int, const char*, int, ...);
typedef int (*close_t)(int);
typedef int (*rename_t)(const char*, const char*);
typedef int (*renameat_t)(int, const char*, int, const char*);
typedef struct hostent* (*gethostbyname_t)(const char*);
typedef int (*getaddrinfo_t)(const char*, const char*, const struct addrinfo*, struct addrinfo**);
typedef FILE* (*fopen_t)(const char*, const char*);
typedef int (*fclose_t)(FILE*);

static connect_t orig_connect=NULL; static sendto_t orig_sendto=NULL; static bind_t orig_bind=NULL;
static open_t orig_open=NULL;
static close_t orig_close=NULL; static close_t orig_close_nocancel=NULL;
static rename_t orig_rename=NULL; static renameat_t orig_renameat=NULL;
static gethostbyname_t orig_gethostbyname=NULL; static getaddrinfo_t orig_getaddrinfo=NULL;
static fopen_t orig_fopen=NULL; static fclose_t orig_fclose=NULL;
static open_t orig_open_nocancel=NULL;
static openat_t orig_openat=NULL;
static openat_t orig_openat_nocancel=NULL;
static BOOL (*orig_NSData_wtf)(id,SEL,NSString*,BOOL)=NULL;
static BOOL (*orig_NSString_wtf)(id,SEL,NSString*,BOOL,NSStringEncoding,NSError**)=NULL;
static BOOL (*orig_NSMgr_createFile)(id,SEL,NSString*,NSData*,NSDictionary*)=NULL;

static int fake_connect(int,const struct sockaddr*,socklen_t);
static ssize_t fake_sendto(int,const void*,size_t,int,const struct sockaddr*,socklen_t);
static int fake_bind(int,const struct sockaddr*,socklen_t);
static int fake_open(const char*,int,...);
static int fake_open_nocancel(const char*,int,...);
static int fake_openat(int,const char*,int,...);
static int fake_openat_nocancel(int,const char*,int,...);
static int fake_close(int); static int fake_close_nocancel(int);
static int fake_rename(const char*,const char*); static int fake_renameat(int,const char*,int,const char*);
static FILE* fake_fopen(const char*,const char*); static int fake_fclose(FILE*);
static struct hostent* fake_gethostbyname(const char*);
static int fake_getaddrinfo(const char*,const char*,const struct addrinfo*,struct addrinfo**);
typedef int (*x509_verify_cert_fn)(void*);
static x509_verify_cert_fn orig_X509_verify_cert=NULL;
static int fake_X509_verify_cert(void* ctx) { (void)ctx; return 1; }

__attribute__((constructor(2)))
static void dst_resolve_and_interpose() {
    orig_connect=(connect_t)dlsym(RTLD_NEXT,"connect");
    orig_sendto=(sendto_t)dlsym(RTLD_NEXT,"sendto");
    orig_bind=(bind_t)dlsym(RTLD_NEXT,"bind");
    orig_open=(open_t)dlsym(RTLD_NEXT,"open");
    orig_open_nocancel=(open_t)dlsym(RTLD_NEXT,"open$NOCANCEL");
    orig_openat=(openat_t)dlsym(RTLD_NEXT,"openat");
    orig_openat_nocancel=(openat_t)dlsym(RTLD_NEXT,"openat$NOCANCEL");
    orig_close=(close_t)dlsym(RTLD_NEXT,"close");
    orig_close_nocancel=(close_t)dlsym(RTLD_NEXT,"close$NOCANCEL");
    orig_rename=(rename_t)dlsym(RTLD_NEXT,"rename");
    orig_renameat=(renameat_t)dlsym(RTLD_NEXT,"renameat");
    orig_gethostbyname=(gethostbyname_t)dlsym(RTLD_NEXT,"gethostbyname");
    orig_getaddrinfo=(getaddrinfo_t)dlsym(RTLD_NEXT,"getaddrinfo");
    orig_fopen=(fopen_t)fopen; orig_fclose=(fclose_t)fclose;
    dst_ensure_log(); LOGD("originals resolved");
    struct rebinding rebinds[]={
        {"connect",(void*)fake_connect,(void**)&orig_connect},
        {"sendto",(void*)fake_sendto,(void**)&orig_sendto},
        {"bind",(void*)fake_bind,(void**)&orig_bind},
        {"gethostbyname",(void*)fake_gethostbyname,(void**)&orig_gethostbyname},
        {"getaddrinfo",(void*)fake_getaddrinfo,(void**)&orig_getaddrinfo},
        {"X509_verify_cert",(void*)fake_X509_verify_cert,(void**)&orig_X509_verify_cert},
        {"open",(void*)fake_open,(void**)&orig_open},
        {"open$NOCANCEL",(void*)fake_open_nocancel,(void**)&orig_open_nocancel},
        {"openat",(void*)fake_openat,(void**)&orig_openat},
        {"openat$NOCANCEL",(void*)fake_openat_nocancel,(void**)&orig_openat_nocancel},
        {"fopen",(void*)fake_fopen,(void**)&orig_fopen},
        {"rename",(void*)fake_rename,(void**)&orig_rename},
        {"renameat",(void*)fake_renameat,(void**)&orig_renameat},
    };
    rebind_symbols(rebinds,sizeof(rebinds)/sizeof(rebinds[0]));
    LOGD("fishhook rebind done");
}

// ---- cluster_token ----
static __thread int g_open_reent=0; static int g_token_inject_log=0;
static int path_is_cluster_token(const char* p) { return p && strstr(p,"cluster_token.txt"); }
static int open_is_read(int f) { return (f&3)==O_RDONLY; }
static const char b64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void gen_klei_token(char*buf,size_t bl) {
    strncpy(buf,"pds-g",bl); buf+=5; bl-=5;
    srand((unsigned)(time(NULL)^getpid()));
    for(size_t i=0;i+1<bl;i++) buf[i]=b64[rand()%64];
    buf[bl-1]=0; if(bl>1) buf[bl-2]='=';
}
static void ensure_cluster_token(const char*path,open_t ropen) {
    if(!ropen) return; int fd=ropen(path,O_RDONLY,0); if(fd<0) return;
    char b[256]; ssize_t n=read(fd,b,255); close(fd);
    if(n>0){b[n]=0; if(strstr(b,"pds-g")) return;}
    char tok[128]; gen_klei_token(tok,sizeof(tok));
    fd=ropen(path,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(fd>=0){write(fd,tok,strlen(tok)); close(fd);}
}
static void ensure_cluster_token_at(const char*path,int dirfd,openat_t ropen) {
    if(!ropen) return; int fd=ropen(dirfd,path,O_RDONLY,0); if(fd<0) return;
    char b[256]; ssize_t n=read(fd,b,255); close(fd);
    if(n>0){b[n]=0; if(strstr(b,"pds-g")) return;}
    char tok[128]; gen_klei_token(tok,sizeof(tok));
    fd=ropen(dirfd,path,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(fd>=0){write(fd,tok,strlen(tok)); close(fd);}
}
static int g_tok_wfd=-1; static char g_tok_wpath[512];
static void record_tok_write_fd(int fd,const char*path,int flags) {
    if(fd<0||!path||!path_is_cluster_token(path)) return;
    if(strchr("wa",(char)(flags&3))||(flags&O_CREAT)) { g_tok_wfd=fd; strncpy(g_tok_wpath,path,511); g_tok_wpath[511]=0; }
}
static void rewrite_cluster_token_on_close() {
    if(g_tok_wpath[0]=='\0') return;
    int wfd=orig_open?orig_open(g_tok_wpath,O_RDONLY,0):open(g_tok_wpath,O_RDONLY,0);
    if(wfd<0) return; char b[256]; ssize_t n=read(wfd,b,255);
    if(orig_close) orig_close(wfd); else close(wfd);
    if(n>0){b[n]=0; if(strstr(b,"pds-g")){g_tok_wpath[0]=0; return;}}
    char tok[128]; gen_klei_token(tok,sizeof(tok));
    wfd=orig_open?orig_open(g_tok_wpath,O_WRONLY|O_CREAT|O_TRUNC,0644):open(g_tok_wpath,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(wfd>=0){write(wfd,tok,strlen(tok)); if(orig_close) orig_close(wfd); else close(wfd);}
    g_tok_wpath[0]=0;
}

// ---- databundle redirect ----
static const char* g_dst_db_names[]={"scripts.zip","images.zip"};
static char g_dst_redirect_buf[1024];
static int g_ready_cache=-1; static time_t g_ready_at=0;
// 前向声明
static NSString* dst_get_cache_dir();
static int dst_assets_ready(void) {
    time_t now=time(NULL);
    if(g_ready_cache>=0 && now-g_ready_at<3) return g_ready_cache;
    int ready=0;
    @autoreleasepool {
        NSString* f=[dst_get_cache_dir() stringByAppendingPathComponent:@"ready.flag"];
        if([[NSFileManager defaultManager] fileExistsAtPath:f]) ready=1;
    }
    g_ready_cache=ready; g_ready_at=now; return ready;
}
// 重定向 ../Documents/ 相对路径到沙箱 Documents 绝对路径
// Lua 的 io.open 底层调用 fopen，CWD = bundle data/（只读），
// ../Documents/ 解析到 bundle 内（只读），需要重定向到沙箱 Documents
// v17: 对写模式也重定向，且不再要求文件已存在（写模式创建新文件时也要重定向）
static char g_lua_redirect_buf[1024];
static const char* dst_redirect_lua_path(const char* path) {
    if(!path) return path;
    // 检查是否是 ../Documents/... 路径
    if(strncmp(path, "../Documents/", 13) != 0) return path;
    @autoreleasepool {
        NSString* rel = [NSString stringWithUTF8String:path+13]; // 跳过 ../Documents/
        NSString* abs = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:rel];
        // 确保父目录存在（写模式创建文件时父目录可能不存在）
        NSString* parentDir = [abs stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
        // v17: 不再检查文件是否存在，直接返回绝对路径
        // 这样写模式也能正确重定向到沙箱目录
        strncpy(g_lua_redirect_buf, [abs UTF8String], 1023);
        g_lua_redirect_buf[1023] = 0;
        return g_lua_redirect_buf;
    }
    return path;
}

static const char* dst_redirect_databundle(const char* path) {
    if(!path) return path;
    const char* base=strrchr(path,'/'); base=base?base+1:path;
    int hit=0; for(int i=0;i<2;i++) if(strcmp(base,g_dst_db_names[i])==0){hit=1;break;}
    if(!hit) return path;
    if(!dst_assets_ready()) return path;
    @autoreleasepool {
        NSString* nm=[NSString stringWithUTF8String:base];
        NSString* cache=[dst_get_cache_dir() stringByAppendingPathComponent:nm];
        if([[NSFileManager defaultManager] fileExistsAtPath:cache]) {
            strncpy(g_dst_redirect_buf,[cache UTF8String],1023); g_dst_redirect_buf[1023]=0; return g_dst_redirect_buf;
        }
    }
    return path;
}

#define EXTRACT_MODE(flags,mode_var) va_list _ap; va_start(_ap,flags); if(flags&O_CREAT) mode_var=(mode_t)va_arg(_ap,int); va_end(_ap);

// ---- file hooks ----
static int fake_open(const char* path,int flags,...) {
    mode_t mode=0; EXTRACT_MODE(flags,mode);
    if(!g_open_reent && open_is_read(flags)) { const char* red=dst_redirect_databundle(path); if(red!=path){int rfd=orig_open?orig_open(red,flags,mode):open(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} red=dst_redirect_lua_path(path); if(red!=path){int rfd=orig_open?orig_open(red,flags,mode):open(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} }
    if(!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)){g_open_reent=1; ensure_cluster_token(path,orig_open); g_open_reent=0;}
    int fd=orig_open?orig_open(path,flags,mode):open(path,flags,mode); record_tok_write_fd(fd,path,flags); return fd;
}
static int fake_open_nocancel(const char* path,int flags,...) {
    mode_t mode=0; EXTRACT_MODE(flags,mode); open_t real=orig_open_nocancel?orig_open_nocancel:orig_open;
    if(!g_open_reent && open_is_read(flags)) { const char* red=dst_redirect_databundle(path); if(red!=path){int rfd=real(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} red=dst_redirect_lua_path(path); if(red!=path){int rfd=real(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} }
    if(!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)){g_open_reent=1; ensure_cluster_token(path,real); g_open_reent=0;}
    int fd=real(path,flags,mode); record_tok_write_fd(fd,path,flags); return fd;
}
static int fake_openat(int dirfd,const char* path,int flags,...) {
    mode_t mode=0; EXTRACT_MODE(flags,mode);
    if(!g_open_reent && open_is_read(flags)) { const char* red=dst_redirect_databundle(path); if(red!=path){int rfd=orig_open?orig_open(red,flags,mode):open(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} red=dst_redirect_lua_path(path); if(red!=path){int rfd=orig_open?orig_open(red,flags,mode):open(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} }
    if(!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)){g_open_reent=1; ensure_cluster_token_at(path,dirfd,orig_openat); g_open_reent=0;}
    int fd=orig_openat?orig_openat(dirfd,path,flags,mode):openat(dirfd,path,flags,mode); record_tok_write_fd(fd,path,flags); return fd;
}
static int fake_openat_nocancel(int dirfd,const char* path,int flags,...) {
    mode_t mode=0; EXTRACT_MODE(flags,mode); openat_t real=orig_openat_nocancel?orig_openat_nocancel:orig_openat;
    if(!g_open_reent && open_is_read(flags)) { const char* red=dst_redirect_databundle(path); if(red!=path){int rfd=orig_open?orig_open(red,flags,mode):open(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} red=dst_redirect_lua_path(path); if(red!=path){int rfd=orig_open?orig_open(red,flags,mode):open(red,flags,mode); record_tok_write_fd(rfd,path,flags); return rfd;} }
    if(!g_open_reent && path_is_cluster_token(path) && open_is_read(flags)){g_open_reent=1; ensure_cluster_token_at(path,dirfd,real); g_open_reent=0;}
    int fd=real(dirfd,path,flags,mode); record_tok_write_fd(fd,path,flags); return fd;
}
static int fake_close(int fd) { if(fd>=0&&fd==g_tok_wfd){g_tok_wfd=-1; rewrite_cluster_token_on_close();} return orig_close?orig_close(fd):close(fd); }
static int fake_close_nocancel(int fd) { if(fd>=0&&fd==g_tok_wfd){g_tok_wfd=-1; rewrite_cluster_token_on_close();} return orig_close_nocancel?orig_close_nocancel(fd):close(fd); }
static int fake_rename(const char* oldp,const char* newp) { if(!orig_rename) return -1; int r=orig_rename(oldp,newp); if(r==0&&newp&&path_is_cluster_token(newp)&&!g_open_reent){g_open_reent=1; ensure_cluster_token(newp,orig_open); g_open_reent=0;} return r; }
static int fake_renameat(int oldfd,const char* oldp,int newfd,const char* newp) { if(!orig_renameat) return -1; int r=orig_renameat(oldfd,oldp,newfd,newp); if(r==0&&newp&&path_is_cluster_token(newp)&&!g_open_reent){g_open_reent=1; ensure_cluster_token_at(newp,newfd,orig_openat); g_open_reent=0;} return r; }

// ---- C-stdio ----
static FILE* g_tok_wfile=NULL;
static FILE* fake_fopen(const char* path,const char* mode) {
    // v17: 对读模式和写模式都做 ../Documents/ 路径重定向
    if(!g_open_reent && mode) {
        // 读模式：先检查 databundle 重定向，再检查 lua_path 重定向
        if(mode[0]=='r' && !strchr(mode,'+')) {
            const char* red=dst_redirect_databundle(path); if(red!=path) return orig_fopen?orig_fopen(red,mode):fopen(red,mode);
            red=dst_redirect_lua_path(path); if(red!=path) return orig_fopen?orig_fopen(red,mode):fopen(red,mode);
        }
        // 写模式：只做 lua_path 重定向（databundle 不需要写重定向）
        if(strchr(mode,'w')||strchr(mode,'a')||strchr(mode,'+')) {
            const char* red=dst_redirect_lua_path(path); if(red!=path) return orig_fopen?orig_fopen(red,mode):fopen(red,mode);
        }
    }
    FILE* f=orig_fopen?orig_fopen(path,mode):fopen(path,mode);
    if(f&&!g_open_reent&&path&&path_is_cluster_token(path)&&mode&&(strchr(mode,'w')||strchr(mode,'a')||strchr(mode,'+'))) { g_tok_wfile=f; strncpy(g_tok_wpath,path,511); g_tok_wpath[511]=0; }
    return f;
}
static int fake_fclose(FILE* f) { if(f&&f==g_tok_wfile){g_tok_wfile=NULL; rewrite_cluster_token_on_close();} return orig_fclose?orig_fclose(f):fclose(f); }

// ---- DNS ----
#define AUTH_REDIR_IP "47.122.115.99"
static int auth_host_matches(const char* name) {
    if(!name) return 0;
    static const char* const hosts[]={"galette.klei.com","login.kleientertainment.com","accounts.klei.com","lobby-v2.klei.com","lobby-v2-cdn.klei.com","cdn-galette.klei.com",NULL};
    size_t n=strlen(name);
    for(int i=0;hosts[i];i++){size_t h=strlen(hosts[i]); if(n>=h&&strcasecmp(name+n-h,hosts[i])==0) return 1;}
    return 0;
}
static struct hostent* fake_gethostbyname(const char* name) {
    if(orig_gethostbyname&&dst_is_authed()&&auth_host_matches(name)) {
        static struct in_addr sa; static char* sal[2]; static struct hostent sh;
        memset(&sh,0,sizeof(sh)); sa.s_addr=inet_addr(AUTH_REDIR_IP); sal[0]=(char*)&sa; sal[1]=NULL;
        sh.h_name=(char*)name; sh.h_addrtype=AF_INET; sh.h_length=4; sh.h_addr_list=sal; return &sh;
    }
    return orig_gethostbyname?orig_gethostbyname(name):NULL;
}
static int fake_getaddrinfo(const char* node,const char* service,const struct addrinfo* hints,struct addrinfo** res) {
    if(orig_getaddrinfo&&dst_is_authed()&&node&&auth_host_matches(node)) return orig_getaddrinfo(AUTH_REDIR_IP,service,hints,res);
    return orig_getaddrinfo?orig_getaddrinfo(node,service,hints,res):EAI_NONAME;
}

// ---- Foundation swizzle ----
static NSString* gen_klei_token_ns(void) { char b[128]; gen_klei_token(b,sizeof(b)); return [NSString stringWithUTF8String:b]; }
static BOOL swiz_NSData_wtf(id s,SEL c,NSString* p,BOOL a) { if(p&&[p rangeOfString:@"cluster_token.txt"].location!=NSNotFound){NSData*t=[gen_klei_token_ns() dataUsingEncoding:NSUTF8StringEncoding]?:[NSData data]; return orig_NSData_wtf(t,c,p,a);} return orig_NSData_wtf(s,c,p,a); }
static BOOL swiz_NSString_wtf(id s,SEL c,NSString* p,BOOL a,NSStringEncoding e,NSError**err) { if(p&&[p rangeOfString:@"cluster_token.txt"].location!=NSNotFound){return orig_NSString_wtf(gen_klei_token_ns(),c,p,a,e,err);} return orig_NSString_wtf(s,c,p,a,e,err); }
static BOOL swiz_NSMgr_createFile(id s,SEL c,NSString* p,NSData* d,NSDictionary* a) { if(p&&[p rangeOfString:@"cluster_token.txt"].location!=NSNotFound){NSData*t=[gen_klei_token_ns() dataUsingEncoding:NSUTF8StringEncoding]?:[NSData data]; return orig_NSMgr_createFile(s,c,p,t,a);} return orig_NSMgr_createFile(s,c,p,d,a); }
static void dst_swizzle_foundation(void) {
    @try { Method m; Class cl;
        cl=[NSData class]; m=class_getInstanceMethod(cl,@selector(writeToFile:atomically:)); if(m){orig_NSData_wtf=(BOOL(*)(id,SEL,NSString*,BOOL))method_getImplementation(m); method_setImplementation(m,(IMP)swiz_NSData_wtf);}
        cl=[NSString class]; m=class_getInstanceMethod(cl,@selector(writeToFile:atomically:encoding:error:)); if(m){orig_NSString_wtf=(BOOL(*)(id,SEL,NSString*,BOOL,NSStringEncoding,NSError**))method_getImplementation(m); method_setImplementation(m,(IMP)swiz_NSString_wtf);}
        cl=[NSFileManager class]; m=class_getInstanceMethod(cl,@selector(createFileAtPath:contents:attributes:)); if(m){orig_NSMgr_createFile=(BOOL(*)(id,SEL,NSString*,NSData*,NSDictionary*))method_getImplementation(m); method_setImplementation(m,(IMP)swiz_NSMgr_createFile);}
    } @catch(NSException* e) { LOGE("swizzle: %s",[[e description] UTF8String]); }
}
__attribute__((constructor(3)))
static void dst_foundation_swizzle_ctor(void) { dst_ensure_log(); dst_swizzle_foundation(); }

// ---- network hooks ----
static int sock_type(int fd) { int t=0; socklen_t tl=sizeof(t); return getsockopt(fd,SOL_SOCKET,SO_TYPE,&t,&tl)==0?t:0; }
static int rewrite_to_relay(const struct sockaddr* addr, struct sockaddr_in* na) {
    if(!addr||addr->sa_family!=AF_INET) return 0;
    const struct sockaddr_in* sin=(const struct sockaddr_in*)(const void*)addr;
    uint32_t ip=sin->sin_addr.s_addr; int port=ntohs(sin->sin_port);
    if(is_loopback(ip)) return 0; if(is_relay(ip,port)) return 0;
    memcpy(na,sin,sizeof(*na)); na->sin_addr.s_addr=g_relay_ip; na->sin_port=htons(dst_relay_port()); return 1;
}
static int fake_connect(int socket,const struct sockaddr* addr,socklen_t len) {
    if(g_relay_ip==0) g_relay_ip=inet_addr(DST_RELAY_IP);
    int authed=dst_is_authed(), st=sock_type(socket);
    if(authed&&st==SOCK_DGRAM) { struct sockaddr_in na; if(rewrite_to_relay(addr,&na)) return orig_connect(socket,(const struct sockaddr*)&na,sizeof(na)); }
    else if(authed&&addr&&addr->sa_family==AF_INET) {
        const struct sockaddr_in* sin=(const struct sockaddr_in*)(const void*)addr;
        uint32_t ip=sin->sin_addr.s_addr; int port=ntohs(sin->sin_port);
        uint32_t sip=inet_addr(DST_RELAY_IP);
        if(!is_loopback(ip)&&ip!=g_relay_ip&&ip!=sip&&(port==80||port==443)) { struct sockaddr_in na; memset(&na,0,sizeof(na)); na.sin_family=AF_INET; na.sin_addr.s_addr=sip; na.sin_port=htons(port); return orig_connect(socket,(const struct sockaddr*)&na,sizeof(na)); }
    }
    return orig_connect(socket,addr,len);
}
static ssize_t fake_sendto(int socket,const void* buffer,size_t length,int flags,const struct sockaddr* dest_addr,socklen_t dest_len) {
    if(g_relay_ip==0) g_relay_ip=inet_addr(DST_RELAY_IP);
    if(dst_is_authed()&&sock_type(socket)==SOCK_DGRAM) { struct sockaddr_in na; if(rewrite_to_relay(dest_addr,&na)) return orig_sendto(socket,buffer,length,flags,(const struct sockaddr*)&na,sizeof(na)); }
    return orig_sendto(socket,buffer,length,flags,dest_addr,dest_len);
}
static int fake_bind(int socket,const struct sockaddr* addr,socklen_t len) {
    if(g_relay_ip==0) g_relay_ip=inet_addr(DST_RELAY_IP);
    int r=orig_bind(socket,addr,len);
    if(r==0&&sock_type(socket)==SOCK_DGRAM&&addr) {
        int fam=addr->sa_family; int is_any=0;
        if(fam==AF_INET){const struct sockaddr_in* sin=(const struct sockaddr_in*)(const void*)addr; is_any=(sin->sin_addr.s_addr==INADDR_ANY);}
        if(fam==AF_INET&&is_any&&dst_is_authed()) { struct sockaddr_in na; memset(&na,0,sizeof(na)); na.sin_family=AF_INET; na.sin_addr.s_addr=g_relay_ip; na.sin_port=htons(dst_relay_port()); const char probe=0; orig_sendto(socket,&probe,1,0,(const struct sockaddr*)&na,sizeof(na)); }
    }
    return r;
}

static void dst_online_init() { if(g_relay_ip==0) g_relay_ip=inet_addr(DST_RELAY_IP); LOGD("=== DST UDP relay init (relay=%s:%d) ===",DST_RELAY_IP,DST_RELAY_PORT); }
__attribute__((constructor(100)))
static void dst_online_ctor() { dst_online_init(); }

// ============ v12 动态资产：后台下载 + 版本选择（dylib↔Lua 通过文件通信）============
// 通信机制：
//   dylib -> Lua:  /tmp/dst_assets_cache/versions.json    （版本列表）
//                   /tmp/dst_assets_cache/progress.txt     （下载进度）
//                   /tmp/dst_assets_cache/pending_version.txt（下载完成待应用）
//   Lua -> dylib:  /tmp/dst_assets_cache/download_request.txt（用户选择的版本ID）
//                   /tmp/dst_assets_cache/ready.flag       （用户确认应用）
//                   /tmp/dst_assets_cache/skip_version.txt （用户跳过）

#define DST_ASSET_HOST   "47.122.115.99"
#define DST_ASSET_BASE   "/dst/"
#define DST_API_BASE     "/api"
#define DST_ASSET_CONN_TO  12
#define DST_ASSET_BUDGET   300
// Documents/DoNotStarveTogether/client_save — DST 引擎自己创建的目录，Lua io.open 一定能读
static NSString* dst_get_cache_dir() {
    static NSString* cacheDir = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cacheDir = [[[[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
            stringByAppendingPathComponent:@"DoNotStarveTogether"] stringByAppendingPathComponent:@"client_save"]
            stringByAppendingPathComponent:@"dst_assets_cache"];
    });
    return cacheDir;
}

// 用 orig_connect 直连（绕过 fishhook，不触发 SIGSEGV）
static int dst_asset_http_get(const char* host, int port, const char* path, char* buf, int buflen) {
    if (!orig_connect) return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct timeval tv; tv.tv_sec = DST_ASSET_CONN_TO; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (orig_connect(sock, (const struct sockaddr*)&sa, sizeof(sa)) != 0) { close(sock); return -1; }
    char req[512];
    int rl = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: DSTIOS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host);
    if (send(sock, req, (size_t)rl, 0) <= 0) { close(sock); return -1; }
    int total = 0; int hdr_end = -1;
    // 阶段1：接收直到找到 HTTP 头结束
    while (total < buflen - 1) {
        int n = recv(sock, buf + total, buflen - total - 1, 0);
        if (n <= 0) break;
        total += n; buf[total] = 0;
        // 找 \r\n\r\n
        for (int i = 0; i <= total - 4; i++) {
            if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { hdr_end = i; break; }
        }
        if (hdr_end >= 0) break;
    }
    if (hdr_end < 0) { close(sock); return -1; }
    // 阶段2：继续接收 body（Connection: close 模式下 body 可能分多次到达）
    int body_start = hdr_end + 4;
    while (total < buflen - 1) {
        int n = recv(sock, buf + total, buflen - total - 1, 0);
        if (n <= 0) break;
        total += n; buf[total] = 0;
    }
    close(sock);
    // 检查 HTTP 200
    buf[hdr_end] = 0;
    if (!strstr(buf, "200 OK") && !strstr(buf, "200 ")) return -1;
    // 移动 body 到 buf 开头
    int body_len = total - body_start;
    if (body_len > 0) memmove(buf, buf + body_start, body_len);
    buf[body_len] = 0;
    return body_len;
}

// 前向声明（dst_asset_download_file 需要调用 dst_write_cache_file）
static void dst_write_cache_file(const char* name, const char* content, int len);

// 从 HTTP 头解析 Content-Length
static long long dst_parse_content_length(const char* headers, int hdr_len) {
    char* cl = strcasestr(headers, "Content-Length:");
    if (!cl) return -1;
    cl += strlen("Content-Length:");
    while (*cl == ' ' || *cl == '\t') cl++;
    return atoll(cl);
}

// 下载文件到指定路径（用 orig_connect，绕过 hook）
// asset_name 用于写实时进度到 progress.txt
static int dst_asset_download_file(const char* host, int port, const char* path, const char* out_path, const char* asset_name) {
    if (!orig_connect) return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct timeval tv; tv.tv_sec = DST_ASSET_CONN_TO; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (orig_connect(sock, (const struct sockaddr*)&sa, sizeof(sa)) != 0) { close(sock); return -1; }
    char req[512];
    int rl = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: DSTIOS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host);
    if (send(sock, req, (size_t)rl, 0) <= 0) { close(sock); return -1; }
    char buf[65536]; int total = 0; int hdr_end = -1;
    while (total < (int)sizeof(buf)) {
        int n = recv(sock, buf + total, sizeof(buf) - total, 0);
        if (n <= 0) break;
        total += n;
        for (int i = 0; i <= total - 4; i++) {
            if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') { hdr_end = i; break; }
        }
        if (hdr_end >= 0) break;
    }
    if (hdr_end < 0) { close(sock); return -1; }
    buf[hdr_end] = 0;
    if (!strstr(buf, "200 OK") && !strstr(buf, "200 ")) { close(sock); return -1; }
    // 解析 Content-Length
    long long content_len = dst_parse_content_length(buf, hdr_end);
    // 使用 orig_fopen 绕过 fishhook，避免在下载循环中触发 fake_fopen
    FILE* out = orig_fopen ? orig_fopen(out_path, "wb") : fopen(out_path, "wb");
    if (!out) { close(sock); return -1; }
    int body_start = hdr_end + 4;
    long long downloaded = 0;
    if (body_start < total) {
        int chunk = total - body_start;
        fwrite(buf + body_start, 1, (size_t)chunk, out);
        downloaded += chunk;
    }
    // 写实时进度
    if (asset_name && content_len > 0) {
        char prog[256];
        snprintf(prog, sizeof(prog), "%s %lld %lld\n", asset_name, downloaded, content_len);
        dst_write_cache_file("progress.txt", prog, 0);
    }
    time_t deadline = time(NULL) + DST_ASSET_BUDGET;
    int last_prog_update = 0;
    while (1) {
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        fwrite(buf, 1, (size_t)n, out);
        downloaded += n;
        // 每 100KB 或每次更新进度
        int dl_kb = (int)(downloaded / 102400);
        if (asset_name && content_len > 0 && dl_kb != last_prog_update) {
            last_prog_update = dl_kb;
            char prog[256];
            snprintf(prog, sizeof(prog), "%s %lld %lld\n", asset_name, downloaded, content_len);
            dst_write_cache_file("progress.txt", prog, 0);
        }
        if (time(NULL) > deadline) break;
    }
    fclose(out); close(sock);
    // 验证下载完整性
    if (content_len > 0 && downloaded < content_len) {
        LOGE("asset worker: download %s incomplete: %lld/%lld bytes", asset_name ? asset_name : "?", downloaded, content_len);
        return -1;
    }
    return 0;
}

// 写文件到 Documents/dst_assets_cache/
static void dst_write_cache_file(const char* name, const char* content, int len) {
    @autoreleasepool {
        NSString* dir = dst_get_cache_dir();
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString* path = [dir stringByAppendingPathComponent:[NSString stringWithUTF8String:name]];
        // 使用 orig_fopen 绕过 fishhook，避免在后台线程中触发 fake_fopen 导致 SIGSEGV
        FILE* f = orig_fopen ? orig_fopen([path UTF8String], "wb") : fopen([path UTF8String], "wb");
        if (f) { if (len > 0) fwrite(content, 1, (size_t)len, f); else fputs(content, f); fclose(f); }
    }
}

// 读 Documents/dst_assets_cache/ 文件
static int dst_read_cache_file(const char* name, char* buf, int buflen) {
    @autoreleasepool {
        NSString* path = [dst_get_cache_dir() stringByAppendingPathComponent:[NSString stringWithUTF8String:name]];
        // 使用 orig_fopen 绕过 fishhook
        FILE* f = orig_fopen ? orig_fopen([path UTF8String], "r") : fopen([path UTF8String], "r");
        if (!f) return -1;
        int n = (int)fread(buf, 1, (size_t)buflen - 1, f);
        buf[n] = 0; fclose(f);
        // trim
        while (n > 0 && (buf[n-1]=='\n' || buf[n-1]=='\r' || buf[n-1]==' ')) buf[--n] = 0;
        return n;
    }
}

static int dst_cache_file_exists(const char* name) {
    @autoreleasepool {
        NSString* path = [dst_get_cache_dir() stringByAppendingPathComponent:[NSString stringWithUTF8String:name]];
        return [[NSFileManager defaultManager] fileExistsAtPath:path] ? 1 : 0;
    }
}

static void dst_remove_cache_file(const char* name) {
    @autoreleasepool {
        NSString* path = [dst_get_cache_dir() stringByAppendingPathComponent:[NSString stringWithUTF8String:name]];
        [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
    }
}

// 后台 worker：拉版本列表 + 轮询下载请求 + 下载
static void* dst_asset_worker(void* arg) {
    (void)arg;
    @try {
        LOGD("=== dst asset worker v20 start (background) ===");

        // 1) 拉版本列表 -> versions.json
        char vbuf[65536];
        char api_path[256];
        snprintf(api_path, sizeof(api_path), "%s/versions", DST_API_BASE);
        int vlen = dst_asset_http_get(DST_ASSET_HOST, 3000, api_path, vbuf, sizeof(vbuf));
        if (vlen <= 0) {
            // 试 80 端口
            vlen = dst_asset_http_get(DST_ASSET_HOST, 80, api_path, vbuf, sizeof(vbuf));
        }
        if (vlen > 0) {
            dst_write_cache_file("versions.json", vbuf, vlen);
            LOGD("asset worker: versions.json written (%d bytes)", vlen);
        } else {
            LOGE("asset worker: failed to fetch versions.json");
        }

        // 2) 轮询 download_request.txt
        int poll_count = 0;
        while (1) {
            sleep(3);
            poll_count++;

            // 检查是否有删除请求
            char del_req[16];
            int dlen = dst_read_cache_file("delete_request.txt", del_req, sizeof(del_req));
            if (dlen > 0 && del_req[0] != 0) {
                LOGD("asset worker: delete request received");
                dst_remove_cache_file("delete_request.txt");
                dst_remove_cache_file("ready.flag");
                dst_remove_cache_file("pending_version.txt");
                dst_remove_cache_file("progress.txt");
                dst_remove_cache_file("skip_version.txt");
                dst_remove_cache_file("download_request.txt");
                dst_remove_cache_file("version.txt");
                dst_remove_cache_file("scripts.zip");
                dst_remove_cache_file("images.zip");
                dst_remove_cache_file("versions.json");
                g_ready_cache = -1; // 清除缓存
                LOGD("asset worker: all cache files deleted");
            }

            // 检查是否有下载请求
            char req_ver[256];
            int rlen = dst_read_cache_file("download_request.txt", req_ver, sizeof(req_ver));
            if (rlen > 0 && req_ver[0] != 0) {
                LOGD("asset worker: download request for version '%s'", req_ver);

                // 检查是否已在下载（简单防重：删请求文件）
                dst_remove_cache_file("download_request.txt");

                // 下载该版本的 scripts.zip + images.zip + version.txt
                const char* assets[] = {"scripts.zip", "images.zip", "version.txt"};
                int all_ok = 1;
                for (int i = 0; i < 3; i++) {
                    char dl_path[512];
                    snprintf(dl_path, sizeof(dl_path), "%s/version/%s/%s",
                             DST_API_BASE, req_ver, assets[i]);

                    // 写初始进度
                    char prog[128];
                    snprintf(prog, sizeof(prog), "%s 0 0\n", assets[i]);
                    dst_write_cache_file("progress.txt", prog, 0);

                    @autoreleasepool {
                        NSString* dir = dst_get_cache_dir();
                        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
                    }

                    char out_path[512];
                    snprintf(out_path, sizeof(out_path), "%s/%s", [dst_get_cache_dir() UTF8String], assets[i]);

                    int port = 3000;
                    // 传入 asset_name 用于实时写进度
                    int rc = dst_asset_download_file(DST_ASSET_HOST, port, dl_path, out_path, assets[i]);
                    if (rc != 0) {
                        // 试 80
                        rc = dst_asset_download_file(DST_ASSET_HOST, 80, dl_path, out_path, assets[i]);
                    }
                    if (rc != 0) {
                        LOGE("asset worker: download %s failed", assets[i]);
                        all_ok = 0; break;
                    }
                    // 写最终进度（下载完成）
                    @autoreleasepool {
                        NSString* fp = [NSString stringWithUTF8String:out_path];
                        NSDictionary* att = [[NSFileManager defaultManager] attributesOfItemAtPath:fp error:nil];
                        long long sz = att ? [att fileSize] : 0;
                        char prog2[128];
                        snprintf(prog2, sizeof(prog2), "%s %lld %lld\n", assets[i], sz, sz);
                        dst_write_cache_file("progress.txt", prog2, 0);
                    }
                    LOGD("asset worker: %s downloaded OK", assets[i]);
                }

                dst_remove_cache_file("progress.txt");

                if (all_ok) {
                    // 读 version.txt 获取版本号
                    char ver_str[128]; ver_str[0] = 0;
                    char ver_path[512];
                    snprintf(ver_path, sizeof(ver_path), "%s/version.txt", [dst_get_cache_dir() UTF8String]);
                    // 使用 orig_fopen 绕过 fishhook
                    FILE* vf = orig_fopen ? orig_fopen(ver_path, "r") : fopen(ver_path, "r");
                    if (vf) { fgets(ver_str, sizeof(ver_str), vf); fclose(vf);
                        size_t L = strlen(ver_str);
                        while (L > 0 && (ver_str[L-1]=='\n'||ver_str[L-1]=='\r')) ver_str[--L]=0;
                    }
                    if (ver_str[0] == 0) strncpy(ver_str, req_ver, sizeof(ver_str)-1);

                    // 写 pending_version.txt
                    char pv[256];
                    snprintf(pv, sizeof(pv), "%s\n", ver_str);
                    dst_write_cache_file("pending_version.txt", pv, 0);
                    LOGD("asset worker: download complete -> pending_version=%s", ver_str);
                } else {
                    char err_msg[256];
                    snprintf(err_msg, sizeof(err_msg), "error: download %s failed\n", req_ver);
                    dst_write_cache_file("pending_version.txt", err_msg, 0);
                }
            }

            // 每 30 轮重新拉一次版本列表
            if (poll_count % 10 == 0) {
                vlen = dst_asset_http_get(DST_ASSET_HOST, 3000, api_path, vbuf, sizeof(vbuf));
                if (vlen <= 0) vlen = dst_asset_http_get(DST_ASSET_HOST, 80, api_path, vbuf, sizeof(vbuf));
                if (vlen > 0) dst_write_cache_file("versions.json", vbuf, vlen);
            }
        }
    } @catch (NSException* e) {
        LOGE("asset worker exception: %s", [[e description] UTF8String]);
    }
    return NULL;
}

__attribute__((constructor(99)))
static void dst_asset_worker_init() {
    dst_ensure_log();
    LOGD("=== dst_asset_worker_init: spawn background worker ===");
    pthread_t t;
    if (pthread_create(&t, NULL, dst_asset_worker, NULL) == 0) {
        pthread_detach(t);
    } else {
        LOGE("asset worker: pthread_create failed");
    }
}

// ============ 皮肤解锁注入 (IOSVISION v6.1) - 必须保留 ============
static NSString* extract_field_from_file(NSString* path, NSString* field) {
    if(!path||![[NSFileManager defaultManager] fileExistsAtPath:path]) return nil;
    NSData* data=[NSData dataWithContentsOfFile:path]; if(!data) return nil;
    NSError* err=nil; NSDictionary* json=[NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if(err||!json) return nil;
    return [json objectForKey:field];
}
static NSString* find_game_userid() {
    NSString* pendingPath=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/DoNotStarveTogether/client_save/pending_keyvalues_prod"];
    if(![[NSFileManager defaultManager] fileExistsAtPath:pendingPath]) return nil;
    return extract_field_from_file(pendingPath,@"OfflineID");
}
static bool patch_cache(NSString* cachePath, NSString* userId) {
    NSData* data=[NSData dataWithContentsOfFile:cachePath]; if(!data) return false;
    NSError* err=nil; NSMutableDictionary* json=[NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&err];
    if(err||!json) return false;
    [json setObject:(userId?userId:@"") forKey:@"OfflineUserID"];
    NSData* patched=[NSJSONSerialization dataWithJSONObject:json options:0 error:&err];
    if(err||!patched) return false;
    return [patched writeToFile:cachePath atomically:YES];
}
__attribute__((constructor(101)))
static void iosvision_init() {
    LOGD("IOSVISION v6.1 - One shot");
    NSFileManager* fm=[NSFileManager defaultManager];
    NSString* bundlePath=[[NSBundle mainBundle] pathForResource:@"inventory_cache_prod" ofType:nil];
    if(!bundlePath||![fm fileExistsAtPath:bundlePath]) { LOGE("inventory_cache_prod not found!"); return; }
    NSString* userId=find_game_userid();
    if(!userId) { LOGD("pending_keyvalues_prod not found, skip"); return; }
    NSString* targetDir=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/DoNotStarveTogether/client_save"];
    [fm createDirectoryAtPath:targetDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString* cachePath=[targetDir stringByAppendingPathComponent:@"inventory_cache_prod"];
    if([fm fileExistsAtPath:cachePath]) {
        NSString* existingId=extract_field_from_file(cachePath,@"OfflineUserID");
        if(existingId&&userId&&[existingId isEqualToString:userId]) {
            LOGD("Skip (ID already matches)");
            for(NSString* sp in @[[targetDir stringByAppendingPathComponent:@"inventory_cache_prod_sig"],[targetDir stringByAppendingPathComponent:@"pending_keyvalues_prod_sig"]]) if([fm fileExistsAtPath:sp]) [fm removeItemAtPath:sp error:nil];
            return;
        }
    }
    [fm removeItemAtPath:cachePath error:nil];
    NSError* err=nil; [fm copyItemAtPath:bundlePath toPath:cachePath error:&err];
    if(err) { LOGE("Copy failed"); return; }
    patch_cache(cachePath,userId);
    for(NSString* sp in @[[targetDir stringByAppendingPathComponent:@"inventory_cache_prod_sig"],[targetDir stringByAppendingPathComponent:@"pending_keyvalues_prod_sig"]]) if([fm fileExistsAtPath:sp]) [fm removeItemAtPath:sp error:nil];
    LOGD("IOSVISION Done.");
}
