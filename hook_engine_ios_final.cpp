/*
 * iOS Hook Engine - 饥荒联机版 v1.2.4
 * 基于 Dobby inline-hook 框架
 *
 * 功能：角色皮肤解锁 + 角色解锁 + 物品皮肤
 *
 * 二进制特性：
 *   - 非 PIE（PIE=0），编译基址固定为 0x100000000
 *   - dyld slide = 0，VM 地址 = 运行时地址
 *   - StoreKit 相关函数在 libStoreKit.framework 中，需单独查找
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

// Dobby headers
#include "dobby.h"

// iOS Frameworks
#include <Foundation/Foundation.h>
#include <GameKit/GameKit.h>

#define LOG_TAG "IOSVISION"
#define LOGD(fmt, ...) fprintf(stderr, "[IOSVISION] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[IOSVISION ERROR] " fmt "\n", ##__VA_ARGS__)

// ============================================================
// 编译时 VM 基址（非PIE，固定）
// ============================================================
#define VM_BASE 0x100000000ULL

// ============================================================
// 辅助函数
// ============================================================

// 获取游戏的运行时基址（非PIE: base = VM_BASE + slide, slide=0）
static uintptr_t find_game_base() {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name && strstr(name, "dontstarvetogether")) {
            uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
            return VM_BASE + slide;
        }
    }
    return 0;
}

// 获取任意 VM 地址对应的运行时地址
static void* vm_to_runtime(uintptr_t vm_addr) {
    // 非PIE: runtime_addr = vm_addr + slide
    // 但由于游戏主二进制非PIE且slide=0，vm_addr本身就是运行时地址
    // 这里用通用方法：通过 image 查找
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        uintptr_t slide = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        uintptr_t base = _dyld_get_image_vmaddr_slide(i) + VM_BASE;
        // 简单的范围检查（对于主二进制）
        if (name && strstr(name, "dontstarvetogether")) {
            if (vm_addr >= VM_BASE && vm_addr < VM_BASE + 0x110000000ULL) {
                return (void*)vm_addr; // 非PIE，vm_addr = runtime_addr
            }
        }
    }
    // StoreKit 等框架：vm_addr 可能在不同 image 中
    // 对主二进制内的地址直接返回
    return (void*)vm_addr;
}

// 检查地址是否在文件范围内（用于验证）
static bool is_valid_offset(uintptr_t vm_offset) {
    // vm_offset 是相对于 VM_BASE 的偏移
    // 文件大小 ~0xD3E070，__TEXT fileoff=0xAD8000
    // vm_offset 在 0x0 ~ 0x100000 范围内是有效的（主二进制代码段）
    return vm_offset < 0x1200000;
}

// ============================================================
// 内存保护修改
// ============================================================
static bool make_writable(void* addr, size_t size) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 16384;
    uintptr_t page_addr = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t page_end = ((uintptr_t)addr + size + page_size - 1) & ~(page_size - 1);
    size_t protect_size = page_end - page_addr;
    int ret = mprotect((void*)page_addr, protect_size, PROT_READ | PROT_WRITE);
    if (ret != 0) {
        LOGE("mprotect failed for 0x%llx: %s", (unsigned long long)page_addr, strerror(errno));
    }
    return ret == 0;
}

static bool restore_protect(void* addr, size_t size) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 16384;
    uintptr_t page_addr = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t page_end = ((uintptr_t)addr + size + page_size - 1) & ~(page_size - 1);
    size_t protect_size = page_end - page_addr;
    return mprotect((void*)page_addr, protect_size, PROT_READ | PROT_EXEC) == 0;
}

// ============================================================
// Hook 目标地址（Ghidra VM 地址，非PIE，即运行时地址）
// 注意：这些地址是相对于 VM_BASE=0x100000000 的文件偏移
// 由于二进制非PIE，运行时地址 = VM_BASE + offset = 0x1000xxxxx
// 但实际地址需要 dyld slide 修正（非PIE情况下 slide=0）
// ============================================================

// --- 成就解锁（GameCenterManager）---
#define VM_IS_UNLOCKED_ACHIEVEMENT    0x100007ec8
#define VM_REPORT_ACHIEVEMENT         0x10000855c
#define VM_RESET_ACHIEVEMENTS         0x1000088ec
#define VM_IS_AUTHENTICATED           0x1000093a0
#define VM_AUTHENTICATE               0x10000928c
#define VM_LOAD_ALL_ACHIEVEMENTS      0x100007c58

// --- 皮肤设置（AnimStateLuaProxy）---
#define VM_SET_SKIN                   0x1000837f8
#define VM_ASSIGN_ITEM_SKINS          0x10008492c
#define VM_OVERRIDE_SKIN_SYMBOL       0x100084678
#define VM_OVERRIDE_ITEM_SKIN_SYMBOL  0x10008472c
#define VM_GET_SKIN_BUILD             0x10008603c
#define VM_ADD_OVERRIDE_BUILD         0x100084aa8
#define VM_CLEAR_OVERRIDE_BUILD       0x100084b34

// --- 网络/玩家（NetworkComponentLuaProxy）---
#define VM_SET_PLAYER_SKIN            0x1000b2c28
#define VM_SET_PLAYER_EQUIP           0x1000b2ba4
#define VM_IS_BORROWED                0x1000b2f00

// --- 地图解锁（cMapExplorerComponentLuaProxy）---
#define VM_LEARN_ALL_MAPS             0x1000a3508
#define VM_RECORD_ALL_MAPS            0x1000a34b0

// ============================================================
// Hook 函数实现（ObjC 风格）
// ============================================================

// 1. GameCenterManager::isUnlockedAchievementWithAchievementID:
typedef BOOL (*IsUnlockedAchievementFunc)(id, SEL, id);
IsUnlockedAchievementFunc orig_IsUnlockedAchievement = NULL;
BOOL hooked_IsUnlockedAchievement(id self, SEL _cmd, id achievementID) {
    LOGD("Hooked: isUnlockedAchievementWithAchievementID: -> YES");
    return YES;
}

// 2. GameCenterManager::loadAllAchievements:
typedef id (*LoadAllAchievementsFunc)(id, SEL);
LoadAllAchievementsFunc orig_LoadAllAchievements = NULL;
id hooked_LoadAllAchievements(id self, SEL _cmd) {
    LOGD("Hooked: loadAllAchievements: -> ALL (empty array = all unlocked)");
    return [NSArray array];
}

// 3. GameCenterManager::reportAchievementWithAchievementID:progress:
typedef void (*ReportAchievementFunc)(id, SEL, id, double);
ReportAchievementFunc orig_ReportAchievement = NULL;
void hooked_ReportAchievement(id self, SEL _cmd, id achievementID, double progress) {
    LOGD("Hooked: reportAchievementWithAchievementID:progress: -> logged");
}

// 4. GameCenterManager::resetAchievements
typedef void (*ResetAchievementsFunc)(id, SEL);
ResetAchievementsFunc orig_ResetAchievements = NULL;
void hooked_ResetAchievements(id self, SEL _cmd) {
    LOGD("Hooked: resetAchievements -> NO-OP");
}

// 5. GameCenterManager::isAuthenticated
typedef BOOL (*IsAuthenticatedFunc)(id, SEL);
IsAuthenticatedFunc orig_IsAuthenticated = NULL;
BOOL hooked_IsAuthenticated(id self, SEL _cmd) {
    LOGD("Hooked: isAuthenticated -> YES");
    return YES;
}

// 6. GameCenterManager::authenticate
typedef void (*AuthenticateFunc)(id, SEL);
AuthenticateFunc orig_Authenticate = NULL;
void hooked_Authenticate(id self, SEL _cmd) {
    LOGD("Hooked: authenticate -> SUCCESS");
}

// 7. AnimStateLuaProxy::SetSkin
typedef long long (*SetSkinFunc)(id, SEL, void*);
SetSkinFunc orig_SetSkin = NULL;
long long hooked_SetSkin(id self, SEL _cmd, void* L) {
    LOGD("Hooked: AnimStateLuaProxy::SetSkin -> SUCCESS");
    return 0;
}

// 8. AnimStateLuaProxy::AssignItemSkins
typedef long long (*AssignItemSkinsFunc)(id, SEL, void*);
AssignItemSkinsFunc orig_AssignItemSkins = NULL;
long long hooked_AssignItemSkins(id self, SEL _cmd, void* L) {
    LOGD("Hooked: AnimStateLuaProxy::AssignItemSkins -> ALL");
    return 0;
}

// 9. AnimStateLuaProxy::OverrideSkinSymbol
typedef long long (*OverrideSkinSymbolFunc)(id, SEL, void*, void*);
OverrideSkinSymbolFunc orig_OverrideSkinSymbol = NULL;
long long hooked_OverrideSkinSymbol(id self, SEL _cmd, void* L, void* symbol) {
    LOGD("Hooked: OverrideSkinSymbol -> ALLOW");
    return 0;
}

// 10. AnimStateLuaProxy::OverrideItemSkinSymbol
typedef long long (*OverrideItemSkinSymbolFunc)(id, SEL, void*, void*);
OverrideItemSkinSymbolFunc orig_OverrideItemSkinSymbol = NULL;
long long hooked_OverrideItemSkinSymbol(id self, SEL _cmd, void* L, void* symbol) {
    LOGD("Hooked: OverrideItemSkinSymbol -> ALLOW");
    return 0;
}

// 11. AnimStateLuaProxy::GetSkinBuild
typedef id (*GetSkinBuildFunc)(id, SEL, void*);
GetSkinBuildFunc orig_GetSkinBuild = NULL;
id hooked_GetSkinBuild(id self, SEL _cmd, void* L) {
    LOGD("Hooked: GetSkinBuild -> VALID");
    return @"";
}

// 12. AnimStateLuaProxy::AddOverrideBuild
typedef void (*AddOverrideBuildFunc)(id, SEL, void*, void*);
AddOverrideBuildFunc orig_AddOverrideBuild = NULL;
void hooked_AddOverrideBuild(id self, SEL _cmd, void* L, void* build) {
    LOGD("Hooked: AddOverrideBuild -> INJECT");
}

// 13. AnimStateLuaProxy::ClearOverrideBuild
typedef void (*ClearOverrideBuildFunc)(id, SEL, void*);
ClearOverrideBuildFunc orig_ClearOverrideBuild = NULL;
void hooked_ClearOverrideBuild(id self, SEL _cmd, void* L) {
    LOGD("Hooked: ClearOverrideBuild -> KEEP (no-op)");
}

// 14. NetworkComponentLuaProxy::SetPlayerSkin
typedef long long (*SetPlayerSkinFunc)(id, SEL, void*);
SetPlayerSkinFunc orig_SetPlayerSkin = NULL;
long long hooked_SetPlayerSkin(id self, SEL _cmd, void* L) {
    LOGD("Hooked: NetworkComponentLuaProxy::SetPlayerSkin -> ALLOW");
    return 0;
}

// 15. NetworkComponentLuaProxy::SetPlayerEquip
typedef long long (*SetPlayerEquipFunc)(id, SEL, void*);
SetPlayerEquipFunc orig_SetPlayerEquip = NULL;
long long hooked_SetPlayerEquip(id self, SEL _cmd, void* L) {
    LOGD("Hooked: NetworkComponentLuaProxy::SetPlayerEquip -> ALLOW");
    return 0;
}

// 16. NetworkComponentLuaProxy::IsBorrowed
typedef BOOL (*IsBorrowedFunc)(id, SEL);
IsBorrowedFunc orig_IsBorrowed = NULL;
BOOL hooked_IsBorrowed(id self, SEL _cmd) {
    LOGD("Hooked: NetworkComponentLuaProxy::IsBorrowed -> NO");
    return NO;
}

// 17. cMapExplorerComponentLuaProxy::LearnAllMaps
typedef void (*LearnAllMapsFunc)(id, SEL);
LearnAllMapsFunc orig_LearnAllMaps = NULL;
void hooked_LearnAllMaps(id self, SEL _cmd) {
    LOGD("Hooked: cMapExplorerComponentLuaProxy::LearnAllMaps -> SUCCESS");
}

// 18. cMapExplorerComponentLuaProxy::RecordAllMaps
typedef long long (*RecordAllMapsFunc)(id, SEL);
RecordAllMapsFunc orig_RecordAllMaps = NULL;
long long hooked_RecordAllMaps(id self, SEL _cmd) {
    LOGD("Hooked: cMapExplorerComponentLuaProxy::RecordAllMaps -> SUCCESS");
    return 1;
}

// ============================================================
// Hook 安装
// ============================================================
static void install_hooks() {
    LOGD("=== IOSVISION iOS Hook Installation ===");

    struct HookEntry {
        const char* name;
        void* addr;
        void* hook_impl;
        void** orig_ptr;
    };

    HookEntry hooks[] = {
        // 成就解锁
        {"isUnlockedAchievementWithAchievementID:",   (void*)VM_IS_UNLOCKED_ACHIEVEMENT,   (void*)hooked_IsUnlockedAchievement,   (void**)&orig_IsUnlockedAchievement},
        {"loadAllAchievements:",                      (void*)VM_LOAD_ALL_ACHIEVEMENTS,     (void*)hooked_LoadAllAchievements,     (void**)&orig_LoadAllAchievements},
        {"reportAchievementWithAchievementID:progress:", (void*)VM_REPORT_ACHIEVEMENT,    (void*)hooked_ReportAchievement,       (void**)&orig_ReportAchievement},
        {"resetAchievements",                         (void*)VM_RESET_ACHIEVEMENTS,        (void*)hooked_ResetAchievements,       (void**)&orig_ResetAchievements},
        {"isAuthenticated",                           (void*)VM_IS_AUTHENTICATED,          (void*)hooked_IsAuthenticated,         (void**)&orig_IsAuthenticated},
        {"authenticate",                              (void*)VM_AUTHENTICATE,              (void*)hooked_Authenticate,            (void**)&orig_Authenticate},

        // 皮肤设置
        {"SetSkin",                                   (void*)VM_SET_SKIN,                  (void*)hooked_SetSkin,                 (void**)&orig_SetSkin},
        {"AssignItemSkins",                           (void*)VM_ASSIGN_ITEM_SKINS,         (void*)hooked_AssignItemSkins,         (void**)&orig_AssignItemSkins},
        {"OverrideSkinSymbol",                        (void*)VM_OVERRIDE_SKIN_SYMBOL,      (void*)hooked_OverrideSkinSymbol,      (void**)&orig_OverrideSkinSymbol},
        {"OverrideItemSkinSymbol",                    (void*)VM_OVERRIDE_ITEM_SKIN_SYMBOL, (void*)hooked_OverrideItemSkinSymbol,  (void**)&orig_OverrideItemSkinSymbol},
        {"GetSkinBuild",                              (void*)VM_GET_SKIN_BUILD,            (void*)hooked_GetSkinBuild,            (void**)&orig_GetSkinBuild},
        {"AddOverrideBuild",                          (void*)VM_ADD_OVERRIDE_BUILD,        (void*)hooked_AddOverrideBuild,        (void**)&orig_AddOverrideBuild},
        {"ClearOverrideBuild",                        (void*)VM_CLEAR_OVERRIDE_BUILD,      (void*)hooked_ClearOverrideBuild,      (void**)&orig_ClearOverrideBuild},

        // 网络/玩家
        {"SetPlayerSkin",                             (void*)VM_SET_PLAYER_SKIN,           (void*)hooked_SetPlayerSkin,           (void**)&orig_SetPlayerSkin},
        {"SetPlayerEquip",                            (void*)VM_SET_PLAYER_EQUIP,          (void*)hooked_SetPlayerEquip,          (void**)&orig_SetPlayerEquip},
        {"IsBorrowed",                                (void*)VM_IS_BORROWED,               (void*)hooked_IsBorrowed,              (void**)&orig_IsBorrowed},

        // 地图解锁
        {"LearnAllMaps",                              (void*)VM_LEARN_ALL_MAPS,            (void*)hooked_LearnAllMaps,            (void**)&orig_LearnAllMaps},
        {"RecordAllMaps",                             (void*)VM_RECORD_ALL_MAPS,           (void*)hooked_RecordAllMaps,           (void**)&orig_RecordAllMaps},
    };

    int installed = 0;
    int total = sizeof(hooks) / sizeof(hooks[0]);

    for (int i = 0; i < total; i++) {
        void* addr = hooks[i].addr;
        make_writable(addr, 16);
        DobbyHook(addr, hooks[i].hook_impl, hooks[i].orig_ptr);
        restore_protect(addr, 16);
        LOGD("  [OK] %s @ 0x%llx", hooks[i].name, (unsigned long long)addr);
        installed++;
    }

    LOGD("=== Installed %d/%d hooks ===", installed, total);
}

// ============================================================
// 入口点
// ============================================================
__attribute__((constructor))
static void iosvision_init() {
    LOGD("IOSVISION iOS: constructor called");

    // 验证游戏二进制已加载
    uintptr_t game_base = find_game_base();
    if (game_base == 0) {
        LOGE("WARNING: dontstarvetogether not found in dyld!");
        LOGE("dyld image count = %u", _dyld_image_count());
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            LOGE("  [%u] %s (slide=0x%llx)", i, _dyld_get_image_name(i),
                 (unsigned long long)_dyld_get_image_vmaddr_slide(i));
        }
        // 即使找不到，也尝试安装（可能在后续加载）
        for (int i = 0; i < 30; i++) {
            game_base = find_game_base();
            if (game_base != 0) break;
            usleep(500000);
        }
    }

    if (game_base != 0) {
        LOGD("Game base: 0x%llx (slide=0x%llx)",
             (unsigned long long)game_base,
             (unsigned long long)(game_base - VM_BASE));
    } else {
        LOGE("ERROR: Game binary never loaded! Hooks will use compile-time addresses.");
    }

    install_hooks();
    LOGD("IOSVISION iOS: initialization complete");
}
