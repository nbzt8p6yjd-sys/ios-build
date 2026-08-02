 * iOS Inventory Injector - 饥荒联机版
 *
 * 功能：把全皮肤库存缓存注入游戏 Documents 目录，自动替换本机ID
 * 不需要 Dobby，不需要 hook，不需要基址
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

#define LOGD(fmt, ...) fprintf(stderr, "[IOSVISION] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[IOSVISION ERROR] " fmt "\n", ##__VA_ARGS__)

// 从设备 IDFV 生成 OfflineUserID
// 饥荒格式：E: + UUID去掉横线（32位hex小写）
static NSString* generate_device_userid() {
    NSUUID* vendorId = [[UIDevice currentDevice] identifierForVendor];
    if (vendorId) {
        NSString* uuidStr = [vendorId UUIDString];
        NSString* noHyphens = [uuidStr stringByReplacingOccurrencesOfString:@"-" withString:@""];
        NSString* result = [NSString stringWithFormat:@"E:%@", [noHyphens lowercaseString]];
        LOGD("Generated OfflineUserID from IDFV: %s", [result UTF8String]);
        return result;
    }
    LOGE("identifierForVendor is nil!");
    return nil;
}

// 从已有的缓存文件中提取本机 OfflineUserID
static NSString* extract_local_userid(NSString* path) {
    if (!path || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        return nil;
    }
    NSData* data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;

    NSError* error = nil;
    NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error || !json) return nil;

    NSString* userid = [json objectForKey:@"OfflineUserID"];
    if (userid && [userid length] > 0) {
        LOGD("Found existing OfflineUserID: %s", [userid UTF8String]);
        return userid;
    }
    return nil;
}

// 在游戏各目录搜索已有的缓存文件，提取本机ID
static NSString* find_local_userid() {
    NSString* home = NSHomeDirectory();
    NSArray* searchDirs = @[
        [home stringByAppendingPathComponent:@"Documents"],
        [home stringByAppendingPathComponent:@"Library"],
        [home stringByAppendingPathComponent:@"Library/Caches"],
        [home stringByAppendingPathComponent:@"Library/Application Support"],
    ];

    NSFileManager* fm = [NSFileManager defaultManager];

    for (NSString* dir in searchDirs) {
        if (![fm fileExistsAtPath:dir]) continue;

        // 直接检查
        NSString* directPath = [dir stringByAppendingPathComponent:@"inventory_cache_prod"];
        if ([fm fileExistsAtPath:directPath]) {
            NSString* uid = extract_local_userid(directPath);
            if (uid) return uid;
        }

        // 遍历子目录
        NSArray* subdirs = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString* subdir in subdirs) {
            NSString* subPath = [dir stringByAppendingPathComponent:subdir];
            BOOL isDir = NO;
            if ([fm fileExistsAtPath:subPath isDirectory:&isDir] && isDir) {
                NSString* cachePath = [subPath stringByAppendingPathComponent:@"inventory_cache_prod"];
                if ([fm fileExistsAtPath:cachePath]) {
                    NSString* uid = extract_local_userid(cachePath);
                    if (uid) return uid;
                }
            }
        }
    }
    return nil;
}

// 替换缓存文件中的 OfflineUserID 为本机ID
static bool patch_cache_with_local_id(NSString* cachePath, NSString* localUserId) {
    NSData* data = [NSData dataWithContentsOfFile:cachePath];
    if (!data) {
        LOGE("Failed to read cache for patching");
        return false;
    }

    NSError* error = nil;
    NSMutableDictionary* json = [NSJSONSerialization JSONObjectWithData:data
                                                                options:NSJSONReadingMutableContainers
                                                                  error:&error];
    if (error || !json) {
        LOGE("Failed to parse cache JSON: %s", error ? [[error localizedDescription] UTF8String] : "unknown");
        return false;
    }

    [json setObject:localUserId forKey:@"OfflineUserID"];
    [json setObject:@"A" forKey:@"UserID"];

    NSData* patchedData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&error];
    if (error || !patchedData) {
        LOGE("Failed to re-serialize patched cache");
        return false;
    }

    bool ok = [patchedData writeToFile:cachePath atomically:YES];
    LOGD("Patched cache with local ID: %s", ok ? "OK" : "FAILED");
    return ok;
}

// ============================================================
// 入口点：复制全皮肤缓存 + 替换本机ID + 删除签名
// ============================================================
__attribute__((constructor))
static void iosvision_init() {
    LOGD("========================================");
    LOGD("IOSVISION Inventory Injector v3.0");
    LOGD("========================================");

    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* docsDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString* cachePath = [docsDir stringByAppendingPathComponent:@"inventory_cache_prod"];
    NSString* bundlePath = [[NSBundle mainBundle] pathForResource:@"inventory_cache_prod" ofType:nil];

    LOGD("Bundle path: %s", bundlePath ? [bundlePath UTF8String] : "(null)");
    LOGD("Docs path: %s", [cachePath UTF8String]);

    // Step 1: 获取本机 OfflineUserID
    LOGD("--- Step 1: Get local OfflineUserID ---");
    NSString* localUserId = find_local_userid();
    if (!localUserId) {
        LOGD("No existing cache, generating from device IDFV...");
        localUserId = generate_device_userid();
    }
    if (!localUserId) {
        LOGE("FATAL: Could not determine local OfflineUserID!");
        return;
    }
    LOGD("Using OfflineUserID: %s", [localUserId UTF8String]);

    // Step 2: 复制全皮肤缓存到 Documents 目录
    LOGD("--- Step 2: Copy inventory cache ---");
    if (!bundlePath || ![fm fileExistsAtPath:bundlePath]) {
        LOGE("inventory_cache_prod not found in app bundle!");
        LOGE("Make sure to include it in dontstarvetogether.app/");
        return;
    }

    [fm removeItemAtPath:cachePath error:nil];
    NSError* error = nil;
    [fm copyItemAtPath:bundlePath toPath:cachePath error:&error];
    if (error) {
        LOGE("Failed to copy cache: %s", [[error localizedDescription] UTF8String]);
        return;
    }
    LOGD("Cache copied to Documents: OK");

    // Step 3: 替换本机ID
    LOGD("--- Step 3: Patch with local ID ---");
    patch_cache_with_local_id(cachePath, localUserId);

    // Step 4: 删除签名文件绕过验证
    LOGD("--- Step 4: Remove signature files ---");
    NSArray* sigFiles = @[
        [docsDir stringByAppendingPathComponent:@"inventory_cache_prod_sig"],
        [docsDir stringByAppendingPathComponent:@"pending_keyvalues_prod_sig"],
    ];
    for (NSString* sigPath in sigFiles) {
        if ([fm fileExistsAtPath:sigPath]) {
            [fm removeItemAtPath:sigPath error:nil];
            LOGD("Removed: %s", [[sigPath lastPathComponent] UTF8String]);
        }
    }

    // Step 5: 验证
    LOGD("--- Step 5: Verify ---");
    NSData* finalData = [NSData dataWithContentsOfFile:cachePath];
    if (finalData) {
        NSString* content = [[NSString alloc] initWithData:finalData encoding:NSUTF8StringEncoding];
        if (content) {
            LOGD("Final cache size: %lu bytes", (unsigned long)[content length]);
            if ([content containsString:@"WILSON"] && [content containsString:@"WENDY"]) {
                LOGD("Skin data verified: OK");
            }
            if ([content containsString:localUserId]) {
                LOGD("Local ID verified: OK");
            }
        }
    }

    LOGD("========================================");
    LOGD("Injection complete!");
    LOGD("========================================");
}
