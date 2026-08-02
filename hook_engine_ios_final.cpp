/*
 * iOS Inventory Injector - 饥荒联机版 v6.0
 *
 * 最简方案：启动时执行一次，立即完成
 * - 找到游戏ID → 替换
 * - 没找到 → 删除字段（和游戏一致）
 * 只执行一次，不影响游戏性能
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

#define LOGD(fmt, ...) fprintf(stderr, "[IOSVISION] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[IOSVISION ERROR] " fmt "\n", ##__VA_ARGS__)

// 从 JSON 文件中提取 OfflineUserID
static NSString* extract_userid_from_file(NSString* path) {
    if (!path || ![[NSFileManager defaultManager] fileExistsAtPath:path]) return nil;
    NSData* data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;

    NSError* error = nil;
    NSDictionary* json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error || !json) return nil;

    NSString* userid = [json objectForKey:@"OfflineUserID"];
    if (userid && [userid length] > 0) {
        return userid;
    }
    return nil;
}

// 从游戏已生成的文件中搜索真实 OfflineUserID
static NSString* find_game_userid() {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSString* home = NSHomeDirectory();

    NSArray* searchDirs = @[
        [home stringByAppendingPathComponent:@"Documents/DoNotStarveTogether/client_save"],
        [home stringByAppendingPathComponent:@"Documents/DoNotStarveTogether"],
        [home stringByAppendingPathComponent:@"Documents"],
        [home stringByAppendingPathComponent:@"Library"],
        [home stringByAppendingPathComponent:@"Library/Caches"],
        [home stringByAppendingPathComponent:@"Library/Application Support"],
    ];

    for (NSString* dir in searchDirs) {
        if (![fm fileExistsAtPath:dir]) continue;

        // inventory_cache_prod
        NSString* cachePath = [dir stringByAppendingPathComponent:@"inventory_cache_prod"];
        if ([fm fileExistsAtPath:cachePath]) {
            NSString* uid = extract_userid_from_file(cachePath);
            if (uid) return uid;
        }

        // pending_keyvalues_prod
        NSString* pendingPath = [dir stringByAppendingPathComponent:@"pending_keyvalues_prod"];
        if ([fm fileExistsAtPath:pendingPath]) {
            NSString* uid = extract_userid_from_file(pendingPath);
            if (uid) return uid;
        }

        // cached_userid
        NSString* cachedPath = [dir stringByAppendingPathComponent:@"cached_userid"];
        if ([fm fileExistsAtPath:cachedPath]) {
            NSData* data = [NSData dataWithContentsOfFile:cachedPath];
            NSString* content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            content = [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if ([content length] > 0 && [content hasPrefix:@"E:"]) {
                return content;
            }
        }

        // 遍历子目录
        NSArray* subdirs = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString* subdir in subdirs) {
            NSString* subPath = [dir stringByAppendingPathComponent:subdir];
            BOOL isDir = NO;
            if ([fm fileExistsAtPath:subPath isDirectory:&isDir] && isDir) {
                NSString* subCache = [subPath stringByAppendingPathComponent:@"inventory_cache_prod"];
                if ([fm fileExistsAtPath:subCache]) {
                    NSString* uid = extract_userid_from_file(subCache);
                    if (uid) return uid;
                }
                NSString* subPending = [subPath stringByAppendingPathComponent:@"pending_keyvalues_prod"];
                if ([fm fileExistsAtPath:subPending]) {
                    NSString* uid = extract_userid_from_file(subPending);
                    if (uid) return uid;
                }
            }
        }
    }
    return nil;
}

// 处理缓存文件：有ID就替换，没ID就删除字段
static bool patch_cache(NSString* cachePath, NSString* userId) {
    NSData* data = [NSData dataWithContentsOfFile:cachePath];
    if (!data) return false;

    NSError* error = nil;
    NSMutableDictionary* json = [NSJSONSerialization JSONObjectWithData:data
                                                                options:NSJSONReadingMutableContainers
                                                                  error:&error];
    if (error || !json) return false;

    if (userId) {
        [json setObject:userId forKey:@"OfflineUserID"];
    } else {
        [json removeObjectForKey:@"OfflineUserID"];
    }

    NSData* patchedData = [NSJSONSerialization dataWithJSONObject:json options:0 error:&error];
    if (error || !patchedData) return false;

    return [patchedData writeToFile:cachePath atomically:YES];
}

// 入口：启动时执行一次
__attribute__((constructor))
static void iosvision_init() {
    LOGD("IOSVISION v6.0 - One shot");

    NSFileManager* fm = [NSFileManager defaultManager];

    // 1. 从 bundle 读取全皮肤缓存
    NSString* bundlePath = [[NSBundle mainBundle] pathForResource:@"inventory_cache_prod" ofType:nil];
    if (!bundlePath || ![fm fileExistsAtPath:bundlePath]) {
        LOGE("inventory_cache_prod not found in bundle!");
        return;
    }

    // 2. 从游戏文件读取ID（游戏没有就是nil）
    NSString* userId = find_game_userid();
    LOGD("Game ID: %s", userId ? [userId UTF8String] : "(none)");

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
        NSString* existingId = extract_userid_from_file(cachePath);
        BOOL idMatch = NO;
        if (userId && existingId && [existingId isEqualToString:userId]) {
            idMatch = YES;
        } else if (!userId && !existingId) {
            idMatch = YES;
        }

        if (idMatch) {
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

    // 有ID就替换，没ID就删除
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
