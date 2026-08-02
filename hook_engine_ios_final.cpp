/*
 * iOS Inventory Injector - 饥荒联机版 v6.1
 *
 * 启动时执行一次，完全跟随 pending_keyvalues_prod 的 OfflineID：
 * - pending_keyvalues_prod 不存在 → 跳过（第一次启动）
 * - OfflineID 有值 → inventory_cache_prod 的 OfflineUserID 设为该值
 * - OfflineID 为空 → OfflineUserID 也设为空
 * - ID已匹配 → 跳过不覆盖
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
