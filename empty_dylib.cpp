/*
 * 隔离测试用「完全空」dylib —— 不含任何构造函数、不含任何 hook、
 * 不依赖任何系统框架（纯 C）。仅导出一个无意义符号。
 *
 * 目的：用来判定「这个 IPA 在目标设备上能否加载任何一个 dylib」。
 *   - 若该空 dylib 注入后依然白屏/零日志 → 100% 是注入(Mach-O)或
 *     TrollStore/ dyld 加载 dylib 的基础设施问题，与我们的 hook 代码无关。
 *   - 若能正常进游戏 → 说明 dylib 加载链路本身是好的，问题在正式
 *     dylib 的构造函数 / hook 代码里，再针对性排查。
 */
extern "C" __attribute__((visibility("default")))
int dst_empty_probe(void) {
    // 什么都不做，返回固定值，避免被链接器优化掉。
    volatile int x = 42;
    return x;
}
