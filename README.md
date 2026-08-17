# DST iOS 私有服 — 出包工具链

让官方 Playdigious **Don't Starve Together** iOS 版（`com.playdigious.dst` v1.3.0，已解密）
走**自建服务器联机**、**绕过 Klei 登录**、采用**客户端开房 + 云端 relay 中转**（非专用服）模型。

## 架构

| 组件 | 位置 | 职责 |
|---|---|---|
| 客户端 dylib | `libIOSVISION.dylib`（本仓库 `hook_engine_ios_final.cpp` 编译） | 把非回环外部 UDP 重写到 relay；把 3 个 Klei 账号域名重定向到自建 api；注入 cluster_token；皮肤解锁 |
| api | 服务器 `:3000` FastAPI | Klei 兼容层（`/login/auto`、`/login/GameSessionToken`、`/account/game/servers` 代理到 lobby 等），含 `/admin` 后台 |
| lobby | 服务器 `:8080` node | 伪装 `lobby-v2.klei.com`，`relayPortForRoom` 固定返回 12000 |
| relay | 服务器 UDP `12000-12999` + admin `:13000` | TURN 式 hairpin 转发；客户端恒连 `12000` |
| nginx | 服务器 `:80/:443` | 反代 api/lobby |

客户端逻辑见 `hook_engine_ios_final.cpp` 顶部注释。服务器组件在 `47.122.115.99:/opt/dst-server/`。

## 出包流程

### 方式一：本地注入（最简单，推荐先跑通）
1. 在本仓库 **Actions → 最新 `Build iOS Hook Dylib + Inject IPA` → Artifacts `ios-dylibs`** 下载 `libIOSVISION.dylib`。
2. 把解密 IPA（如 `包名用中文.ipa`）和 `libIOSVISION.dylib` 放同目录，运行（Mac/Win/Linux 均可，需 `pip install lief`）：
   ```bash
   python3 inject_dylib.py --ipa 包名用中文.ipa --dylib libIOSVISION.dylib --out dst-private-final.ipa
   ```
3. 产出 `dst-private-final.ipa`，用 **TrollStore** 或 **企业证书** 签名后安装。

`inject_dylib.py` 做的事：解压 IPA → 拷 dylib 进 `Frameworks/` → 用 LIEF 给主程序加 `LC_LOAD_DYLIB` → 重打包并保留权限。已用真二进制验证。

### 方式二：仓库全自动
1. 把解密 IPA 以 **`base.ipa`** 为文件名传到本仓库的 **Release（名为 `base`）**。
2. 在 Actions 手动重跑 `Build iOS Hook Dylib + Inject IPA`（或 push 触发）。
3. 构建完成后，Artifacts 里会多一个 **`dst-private-final-ipa`**，即为可直接安装的包。
   > 没传 `base.ipa` 时，`inject` job 会自动跳过，只编 dylib，不影响构建。

## 安装
- **TrollStore（巨魔商店）**：直接分享 IPA 安装，CoreTrust 绕过无需重签。
- **企业签**：用你的企业证书对整包重签后分发。两种都会覆盖 dylib 签名，无需在 Windows/Mac 上单独 codesign。

## 已知限制 / 注意
- **relay 仅支持 2 人**：单 socket 转发，RakNet 看来所有对端都是 `47.122.115.99:12000`，第 3 人会地址冲突。多人房需改 per-client 寻址。
- **TLS**：客户端对伪造的 Klei 域名走 HTTPS，设备需安装服务器自定义 CA（`/opt/dst-server/certs/ca.crt`），否则证书校验失败。
- **lobby-v2.klei.com** 未被 dylib 重定向，但房间列表走 `accounts.klei.com/account/game/servers` 经 api 代理到 lobby，影响有限。
- 工作区里的 `github令牌.txt`（真实 token）与 `woaini520.pem`（服务器私钥）为明文敏感文件，出完活建议轮换并删除。
