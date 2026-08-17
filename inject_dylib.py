#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject_dylib.py - 把 DST iOS 私有服 dylib 注入解密 IPA（无需 macOS）

流程：
  1. 解压 IPA 到临时目录（保留原 zip 的 Unix 权限位）
  2. 把 dylib 拷进 <app>/Frameworks/
  3. 用 LIEF 给主程序二进制加 LC_LOAD_DYLIB（@executable_path/Frameworks/xxx.dylib）
     支持 FatBinary：所有 slice 都加
  4. 重新打成 IPA（保留权限），产出可直接用 巨魔商店(TrollStore)/企业签 安装的包

签名说明：本脚本不重签名。TrollStore 或企业证书重签会覆盖整包（含 dylib），
          因此 Windows 上无需 codesign。若用免签/自签且系统较新，请确保最终用
          TrollStore 或企业证书签名后再装。

用法：
  python inject_dylib.py --ipa 包名用中文.ipa --dylib libIOSVISION.dylib \
      --out dst-private-final.ipa
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

try:
    import lief
except ImportError:
    sys.exit("[FATAL] 需要 lief：pip install lief")

LOAD_PATH = "@executable_path/Frameworks/libIOSVISION.dylib"
DYLIB_NAME = "libIOSVISION.dylib"


def find_app_dir(payload_dir):
    for name in os.listdir(payload_dir):
        full = os.path.join(payload_dir, name)
        if name.endswith(".app") and os.path.isdir(full):
            return full
    raise SystemExit("[FATAL] Payload 下找不到 *.app")


def get_executable_name(app_dir):
    info = os.path.join(app_dir, "Info.plist")
    if os.path.exists(info):
        try:
            import plistlib
            with open(info, "rb") as f:
                p = plistlib.load(f)
            e = p.get("CFBundleExecutable")
            if e:
                return e
        except Exception:
            pass
    # 退化：找 app 目录下无扩展名、可执行的大文件
    best, bestsize = None, -1
    for n in os.listdir(app_dir):
        fp = os.path.join(app_dir, n)
        if os.path.isfile(fp) and os.access(fp, os.X_OK):
            s = os.path.getsize(fp)
            if s > bestsize:
                best, bestsize = n, s
    if best:
        return best
    raise SystemExit("[FATAL] 无法确定主程序可执行文件名")


def inject_load_command(bin_path, load_path):
    mb = lief.MachO.parse(bin_path)
    if mb is None:
        raise SystemExit(f"[FATAL] LIEF 无法解析 {bin_path}")
    binaries = mb if isinstance(mb, lief.MachO.FatBinary) else [mb]
    added = 0
    for b in binaries:
        names = [l.name for l in b.libraries]
        if load_path in names:
            print(f"  [skip] 已存在 LC_LOAD_DYLIB: {load_path}")
            added += 1
            continue
        b.add_library(load_path)
        added += 1
    mb.write(bin_path)
    # 校验
    mb2 = lief.MachO.parse(bin_path)
    binaries2 = mb2 if isinstance(mb2, lief.MachO.FatBinary) else [mb2]
    ok = all((load_path in [l.name for l in bb.libraries]) for bb in binaries2)
    if not ok:
        raise SystemExit("[FATAL] 注入后校验失败：找不到新增的 LC_LOAD_DYLIB")
    return added


def repackage(app_root, out_ipa):
    """把 app_root（含 Payload/xxx.app）重新打成 IPA，保留权限位。"""
    payload_parent = os.path.dirname(app_root)  # .../Payload
    work_root = os.path.dirname(payload_parent)  # 临时根（Payload 在此）
    mode_mask = 0xFFFF
    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, _, filenames in os.walk(work_root):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                arc = os.path.relpath(full, work_root).replace(os.sep, "/")
                st = os.stat(full)
                mode = st.st_mode & mode_mask
                zi = zipfile.ZipInfo(arc)
                zi.external_attr = mode << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                with open(full, "rb") as f:
                    z.writestr(zi, f.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True, help="输入解密 IPA")
    ap.add_argument("--dylib", required=True, help="编译好的 dylib（如 libIOSVISION.dylib）")
    ap.add_argument("--out", required=True, help="输出 IPA")
    ap.add_argument("--dylib-name", default=DYLIB_NAME, help="注入后在 Frameworks 下的文件名")
    ap.add_argument("--load-path", default=LOAD_PATH, help="LC_LOAD_DYLIB 写入的 install name")
    args = ap.parse_args()

    if not os.path.exists(args.ipa):
        sys.exit(f"[FATAL] IPA 不存在: {args.ipa}")
    if not os.path.exists(args.dylib):
        sys.exit(f"[FATAL] dylib 不存在: {args.dylib}")

    tmp = tempfile.mkdtemp(prefix="inject_")
    try:
        print(f"[1/4] 解压 IPA -> {tmp}")
        with zipfile.ZipFile(args.ipa, "r") as z:
            z.extractall(tmp)

        payload_dir = os.path.join(tmp, "Payload")
        if not os.path.isdir(payload_dir):
            raise SystemExit("[FATAL] 不是合法 IPA（缺少 Payload）")
        app_dir = find_app_dir(payload_dir)
        print(f"       app = {os.path.basename(app_dir)}")

        exe_name = get_executable_name(app_dir)
        exe_path = os.path.join(app_dir, exe_name)
        print(f"[2/4] 主程序 = {exe_name}")

        # 拷 dylib 进 Frameworks
        fw_dir = os.path.join(app_dir, "Frameworks")
        os.makedirs(fw_dir, exist_ok=True)
        dest_dylib = os.path.join(fw_dir, args.dylib_name)
        shutil.copyfile(args.dylib, dest_dylib)
        os.chmod(dest_dylib, 0o755)
        print(f"       已放入 Frameworks/{args.dylib_name}")

        print(f"[3/4] 注入 LC_LOAD_DYLIB: {args.load_path}")
        n = inject_load_command(exe_path, args.load_path)
        print(f"       已处理 {n} 个架构 slice")

        print(f"[4/4] 重新打包 -> {args.out}")
        repackage(app_dir, args.out)
        size = os.path.getsize(args.out)
        print(f"       完成，输出 {size/1024/1024:.1f} MB")
        print("[OK] 注入成功。用 TrollStore 或企业证书签名后安装。")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
