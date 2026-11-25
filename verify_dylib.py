# -*- coding: utf-8 -*-
"""verify_dylib.py —— 解析 FAT binary 并验证架构"""
import struct
from pathlib import Path

p = Path(__file__).resolve().parent / "dist" / "BalanceTweak-dylib" / "BalanceTweak.dylib"
if not p.exists():
    print(f"  ✗ 文件不存在: {p}")
    raise SystemExit(1)

d = p.read_bytes()
magic_le = struct.unpack("<I", d[:4])[0]
magic_be = struct.unpack(">I", d[:4])[0]
print(f"  文件: {p.name}  {len(d)} 字节")
print(f"  magic(LE)={magic_le:#x}  magic(BE)={magic_be:#x}")

if magic_be == 0xCAFEBABE:
    n = struct.unpack(">I", d[4:8])[0]
    print(f"  格式: FAT binary (32-bit header, {n} 个架构)")
    off = 8
    for i in range(n):
        ct, cst, o, sz, al = struct.unpack(">IIIII", d[off:off + 20])
        if cst == 0x80000002:
            arch = "arm64e"
        elif cst == 0:
            arch = "arm64"
        else:
            arch = f"sub=0x{cst:08x}"
        print(f"    切片{i}: cputype=0x{ct:x}  {arch}  offset={o}  size={sz}  align=2^{al}")
        sm = struct.unpack("<I", d[o:o + 4])[0]
        kind = "Mach-O 64" if sm == 0xFEEDFACF else f"0x{sm:x}"
        print(f"      切片 header: {kind}")

        # 解析该切片的 LC_LOAD_DYLIB
        try:
            ncmds = struct.unpack("<I", d[o + 16:o + 20])[0]
            print(f"      ncmds: {ncmds}")
            coff = o + 32
            loads = []
            for _j in range(ncmds):
                cmd, cs = struct.unpack("<II", d[coff:coff + 8])
                if cmd == 0xC:
                    no = struct.unpack("<I", d[coff + 8:coff + 12])[0]
                    nm = d[coff + no:coff + cs].split(b"\x00")[0].decode("utf-8", "replace")
                    loads.append(nm)
                coff += cs
            if loads:
                print(f"      LC_LOAD_DYLIB ({len(loads)}):")
                for l in loads[:8]:
                    print(f"        {l}")
        except Exception as ex:
            print(f"      解析 load commands 失败: {ex}")

        off += 20
elif magic_le == 0xCAFEBABF:
    print("  格式: FAT binary (64-bit header)")
elif magic_le == 0xFEEDFACF:
    print("  格式: Thin Mach-O 64")
    ct, cst = struct.unpack("<II", d[4:12])
    arch = "arm64e" if cst == 0x80000002 else ("arm64" if cst == 0 else f"sub=0x{cst:x}")
    print(f"  架构: cputype=0x{ct:x}  {arch}")
else:
    print(f"  格式: 未知 ({magic_le:#x})")
