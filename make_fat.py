# -*- coding: utf-8 -*-
"""make_fat.py —— 手动构造 FAT binary（arm64 + arm64e）"""
import struct
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "build"

a_path = OUT / "arm64.dylib"
b_path = OUT / "arm64e.dylib"
out_path = OUT / "BalanceTweak.dylib"

if not a_path.exists():
    print(f"  ✗ {a_path.name} 不存在")
    sys.exit(1)
if not b_path.exists():
    print(f"  ✗ {b_path.name} 不存在")
    sys.exit(1)

a = a_path.read_bytes()
b = b_path.read_bytes()

# FAT_MAGIC_64 (big-endian) = 0xcafebabf
FAT_MAGIC = 0xCAFEBABF
N = 2
ALIGN = 14  # 2^14 = 16384
HDR = 8 + N * 32  # fat_header(8) + 2 * fat_arch_64(32)


def align_up(v, a):
    return (v + a - 1) // a * a


off1 = align_up(HDR, 1 << ALIGN)
off2 = align_up(off1 + len(a), 1 << ALIGN)

hdr = struct.pack(">II", FAT_MAGIC, N)
# fat_arch_64: cputype, cpusubtype, offset, size, align, reserved
hdr += struct.pack(">IIQQII", 0x0100000C, 0x00000000, off1, len(a), ALIGN, 0)  # arm64
hdr += struct.pack(">IIQQII", 0x0100000C, 0x80000002, off2, len(b), ALIGN, 0)  # arm64e

buf = bytearray()
buf += hdr
buf += b"\x00" * (off1 - len(buf))
buf += a
buf += b"\x00" * (off2 - len(buf))
buf += b

out_path.write_bytes(bytes(buf))

print(f"  ✓ {out_path.name}: {len(buf)} bytes")
print(f"    arm64  @ {off1}  ({len(a)} bytes)")
print(f"    arm64e @ {off2}  ({len(b)} bytes)")
