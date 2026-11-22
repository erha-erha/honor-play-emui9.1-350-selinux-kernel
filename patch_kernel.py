#!/usr/bin/env python3
"""
Deterministic 212-byte ARM64 binary patcher for the stock Honor Play (COR-AL10)
EMUI 9.1.0.350 (Linux 4.9.148, built 2021-04-15) kernel image.

Unlocks runtime SELinux mode toggling (`setenforce 0` / `setenforce 1`) while
booting safely in Enforcing mode and leaving all stock drivers (Hi1102 Wi-Fi,
camera ISP, FBE crypto, GPU/CPU governors) completely untouched.
"""

import argparse
import gzip
import hashlib
import struct
import sys
from pathlib import Path

# Static kernel virtual address base (_text)
TEXT_ADDR = 0xFFFFFF8008080000

# Writable .data slot (before __mmuoff_data_start @ 0x2788000, outside RO/BSS)
MY_ENF_VA = 0xFFFFFF800A807F00
MY_ENF_PAGE = MY_ENF_VA & ~0xFFF
MY_ENF_OFF = MY_ENF_VA & 0xFFF

# Permanent RX .text code cave (outside Huawei TEE CFC area @ 0x1580000)
CAVE_AVC_VA = 0xFFFFFF80095F0000
CAVE_READ_VA = 0xFFFFFF80095F0020
CAVE_CFI_VA = 0xFFFFFF80095F0040
CAVE_WR_VA = 0xFFFFFF80095F0044

# Hook sites inside stock 9.1.0.350 kernel
AVC_HOOK_VA = 0xFFFFFF800843880C   # avc_denied.isra.7 + 0x2c
AVC_GRANT_VA = 0xFFFFFF8008438810  # avc_denied.isra.7 + 0x30 (grant path)
AVC_DENY_VA = 0xFFFFFF800843884C   # avc_denied.isra.7 + 0x6c (return -EACCES)
READ_HOOK_VA = 0xFFFFFF8008443A30  # sel_read_enforce + 0x30 (mov w3, #1)
READ_CONT_VA = 0xFFFFFF8008443A34  # sel_read_enforce + 0x34

# Existing kernel helpers in stock 9.1.0.350 Image
FN_KSTRTOL_USER = 0xFFFFFF80084F7504  # kstrtol_from_user
FN_TASK_HAS_SEC = 0xFFFFFF8008443808  # task_has_security
FN_AVC_SS_RESET = 0xFFFFFF8008438BA4  # avc_ss_reset
FN_SELNL_NOTIFY = 0xFFFFFF8008446468  # selnl_notify_setenforce
FN_STATUS_UPD = 0xFFFFFF8008456C80    # selinux_status_update_setenforce

# Empty R_AARCH64_NONE slot inside [__rela_offset, __rela_offset + __rela_size)
RELA_SLOT_FO = 0x229D808
SEL_ENF_WR_PTR = 0xFFFFFF80096D0C80   # sel_enforce_ops + 0x18 (.write)
HUAWEI_CFI_TAG = 0x0035C000
R_AARCH64_RELATIVE = 0x403
SECURITY_SETENFORCE = 0x80
PARTITION_SIZE = 25165824  # 24 MiB


def enc_b(pc: int, target: int) -> int:
    diff = target - pc
    assert diff % 4 == 0 and -(1 << 27) <= diff < (1 << 27), f"b out of range: {hex(diff)}"
    return 0x14000000 | ((diff >> 2) & 0x03FFFFFF)


def enc_bl(pc: int, target: int) -> int:
    diff = target - pc
    assert diff % 4 == 0 and -(1 << 27) <= diff < (1 << 27), f"bl out of range: {hex(diff)}"
    return 0x94000000 | ((diff >> 2) & 0x03FFFFFF)


def enc_adrp(pc: int, target_page: int, rd: int) -> int:
    assert (target_page & 0xFFF) == 0
    delta_pages = (target_page - (pc & ~0xFFF)) >> 12
    assert -(1 << 20) <= delta_pages < (1 << 20), f"adrp out of range: {delta_pages}"
    imm = delta_pages & 0x1FFFFF
    return 0x90000000 | ((imm & 0x3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | (rd & 31)


def enc_add_imm64(rd: int, rn: int, imm12: int) -> int:
    assert 0 <= imm12 < 4096
    return 0x91000000 | (imm12 << 10) | ((rn & 31) << 5) | (rd & 31)


def enc_ldr_uimm32(rt: int, rn: int, offset: int) -> int:
    assert offset % 4 == 0 and 0 <= offset < 16384
    return 0xB9400000 | ((offset // 4) << 10) | ((rn & 31) << 5) | (rt & 31)


def enc_str_uimm32(rt: int, rn: int, offset: int) -> int:
    assert offset % 4 == 0 and 0 <= offset < 16384
    return 0xB9000000 | ((offset // 4) << 10) | ((rn & 31) << 5) | (rt & 31)


def enc_ldr_uimm64(rt: int, rn: int, offset: int) -> int:
    assert offset % 8 == 0 and 0 <= offset < 32768
    return 0xF9400000 | ((offset // 8) << 10) | ((rn & 31) << 5) | (rt & 31)


def enc_str_uimm64(rt: int, rn: int, offset: int) -> int:
    assert offset % 8 == 0 and 0 <= offset < 32768
    return 0xF9000000 | ((offset // 8) << 10) | ((rn & 31) << 5) | (rt & 31)


def enc_tbnz(rt: int, bit: int, pc: int, target: int) -> int:
    diff = target - pc
    assert diff % 4 == 0 and -(1 << 15) <= diff < (1 << 15)
    b5 = (bit >> 5) & 1
    b40 = bit & 31
    imm14 = (diff >> 2) & 0x3FFF
    return 0x37000000 | (b5 << 31) | (b40 << 19) | (imm14 << 5) | (rt & 31)


def enc_cbz(is64: bool, rt: int, pc: int, target: int) -> int:
    diff = target - pc
    assert diff % 4 == 0 and -(1 << 20) <= diff < (1 << 20)
    imm19 = (diff >> 2) & 0x7FFFF
    return (0xB4000000 if is64 else 0x34000000) | (imm19 << 5) | (rt & 31)


def enc_cbnz(is64: bool, rt: int, pc: int, target: int) -> int:
    diff = target - pc
    assert diff % 4 == 0 and -(1 << 20) <= diff < (1 << 20)
    imm19 = (diff >> 2) & 0x7FFFF
    return (0xB5000000 if is64 else 0x35000000) | (imm19 << 5) | (rt & 31)


def enc_b_cond(cond: int, pc: int, target: int) -> int:
    diff = target - pc
    assert diff % 4 == 0 and -(1 << 20) <= diff < (1 << 20)
    imm19 = (diff >> 2) & 0x7FFFF
    return 0x54000000 | (imm19 << 5) | (cond & 0xF)


def enc_stp_pre64(rt1: int, rt2: int, rn: int, imm_signed: int) -> int:
    assert imm_signed % 8 == 0 and -512 <= imm_signed <= 504
    imm7 = (imm_signed // 8) & 0x7F
    return 0xA9800000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt1 & 31)


def enc_stp_off64(rt1: int, rt2: int, rn: int, imm_signed: int) -> int:
    assert imm_signed % 8 == 0 and -512 <= imm_signed <= 504
    imm7 = (imm_signed // 8) & 0x7F
    return 0xA9000000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt1 & 31)


def enc_ldp_off64(rt1: int, rt2: int, rn: int, imm_signed: int) -> int:
    assert imm_signed % 8 == 0 and -512 <= imm_signed <= 504
    imm7 = (imm_signed // 8) & 0x7F
    return 0xA9400000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt1 & 31)


def enc_ldp_post64(rt1: int, rt2: int, rn: int, imm_signed: int) -> int:
    assert imm_signed % 8 == 0 and -512 <= imm_signed <= 504
    imm7 = (imm_signed // 8) & 0x7F
    return 0xA8C00000 | (imm7 << 15) | ((rt2 & 31) << 10) | ((rn & 31) << 5) | (rt1 & 31)


def enc_mov_reg64(rd: int, rm: int) -> int:
    return 0xAA0003E0 | ((rm & 31) << 16) | (rd & 31)


def enc_mov_reg32(rd: int, rm: int) -> int:
    return 0x2A0003E0 | ((rm & 31) << 16) | (rd & 31)


def enc_movz32(rd: int, imm16: int) -> int:
    return 0x52800000 | ((imm16 & 0xFFFF) << 5) | (rd & 31)


def enc_movn64(rd: int, not_val: int) -> int:
    return 0x92800000 | ((not_val & 0xFFFF) << 5) | (rd & 31)


def enc_cmp_imm64(rn: int, imm12: int) -> int:
    return 0xF100001F | ((imm12 & 0xFFF) << 10) | ((rn & 31) << 5)


def enc_cmp_reg32(rn: int, rm: int) -> int:
    return 0x6B00001F | ((rm & 31) << 16) | ((rn & 31) << 5)


def enc_cset32(rd: int, cond: int) -> int:
    return 0x1A9F07E0 | (((cond ^ 1) & 0xF) << 12) | (rd & 31)


def enc_sxtw(rd: int, rn: int) -> int:
    return 0x93407C00 | ((rn & 31) << 5) | (rd & 31)


def patch_image(raw_bootimg: bytes, verify_disasm: bool = False) -> tuple[bytes, bytes]:
    if raw_bootimg[:8] != b"ANDROID!":
        raise ValueError("Input file is not a valid Android boot image (missing ANDROID! magic)")

    ksize = struct.unpack_from("<I", raw_bootimg, 8)[0]
    psize = struct.unpack_from("<I", raw_bootimg, 36)[0]
    hver = struct.unpack_from("<I", raw_bootimg, 40)[0]
    if psize != 2048 or hver != 1:
        raise ValueError(f"Unexpected boot header (pagesize={psize}, header_version={hver})")

    orig_img = gzip.decompress(raw_bootimg[psize : psize + ksize])
    if len(orig_img) != 41453576:
        raise ValueError(
            f"Unexpected uncompressed kernel Image size ({len(orig_img)} != 41453576). "
            "Make sure input is the exact COR-AL10 9.1.0.350 (2021-04-15) stock kernel."
        )

    img = bytearray(orig_img)

    def put32(va: int, word: int) -> None:
        struct.pack_into("<I", img, va - TEXT_ADDR, word)

    # Strict pre-patch invariants to prevent patching the wrong build
    assert struct.unpack_from("<I", img, AVC_HOOK_VA - TEXT_ADDR)[0] == 0x36000200, "avc_denied mismatch"
    assert struct.unpack_from("<I", img, READ_HOOK_VA - TEXT_ADDR)[0] == 0x52800023, "sel_read_enforce mismatch"
    assert img[CAVE_AVC_VA - TEXT_ADDR : CAVE_AVC_VA - TEXT_ADDR + 0x200] == b"\x00" * 0x200, "code cave not empty"
    assert img[MY_ENF_VA - TEXT_ADDR : MY_ENF_VA - TEXT_ADDR + 16] == b"\x00" * 16, "data slot not empty"
    assert img[RELA_SLOT_FO : RELA_SLOT_FO + 24] == b"\x00" * 24, "RELA slot not empty"

    # 1. Initialize my_selinux_enforcing = 1 (boot in Enforcing mode for FBE safety)
    struct.pack_into("<I", img, MY_ENF_VA - TEXT_ADDR, 1)

    # 2. Hook avc_denied.isra.7 + 0x2c -> trampoline_avc_denied
    put32(AVC_HOOK_VA, enc_b(AVC_HOOK_VA, CAVE_AVC_VA))
    for va, word in [
        (CAVE_AVC_VA + 0x00, enc_tbnz(0, 0, CAVE_AVC_VA + 0x00, CAVE_AVC_VA + 0x10)),
        (CAVE_AVC_VA + 0x04, enc_adrp(CAVE_AVC_VA + 0x04, MY_ENF_PAGE, 0)),
        (CAVE_AVC_VA + 0x08, enc_ldr_uimm32(0, 0, MY_ENF_OFF)),
        (CAVE_AVC_VA + 0x0C, enc_cbnz(False, 0, CAVE_AVC_VA + 0x0C, CAVE_AVC_VA + 0x14)),
        (CAVE_AVC_VA + 0x10, enc_b(CAVE_AVC_VA + 0x10, AVC_GRANT_VA)),
        (CAVE_AVC_VA + 0x14, enc_b(CAVE_AVC_VA + 0x14, AVC_DENY_VA)),
    ]:
        put32(va, word)

    # 3. Hook sel_read_enforce + 0x30 -> trampoline_read_enforce
    put32(READ_HOOK_VA, enc_b(READ_HOOK_VA, CAVE_READ_VA))
    for va, word in [
        (CAVE_READ_VA + 0x00, enc_adrp(CAVE_READ_VA + 0x00, MY_ENF_PAGE, 3)),
        (CAVE_READ_VA + 0x04, enc_ldr_uimm32(3, 3, MY_ENF_OFF)),
        (CAVE_READ_VA + 0x08, enc_b(CAVE_READ_VA + 0x08, READ_CONT_VA)),
    ]:
        put32(va, word)

    # 4. Write Huawei CFI tag + my_sel_write_enforce handler
    put32(CAVE_CFI_VA, HUAWEI_CFI_TAG)

    l_skip_reset = CAVE_WR_VA + 0x84
    l_ret_count = CAVE_WR_VA + 0x94
    l_ret_einval = CAVE_WR_VA + 0x9C
    l_ret_err = CAVE_WR_VA + 0xA4
    l_epilogue = CAVE_WR_VA + 0xA8

    wr_insns = [
        (CAVE_WR_VA + 0x00, enc_stp_pre64(29, 30, 31, -0x40)),
        (CAVE_WR_VA + 0x04, enc_add_imm64(29, 31, 0)),
        (CAVE_WR_VA + 0x08, enc_stp_off64(19, 20, 31, 0x10)),
        (CAVE_WR_VA + 0x0C, enc_str_uimm64(21, 31, 0x20)),
        (CAVE_WR_VA + 0x10, enc_mov_reg64(19, 2)),
        (CAVE_WR_VA + 0x14, enc_cbz(True, 19, CAVE_WR_VA + 0x14, l_ret_einval)),
        (CAVE_WR_VA + 0x18, enc_cmp_imm64(19, 0xFFF)),
        (CAVE_WR_VA + 0x1C, enc_b_cond(0x8, CAVE_WR_VA + 0x1C, l_ret_einval)),
        (CAVE_WR_VA + 0x20, enc_ldr_uimm64(4, 3, 0)),
        (CAVE_WR_VA + 0x24, enc_cbnz(True, 4, CAVE_WR_VA + 0x24, l_ret_einval)),
        (CAVE_WR_VA + 0x28, enc_mov_reg64(0, 1)),
        (CAVE_WR_VA + 0x2C, enc_mov_reg64(1, 19)),
        (CAVE_WR_VA + 0x30, enc_movz32(2, 0)),
        (CAVE_WR_VA + 0x34, enc_add_imm64(3, 31, 0x30)),
        (CAVE_WR_VA + 0x38, enc_bl(CAVE_WR_VA + 0x38, FN_KSTRTOL_USER)),
        (CAVE_WR_VA + 0x3C, enc_cbnz(False, 0, CAVE_WR_VA + 0x3C, l_ret_err)),
        (CAVE_WR_VA + 0x40, enc_ldr_uimm64(0, 31, 0x30)),
        (CAVE_WR_VA + 0x44, enc_cmp_imm64(0, 0)),
        (CAVE_WR_VA + 0x48, enc_cset32(20, 0x1)),
        (CAVE_WR_VA + 0x4C, enc_adrp(CAVE_WR_VA + 0x4C, MY_ENF_PAGE, 21)),
        (CAVE_WR_VA + 0x50, enc_add_imm64(21, 21, MY_ENF_OFF)),
        (CAVE_WR_VA + 0x54, enc_ldr_uimm32(0, 21, 0)),
        (CAVE_WR_VA + 0x58, enc_cmp_reg32(20, 0)),
        (CAVE_WR_VA + 0x5C, enc_b_cond(0x0, CAVE_WR_VA + 0x5C, l_ret_count)),
        (CAVE_WR_VA + 0x60, 0xD5384100),  # mrs x0, sp_el0
        (CAVE_WR_VA + 0x64, enc_movz32(1, SECURITY_SETENFORCE)),
        (CAVE_WR_VA + 0x68, enc_bl(CAVE_WR_VA + 0x68, FN_TASK_HAS_SEC)),
        (CAVE_WR_VA + 0x6C, enc_cbnz(False, 0, CAVE_WR_VA + 0x6C, l_ret_err)),
        (CAVE_WR_VA + 0x70, enc_str_uimm32(20, 21, 0)),
        (CAVE_WR_VA + 0x74, 0xD5033ABF),  # dmb ishst
        (CAVE_WR_VA + 0x78, enc_cbz(False, 20, CAVE_WR_VA + 0x78, l_skip_reset)),
        (CAVE_WR_VA + 0x7C, enc_movz32(0, 0)),
        (CAVE_WR_VA + 0x80, enc_bl(CAVE_WR_VA + 0x80, FN_AVC_SS_RESET)),
        (CAVE_WR_VA + 0x84, enc_mov_reg32(0, 20)),
        (CAVE_WR_VA + 0x88, enc_bl(CAVE_WR_VA + 0x88, FN_SELNL_NOTIFY)),
        (CAVE_WR_VA + 0x8C, enc_mov_reg32(0, 20)),
        (CAVE_WR_VA + 0x90, enc_bl(CAVE_WR_VA + 0x90, FN_STATUS_UPD)),
        (CAVE_WR_VA + 0x94, enc_mov_reg64(0, 19)),
        (CAVE_WR_VA + 0x98, enc_b(CAVE_WR_VA + 0x98, l_epilogue)),
        (CAVE_WR_VA + 0x9C, enc_movn64(0, 0x15)),  # -EINVAL (-22)
        (CAVE_WR_VA + 0xA0, enc_b(CAVE_WR_VA + 0xA0, l_epilogue)),
        (CAVE_WR_VA + 0xA4, enc_sxtw(0, 0)),
        (CAVE_WR_VA + 0xA8, enc_ldr_uimm64(21, 31, 0x20)),
        (CAVE_WR_VA + 0xAC, enc_ldp_off64(19, 20, 31, 0x10)),
        (CAVE_WR_VA + 0xB0, enc_ldp_post64(29, 30, 31, 0x40)),
        (CAVE_WR_VA + 0xB4, 0xD65F03C0),  # ret
    ]
    for va, word in wr_insns:
        put32(va, word)

    # 5. Register sel_enforce_ops.write in KASLR .rela table
    struct.pack_into("<QQQ", img, RELA_SLOT_FO, SEL_ENF_WR_PTR, R_AARCH64_RELATIVE, CAVE_WR_VA)

    changed = sum(1 for a, b in zip(orig_img, img) if a != b)
    assert changed == 212, f"Expected exactly 212 modified bytes, got {changed}"

    if verify_disasm:
        try:
            import capstone

            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            print("=== Disassembly Audit ===")
            for label, va, sz in [
                ("trampoline_avc_denied", CAVE_AVC_VA, 0x18),
                ("trampoline_read_enforce", CAVE_READ_VA, 0x0C),
                ("my_sel_write_enforce", CAVE_WR_VA, 0xB8),
            ]:
                print(f"\n[{label} @ 0x{va:016x}]")
                for insn in md.disasm(bytes(img[va - TEXT_ADDR : va - TEXT_ADDR + sz]), va):
                    print(f"  0x{insn.address:x}: {insn.mnemonic:8s} {insn.op_str}")
        except ImportError:
            print("Note: capstone not installed; skipping disassembly audit.", file=sys.stderr)

    # Repack Android Boot Image v1 preserving exact stock header & os_patch_level
    gz_data = gzip.compress(bytes(img), compresslevel=9, mtime=0)
    hdr = bytearray(raw_bootimg[:psize])
    struct.pack_into("<I", hdr, 8, len(gz_data))

    sha1 = hashlib.sha1()
    sha1.update(gz_data)
    sha1.update(struct.pack("<I", len(gz_data)))
    for _ in range(3):  # empty ramdisk, second, recovery_dtbo
        sha1.update(struct.pack("<I", 0))
    hdr[576:608] = sha1.digest() + b"\x00" * 12

    padded_klen = ((len(gz_data) + psize - 1) // psize) * psize
    bootimg = bytes(hdr) + gz_data + b"\x00" * (padded_klen - len(gz_data))
    if len(bootimg) > PARTITION_SIZE:
        raise ValueError(f"Repacked boot image ({len(bootimg)} bytes) exceeds 24 MiB kernel partition")

    padded_24m = bootimg + b"\x00" * (PARTITION_SIZE - len(bootimg))
    return bootimg, padded_24m


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patch stock Honor Play (COR-AL10) EMUI 9.1.0.350 kernel to unlock SELinux Permissive mode."
    )
    parser.add_argument("-i", "--input", required=True, type=Path, help="Path to stock_kernel_350.img")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Output path for patched kernel .img")
    parser.add_argument("--padded-24m", type=Path, help="Optional output path for zero-padded 24 MiB raw dd image")
    parser.add_argument("--disasm", action="store_true", help="Print Capstone ARM64 disassembly audit")
    args = parser.parse_args()

    raw = args.input.read_bytes()
    bootimg, padded_24m = patch_image(raw, verify_disasm=args.disasm)

    args.output.write_bytes(bootimg)
    print(f"Wrote patched boot image: {args.output} ({len(bootimg)} bytes)")
    print(f"SHA-256: {hashlib.sha256(bootimg).hexdigest()}")

    if args.padded_24m:
        args.padded_24m.write_bytes(padded_24m)
        print(f"Wrote 24 MiB padded image: {args.padded_24m} ({len(padded_24m)} bytes)")
        print(f"24 MiB SHA-256: {hashlib.sha256(padded_24m).hexdigest()}")


if __name__ == "__main__":
    main()
