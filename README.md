# Honor Play (COR-AL10) EMUI 9.1.0.350 SELinux-Unlocked Stock Kernel

A minimal **212-byte ARM64 binary patch** applied directly to the stock **EMUI 9.1.0.350 (`C00E440R1P2`)** kernel (`Linux 4.9.148`, Kirin 970) for the **Honor Play (`COR-AL10`)**.

It unlocks runtime SELinux mode switching (`setenforce 0` / `setenforce 1`) while keeping **100% of the stock 9.1.0.350 drivers intact** — no system downgrade, no data wipe, full encrypted Wi-Fi (WPA2-PSK/CCMP) support, stock camera ISP, and full Magisk compatibility.

---

## Why This Exists

Huawei only published Kirin 970 EMUI 9.1 open-source kernel code for the older **`9.1.0.312`** build. Flashing any `312`-based custom kernel (e.g. Dispossible / KernelSU builds) onto a newer **`9.1.0.350`** system causes a Wi-Fi HAL / Hi1102 firmware mismatch:

- Open networks may connect, but **all WPA2-PSK encrypted Wi-Fi networks fail during the 4-way handshake** (`reason=15`, reported by Android as *"Incorrect password"*).
- Camera secure ISP initialization (`secisp_device_enable`) can also throw errors across builds.

Instead of downgrading the entire system to `9.1.0.312` (which wipes userdata) or reverse-engineering hundreds of Hi1102 driver files, this project patches **only 212 bytes** of the genuine stock `9.1.0.350` kernel binary to restore `CONFIG_SECURITY_SELINUX_DEVELOP` behavior cleanly.

---

## Target Firmware & Compatibility

- **Device**: Honor Play (`COR-AL10`, Kirin 970, `HWCOR`)
- **Stock OS**: EMUI `9.1.0.350(C00E440R1P2)` (base display ID `9.1.0.346`, security patch `2021-03-01`, boot header `os_patch_level=2020-10`)
- **Stock Kernel**: `Linux version 4.9.148 (android@localhost) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Thu Apr 15 02:23:51 CST 2021`
- **Stock `kernel` Partition SHA-256 (24 MB dump)**:
  `353eac389156f8fa2934e0a19211559e52494c5e1296256038fb9552ec3d3363`
- **Bootloader**: Must be unlocked (`bootlock=unlocked`).
- **Root / Encryption**: Tested with stock FBE hardware-encrypted `/data` (`f2fs`, `verify_encrypt,inline_encrypt,sdp_encrypt`) and **Magisk 27.0** installed in `recovery_ramdisk`.

> **Warning**: The binary patch uses hardcoded offsets specific to the exact `2021-04-15` `COR-AL10 9.1.0.350` stock kernel build listed above. Do **not** flash this image onto other firmware versions or models without verifying compatibility and backing up your stock `kernel` partition first.

---

## Technical Details (212-Byte Patch)

The stock `9.1.0.350` kernel is compiled with `CONFIG_SECURITY_SELINUX_DEVELOP=n`, `CONFIG_RELOCATABLE=y` (KASLR), `CONFIG_HUAWEI_CFI=y` (CFI tag `0x0035c000`), and `CONFIG_DEBUG_RODATA=y`.

The patch modifies 5 surgical sites inside the 41,453,576-byte uncompressed ARM64 `Image`:

| # | Component | Virtual Address (Static) | Purpose |
| :- | :--- | :--- | :--- |
| 1 | Writable state flag (`my_selinux_enforcing`) | `0xffffff800a807f00` (`.data` tail, before `__mmuoff_data_start`) | 4-byte `uint32_t` initialized to **`1`** so the device always boots in **Enforcing** mode to safely pass EMUI `/data` FBE decryption. |
| 2 | `avc_denied.isra.7` hook + trampoline | Hook: `0xffffff800843880c`<br>Cave: `0xffffff80095f0000` (`.text`, 64 KB before `__cfc_area_start`) | Checks `avd->flags & AVD_FLAGS_PERMISSIVE`; if unset, loads `my_selinux_enforcing` via PC-relative `adrp + ldr`. When `0`, branches to the native grant path (`avc_update_node(AVC_CALLBACK_GRANT)` + `return 0`). All four AVC paths (`avc_has_perm`, `avc_has_perm_noaudit`, `avc_has_perm_flags`, `avc_has_extended_perms`) route through `avc_denied.isra.7`. |
| 3 | `sel_read_enforce` hook + trampoline | Hook: `0xffffff8008443a30`<br>Cave: `0xffffff80095f0020` | Replaces hardcoded `mov w3, #1` with a PC-relative load of `my_selinux_enforcing` so `/sys/fs/selinux/enforce` and `getenforce` dynamically reflect `1` or `0`. |
| 4 | `my_sel_write_enforce` handler | CFI tag: `0xffffff80095f0040` (`0x0035c000`)<br>Entry: `0xffffff80095f0044` | Full `file_operations.write` handler: validates `count` and `*ppos`, parses userspace input via native `kstrtol_from_user`, enforces permission via `task_has_security(current, SECURITY__SETENFORCE=0x80)`, updates `my_selinux_enforcing` with `dmb ishst`, calls `avc_ss_reset(0)` when re-enabling Enforcing, and notifies userspace via `selnl_notify_setenforce` and `selinux_status_update_setenforce`. |
| 5 | KASLR `.rela` registration | File offset `0x229d808` (existing null `R_AARCH64_NONE` slot inside `[__rela_offset, __rela_offset + __rela_size)`) | Appends one `R_AARCH64_RELATIVE` (`0x403`) relocation pointing `sel_enforce_ops.write` (`0xffffff80096d0c80`, offset `+0x18`) to `0xffffff80095f0044`. Relocated natively by `__relocate_kernel` at boot regardless of KASLR slide. |

All original Android boot image v1 header fields (`header_version=1`, `pagesize=2048`, `os_version=9.0.0`, `os_patch_level=2020-10`, and stock `androidboot.selinux=enforcing` cmdline) are preserved identically, with only `kernel_size` and the header SHA-1 digest updated.

---

## Quick Start (Flashing Prebuilt Release)

### 1. Back up your stock `kernel` partition first (Mandatory)
From a rooted shell (`adb shell su`):
```sh
dd if=/dev/block/bootdevice/by-name/kernel of=/sdcard/stock_kernel_350.img bs=1048576
```
Pull `/sdcard/stock_kernel_350.img` to your PC and keep it safe.

### 2. Download the patched kernel image
Grab `cor-al10-9.1.0.350-kernel-selinux-enforcing.img` from [Releases](../../releases) and verify its SHA-256 against `SHA256SUMS.txt`.

### 3. Flash to the `kernel` partition
Via Fastboot (recommended):
```sh
fastboot flash kernel cor-al10-9.1.0.350-kernel-selinux-enforcing.img
fastboot reboot
```
*(Or via root `dd` directly to `/dev/block/bootdevice/by-name/kernel` after padding/clearing trailing bytes, followed by `sync && reboot`.)*

### 4. Switch to Permissive mode after booting
The device boots in **Enforcing** mode by default so EMUI encryption unlocks cleanly. Once booted:
```sh
su -c "setenforce 0"
su -c "getenforce"   # Outputs: Permissive
```

### 5. Optional: Auto-switch to Permissive on every boot (Magisk)
Copy [`scripts/99_selinux_permissive.sh`](scripts/99_selinux_permissive.sh) to `/data/adb/service.d/99_selinux_permissive.sh` and set executable permissions:
```sh
adb push scripts/99_selinux_permissive.sh /data/local/tmp/
adb shell su -c "cp /data/local/tmp/99_selinux_permissive.sh /data/adb/service.d/ && chmod 0755 /data/adb/service.d/99_selinux_permissive.sh && chown root:root /data/adb/service.d/99_selinux_permissive.sh"
```
The script waits until `sys.boot_completed=1` plus 3 seconds before running `setenforce 0`.

### Rollback / Recovery
If anything goes wrong, power off the device, hold **Volume Down (-)** while connecting USB to enter **Fastboot & Rescue Mode**, and restore your stock backup:
```sh
fastboot flash kernel stock_kernel_350.img
fastboot reboot
```

---

## Reproducing the Patch Locally

You can reproduce the exact patched kernel image from your own stock `kernel` partition dump using [`patch_kernel.py`](patch_kernel.py):

```bash
# Python 3.8+ (optional: `pip install capstone` for automatic disassembly audit)
python3 patch_kernel.py --input stock_kernel_350.img --output cor-al10-9.1.0.350-kernel-selinux-enforcing.img
```

The script strictly asserts every original instruction word, zero-filled cave/data/RELA slot, and outputs a deterministic Android boot image v1 file.

---

## Hardware Smoke Test Results

Verified on an actual **Honor Play (`COR-AL10`)** running stock **EMUI `9.1.0.350(C00E440R1P2)`** with FBE encryption and Magisk `27.0:MAGISK:R`:

- **Boot & Stability**: Clean cold boot, zero kernel panics / Oops / Huawei CFI violations.
- **SELinux Runtime Control**: Boots `Enforcing`, `setenforce 0` switches to `Permissive` and allows restricted debugfs access from non-root shell (`ls /sys/kernel/debug`), `setenforce 1` immediately restores enforcement, non-root writes to `/sys/fs/selinux/enforce` are rejected with `Permission denied`, and `init` receives all `setenforce` netlink notifications.
- **Encrypted Wi-Fi**: Connects cleanly to 5 GHz WPA2-PSK (CCMP) networks with zero TX data frame errors.
- **Camera & ISP**: Stock camera opens cleanly with active preview/capture streams and clean `hisp160` power-down (`0` `secisp` errors).
- **Other Subsystems**: Cellular/SIM, Bluetooth HAL, GNSS/GPS HAL daemons, Gyroscope/Magnetometer/Light/Proximity/Step sensors, Hi6403 audio, Fingerprint HAL, CPU/GPU (`gpu_scene_aware`) governors, USB charging, and F2FS encrypted storage all verified working.

---

## License & Disclaimer

- The patcher script (`patch_kernel.py`), helper script (`scripts/99_selinux_permissive.sh`), and documentation in this repository are released under the **MIT License**.
- The patched prebuilt kernel binary in Releases is a derivative of the Linux kernel (`4.9.148`, **GPL-2.0**) and stock Huawei Kirin 970 firmware kernel.
- **Disclaimer**: Flashing modified kernels carries inherent risk. Always back up your stock `kernel` partition and personal data before flashing. You proceed at your own responsibility.
