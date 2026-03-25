# apfs-hcp-patcher

APFS supports snapshot delta restores<sup>1</sup>. Normally, Apple forbids snapshot delta restores to hardware-encrypted (HCP) volumes.

That is: if the target is on an internal disk, this command:

```bash
sudo asr restore --source disk5s1 --target disk3s6 --erase --fromSnapshot <name> --toSnapshot <name>
```

will fail, producing the following log entry:

```
2025-11-30 01:59:10.581419+0100 0x7751b    Default     0x0                  0      0    kernel: (apfs) delta_restore_verify_compatibility:4640: disk3s6 Snapshot delta restore not supported on HCP volumes
```

This tool patches the check in `_delta_restore_verify_compatibility` in `APFS.kext`, enabling snapshot
delta restores to hardware-encrypted (HCP) volumes.

______________________________________________________________________

<sup>1</sup> see `man 8 asr` for details.

## Prerequisites

- Apple Silicon
- [uv](https://docs.astral.sh/uv/)
- [ipsw](https://github.com/blacktop/ipsw)

## How it works

```com.apple.filesystems.apfs.disass
  ...
  _delta_restore_verify_compatibility:
  ...
  0xfffffe000b992bc4:  88 0a 40 b9   ldr  w8, [x20, #0x8]    ; load encryption type
  0xfffffe000b992bc8:  1f 0d 00 71   cmp  w8, #0x3           ; check if it's HCP type (3)
- 0xfffffe000b992bcc:  81 fd ff 54   b.ne 0xfffffe000b992b7c ; proceed if it's not the case
+ 0xfffffe000b992bcc:  ec ff ff 17   b    0xfffffe000b992b7c ; proceed regardless
  ...
```

_NOTE_: the addresses above are from the APFS fileset entry inside `kernelcache.decompressed` on `macOS 26.2 (25C56)`

## Usage

### Patch `kernelcache.decompressed`

NOTE: if you have multiple macOS installations, find the one currently running using `diskutil apfs listVolumeGroups`

```sh
VGUUID=$(diskutil apfs listVolumeGroups -plist | xmllint --xpath "//key[text()='APFSVolumeGroupUUID']/following-sibling::string[1]/text()" -)
ipsw kernel dec /System/Volumes/Preboot/$VGUUID/boot/**/kernelcache -o .
uvx "git+https://github.com/ink-splatters/apfs-hcp-patcher" kernelcache.decompressed
```

This patches the `com.apple.filesystems.apfs` fileset entry inside the
decompressed kernelcache and writes `kernelcache.decompressed.patched`.

### Install patched kernelcache

Boot to 1TR (paired recovery OS):

- Shut down the system and wait for a few seconds
- Press and hold the Power button until `Loading...` appears. **Make sure you don't double-press**
- Select Recovery OS
- Unlock your Data volume (if FileVault is enabled)
- Run:

```sh
kmutil configure-boot --custom-boot-object <path>/kernelcache.decompressed.patched --compress --volume <System Volume mount>
```

You will be warned that this operation will put your system in Permissive Security mode.

Confirm all the prompts with "yes" / enter your password when asked.

- Reboot
- Enjoy!

## Troubleshooting

### Cannot change boot policy in Recovery OS

You are trying to install kernelcache from "regular" RecoveryOS and not 1TR - paired one. Make sure you followed the first steps from
[Install kernelcache](#install-kernelcache) precisely.

If the problem persists - the copy of RecoveryOS from APFS Container with your system is broken.

Solutions:

- reinstall macOS
- DIY: use [Asahi Linux Installer](https://github.com/AsahiLinux/asahi-installer/blob/main/src/stub.py) code which among other things, creates Recovery volume for their stub. Disclaimer: you are on your own. Do backups and hope for the best but get prepared for DFU restore.

## License

[MIT](./LICENSE)

## Credits

- [@blacktop](https://github.com/blacktop) for [ipsw](https://github.com/blacktop/ipsw)
- @marcan42 and [Asahi Linux](https://asahilinux.org) team for [Asahi Linux Installer](https://github.com/AsahiLinux/asahi-installer)
