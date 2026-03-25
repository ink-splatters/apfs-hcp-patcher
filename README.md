# apfs-hcp-patcher

APFS supports snapshot delta restores<sup>1</sup>.

Apple forbids snapshot delta restores to hardware-encrypted (HCP) volumes.

That is: if the target is on internal disk, the command below will fail:

```bash
sudo asr restore --source disk5s1 --target disk3s6 --erase --fromSnapshot <name> --toSnapshot <name>
```

...producing the following log entry:

```
2025-11-30 01:59:10.581419+0100 0x7751b    Default     0x0                  0      0    kernel: (apfs) delta_restore_verify_compatibility:4640: disk3s6 Snapshot delta restore not supported on HCP volumes
```

### Remedy

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

**NOTE**: the addresses above are from the APFS fileset entry inside `kernelcache.decompressed` on `macOS 26.2 (25C56)`

## Usage

### Decompress kernelcache

```sh
VGUUID=$(diskutil info -plist / | plutil -extract APFSVolumeGroupID raw -)
ipsw kernel dec /System/Volumes/Preboot/$VGUUID/boot/**/kernelcache -o .
```

### Patch `kernelcache.decompressed`

```sh
uvx "git+https://github.com/ink-splatters/apfs-hcp-patcher" kernelcache.decompressed
```

### Install kernelcache.decompressed.patched

From 1TR (paired recovery OS):

```sh
kmutil configure-boot --custom-boot-object <path>/kernelcache.decompressed.patched --compress --volume <System Volume mount>
```

- Reboot
- Enjoy!

## License

[MIT](./LICENSE)

## Credits

- Apple for macOS
- [@blacktop](https://github.com/blacktop) for [ipsw](https://github.com/blacktop/ipsw)
