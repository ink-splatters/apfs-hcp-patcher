# apfs-hcp-patcher

Normally, Apple forbids snapshot delta restores to hardware-encrypted volumes.

That is, if target is on internal disk, this command:

```bash
# Should now work on HCP volumes:
sudo asr restore --source disk5s1 --target disk3s6 --erase --fromSnapshot <name> --toSnapshot <name>
```

will fail and add the following log entry:

```
2025-11-30 01:59:10.581419+0100 0x7751b    Default     0x0                  0      0    kernel: (apfs) delta_restore_verify_compatibility:4640: disk3s6 Snapshot delta restore not supported on HCP volumes
```

This tool patches the check in `_delta_restore_verify_compatibility` (APFS.kext), enabling the discussed
functionality.

## Preqrequisites

- [uv](https://docs.astral.sh/uv/)
- [ipsw](https://github.com/blacktop/ipsw)
- KDK (download from https://developer.apple.com for your system)
- SIP off

## Usage

NOTE: if you have multiple macOS installations, find the one currently running using `diskutil apfs listVolumeGroups`)

```sh
❯ VGUUID=$(diskutil apfs listVolumeGroups -plist | xmllint --xpath "//key[text()='APFSVolumeGroupUUID']/following-sibling::string[1]/text()")
❯ ipsw kernel dec /System/Volumes/Preboot/$VGUUID/boot/**/kernelcache -o kernelcache.decompressed

# TODO...

```
