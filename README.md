# apfs-hcp-patcher

APFS supports snapshot delta restores. See `man 8 asr` for details.

Normally, Apple forbids snapshot delta restores to hardware-encrypted (HCP) volumes.

That is: if target is on internal disk, this command:

```bash
# Should now work on HCP volumes:
sudo asr restore --source disk5s1 --target disk3s6 --erase --fromSnapshot <name> --toSnapshot <name>
```

will fail, producing the following log entry:

```
2025-11-30 01:59:10.581419+0100 0x7751b    Default     0x0                  0      0    kernel: (apfs) delta_restore_verify_compatibility:4640: disk3s6 Snapshot delta restore not supported on HCP volumes
```

This tool patches the check in `_delta_restore_verify_compatibility` (APFS.kext), enabling snapshot
delta restores to hardware-encrypted (HCP) volumes.

_WARNING_: this tool will put your system in _Permissive Security_ mode.

## Preqrequisites

- [uv](https://docs.astral.sh/uv/)
- [ipsw](https://github.com/blacktop/ipsw)
- KDK (download from https://developer.apple.com for your system)
- SIP off

## Usage

### Patch

NOTE: if you have multiple macOS installations, find the one currently running using `diskutil apfs listVolumeGroups`)

```sh
VGUUID=$(diskutil apfs listVolumeGroups -plist | xmllint --xpath "//key[text()='APFSVolumeGroupUUID']/following-sibling::string[1]/text()" - )
SOC=$( uname -v | sed -E 's/^.+RELEASE_ARM64_(.+)$/\1/g')
ipsw kernel dec /System/Volumes/Preboot/$VGUUID/boot/**/kernelcache -o .
ipsw kernel extract kernelcache.decompressed com.apple.filesystems.apfs
uvx --with lief "git+https://github.com/ink-splatters/apfs-hcp-patcher" com.apple.filesystems.apfs
```

_NOTE_: it's possible to patch `kernelcache.decompressed` directly and skip \[Build kernelcache\](#Build kernelcache) section completely by using `--dumb` mode

Caveat is that, living up to its name, the tool doesn't know anything about what it's gonna patch.

Despite the signature is unique enough and probability of invalid patch is quite low, use at your own risk:

```sh
uvx --with lief "git+https://github.com/ink-splatters/apfs-hcp-patcher" --dumb kernelcache.decompressed
```

### Build kernelcache

Locate installed KDK at `/Library/Developer/KDKs`, locate APFS kext bundle and replace the Mach-O with
`com.apple.filesystems.apfs.patched` and create patched kernelcache:

```sh
sudo mkdir -p /Library/KernelCollections
sudo /usr/bin/kmutil create \
    -n boot \
    -a arm64e \
    -V release \
    -B /Library/KernelCollections/kc.patched \
    -V release \
    -k /System/Library/Kernels/kernel.release.$SOC \
    -x $( kmutil inspect -V release --no-header | awk ' { print " -b "$1; }' )
```

### Install kernelcache

Boot to 1TR (paired recovery OS):

1. Shutdown the system
1. Wait a few seconds
1. Press Power button one time and hold until invitation to Boot Menu ("Loading \<...>")
1. Select Recovery OS
1. Unlock your Data volume (if FileVault is enabled)
1. Run:

```sh
kmutil configure-boot --custom-boot-object <Data Volume>/Library/KernelCollections/kc.patched --compress --volume <System Volume mount>
```

confirm all the prompts with "yes" / enter your password when asked

7. Reboot
1. Enjoy
