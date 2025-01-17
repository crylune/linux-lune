# linux-lune
This is a custom built Linux kernel focused on a balance of speed and security. It is based on `linux-zen` and has all kernel configurations and patches from `linux-hardened`, tailored for compatibility, with a few exceptions (see [Observations](https://github.com/crylune/linux-lune#observations)). It also includes my own configurations and improvements that are documented below.

I also offer patches from `linux-hardened` tailored to work with the latest version of `linux-zen`, dubbed `lune-hardened`.

# Why?
The main motive behind this was wanting to use the Zen and Hardened kernels at the same time. No one seemed to have provided such a custom kernel, and the ones I've found were all grossly outdated. Applying the Hardened patches on top of Zen does not work without code modification due to diff conflicts. It seemed easy to adapt the Hardened patches and kernel configurations to work with Zen's, and here we are.

# Attention
- This kernel is intended to be used with [Arch Linux](https://archlinux.org/), and the patches are intended to be applied and built with the [Arch Build System](https://wiki.archlinux.org/title/Kernel/Arch_build_system) (ABS).
- The security configuration in this kernel is very strict by default (confidentiality lockdown mode by default and intentionally having no `linux-lune-headers` for modules, which are omitted - sorry, NVIDIA users). Your desktop experience may be impacted by using this kernel, it is up to you to determine whether or not it aligns with your workflow.
- **I urge you to verify the authenticity of your downloaded files through SHA-256 checksums and the attached signatures, before utilising any of the files I provide, to protect against HTTP smuggling attacks.**

# List of changes in the kernel
- Based on `linux-zen` patches and configurations
- All patches and configurations from `linux-hardened`
- Full `usbctl` support imported from `linux-hardened` (see below)
- Various additional security configurations from the Kernel Self Protection Project, GrapheneOS, grsecurity, my own configurations, and more (see below)
- `vm.max_map_count` increased to `16777216` for best compatibility with memory intensive applications (especially some Wine/Proton Windows games)

## usbctl
Included in this kernel is full support for [usbctl](https://github.com/troglobit/usbctl), an utility designed for `linux-hardened` that gives you more control over USB devices plugged in to your PC.

The regular `usbctl` package will not install with `linux-lune`, as `linux-hardened` is its dependency, despite the Lune kernel having full support for it. To mitigate this, I have included precompiled, compatible tarballs of `usbctl` in the Releases section, that work with my kernel, if you wish to use this utility. Alternatively, you can clone the original and edit its PKGBUILD to remove `linux-hardened` as a dependency.

# Kernel usage and installation
For convenience, I provide a pre-made kernel tarball, targeting the Generic x86_64 architecture. It can be found under Releases, and it can simply be installed with:

`$ sudo pacman -U linux-lune-x.xx.xx.zen1-1-x86_64.pkg.tar.zst`

... then recreate the configuration for your bootloader of choice.

AUR package for this kernel is planned, however it is quite niche, so we will see. For now, update the kernel by checking back every once in a while and following the above steps. It is updated regularly.

## Patch file
The patch file is almost entirely the one from `linux-hardened`, with my changes being code compatibility with `linux-zen`. increased `vm.max_map_count` value, and configuring some features for security at the kernel level (see [Configurations](https://github.com/crylune/linux-lune#configurations) below).

If you wish to build your own kernel (for example to tailor it to your CPU's architecture), clone `linux-zen`, have the corresponding `lune-hardened-vx.xx.xx.patch` file in the `PKGBUILD`'s directory, and follow instructions from the ABS.

You are also required to download the complementary tarball dubbed `linux-lune-vx.xx.xxx-complementary.tar.zst` and extract it to your kernel's source tree in order for the compile to work, as it includes new files from `linux-hardened`, of which patches point to. Doing this will require the compilation to be done with the command `makepkg -si --skipinteg`, as the complementary files will obviously invalidate the integrity of the source.

Additionally, as in `linux-hardened`, you are required to comment out the following line from the `PKGBUILD`, as BPF is not really compatible with the fully randomized ASLR the kernel uses:

`# make -C tools/bpf/bpftool vmlinux.h feature-clang-bpf-co-re=1`

You are free to change anything about the kernel and make it your own, including the `config` file (I do recommend adding the configurations below), and the source code present on this page.

## Note
The patch file is only a part of `linux-hardened`. Its configurations are not handled by the patch file, and they are important and necessary. They are also included in my kernel tarball. However, if you wish to build your own, you will have to copy its configurations yourself and apply them to your own kernel.

Luckily, this is easy to do and always compatible. Making the `linux-hardened` patch file compatible with Zen patches is the hard part and I did that for you. You can use `meld` to compare the `config` files of `linux-zen` and `linux-hardened`, and apply the security improvements from the latter to the former.

# Configurations
On top of the configurations from `linux-hardened`, I have applied the following:

```
RETPOLINE=y
# USB_USBNET is not set
# DEVMEM is not set
PAGE_POISONING=y
GCC_PLUGIN_STACKLEAK=y
DM_CRYPT=y
# DEBUG_BUGVERBOSE is not set
ARCH_HAS_ELF_RANDOMIZE=y
INIT_ON_FREE_DEFAULT_ON=y
INIT_ON_ALLOC_DEFAULT_ON=y
DEBUG_VIRTUAL=y
INIT_STACK_ALL_ZERO=y
STACKPROTECTOR=y
STACKPROTECTOR_STRONG=y
SCHED_STACK_END_CHECK=y
# STACKLEAK_METRICS is not set
# STACKLEAK_RUNTIME_DISABLE is not set
GCC_PLUGIN_STACKLEAK=y
STRICT_KERNEL_RWX=y
SLAB_FREELIST_HARDENED=y
SLAB_FREELIST_RANDOM=y
# COMPAT_BRK is not set
# INET_DIAG is not set
HARDENED_USERCOPY=y
X86_UMIP=y
# PROC_PAGE_MONITOR is not set
# DEBUG_FS is not set
RANDOMIZE_BASE=y
RANDOMIZE_MEMORY=y
GCC_PLUGIN_RANDSTRUCT=y
# HIBERNATION is not set
# SUSPEND is not set
# ARCH_HIBERNATION_POSSIBLE is not set
# ARCH_SUSPEND_POSSIBLE is not set
# KEXEC is not set
# KEXEC_FILE is not set
STRICT_MODULE_RWX=y
MODULE_SIG=y
MODULE_SIG_ALL=y
MODULE_SIG_SHA512=y
MODULE_SIG_FORCE=y
SECCOMP=y
# USELIB is not set
# MODIFY_LDT_SYSCALL is not set
LEGACY_VSYSCALL_NONE=y
# X86_VSYSCALL_EMULATION is not set
SECURITY=y
SECURITY_YAMA=y
SECURITY_LOCKDOWN_LSM=y
SECURITY_LOCKDOWN_LSM_EARLY=y
LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y
LSM="landlock,lockdown,yama,confidentiality,apparmor,bpf"
SECURITY_SAFESETID=y
SECURITY_LOADPIN=y
SECURITY_LOADPIN_ENFORCE=y
INTEL_IOMMU_DEFAULT_ON=y
# CONFIG_SECURITY_SELINUX_BOOTPARAM is not set
# CONFIG_SECURITY_SELINUX_DEVELOP is not set
PAGE_TABLE_CHECK=y
PAGE_TABLE_CHECK_ENFORCED=y
# CONFIG_BINFMT_MISC is not set
EFI_DISABLE_PCI_DMA=y
# CONFIG_BLK_DEV_FD is not set
# CONFIG_ZSMALLOC_STAT is not set
# CONFIG_X86_16BIT is not set
# CONFIG_SMB_SERVER is not set
TRIM_UNUSED_KSYMS=y
# CONFIG_COREDUMP is not set
# CONFIG_EFI_CUSTOM_SSDT_OVERLAYS is not set
# CONFIG_MEM_SOFT_DIRTY is not set
# CONFIG_IO_URING is not set
```

# Hardened sysctl and kernel cmdline
It is recommended to complement this kernel with a hardened sysctl file. Create a new `sysctl.conf` file under `/etc/sysctl.d`, and edit its contents to the following:

```
kernel.unprivileged_userns_clone=0
kernel.kptr_restrict=2
kernel.randomize_va_space=2
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=3
kernel.dmesg_restrict=1
kernel.kexec_load_disabled=1
kernel.pid_max=4194304
kernel.perf_event_paranoid=3
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_max_sample_rate=1
kernel.sysrq=0
kernel.oops_limit=100
kernel.warn_limit=100
kernel.io_uring_disabled=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
fs.suid_dumpable=0
vm.max_map_count=16777216
vm.mmap_min_addr=65536
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
vm.unprivileged_userfaultfd=0
dev.tty.ldisc_autoload=0
net.core.bpf_jit_harden=2
net.ipv4.tcp_syncookies=1
net.ipv4.ip_forward=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.tcp_synack_retries=5
net.ipv4.tcp_congestion_control=bbr
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.default.shared_media=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.arp_announce=2
net.ipv4.conf.all.arp_announce=2
net.ipv4.conf.default.arp_ignore=1
net.ipv4.conf.all.arp_ignore=1
net.ipv4.conf.default.drop_gratuitous_arp=1
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_timestamps=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_base_mss=1024
net.ipv6.conf.default.forwarding=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.all.router_solicitations=0
net.ipv6.conf.default.router_solicitations=0
net.ipv6.conf.all.accept_ra_rtr_pref=0
net.ipv6.conf.default.accept_ra_rtr_pref=0
net.ipv6.conf.all.accept_ra_pinfo=0
net.ipv6.conf.default.accept_ra_pinfo=0
net.ipv6.conf.all.accept_ra_defrtr=0
net.ipv6.conf.default.accept_ra_defrtr=0
net.ipv6.conf.all.autoconf=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.all.dad_transmits=0
net.ipv6.conf.default.dad_transmits=0
net.ipv6.conf.all.max_addresses=1
net.ipv6.conf.default.max_addresses=1
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
```

## Cmdline
The following kernel cmdline parameters are recommended for additional security at little to no cost to performance.

`lsm=landlock,lockdown,yama,confidentiality,apparmor,bpf lockdown=confidentiality hardened_usercopy=1 init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on page_alloc.shuffle=1 slab_nomerge iommu.passthrough=0 iommu.strict=1 mitigations=auto kfence.sample_interval=100 vsyscall=none vdso32=0 cfi=kcfi`

# Observations
- The `CONFIG_USER_NS_UNPRIVILEGED` parameter is deliberately not set in the patch and kernel, as it causes compatibility issues with many applications who for some reason still rely on insecure unprivileged namespaces. Instead, it is recommended to use sysctl and set the `kernel.unprivileged_userns_clone` parameter to `0` (unprivileged namespaces disabled; more secure) or `1` (enabled; less secure but more compatible) through a .conf file, which makes it easier to switch it on and off on-demand versus having to re-build the entire kernel.
- You may notice that not all recommended parameters from the KSPP are included. This is because I have tested them and they affect performance greatly (such as forcing SLUB debugging), which is not the point of this kernel. I do not intend to maximize security here and I am conscious that I am omitting some configurations, but that is because, as I mentioned at the beginning of this README, this is supposed to be balanced between security and speed. The goal is to have this kernel be more secure than `linux-hardened` while offering the speed of `linux-zen`.
