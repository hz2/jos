# Boot

following minimal rust kernel[^1]

## prereqs

- 3 release channels[^2]
- multiboot-kernel[^3]
- multiboot spec[^4]
- `unsafe` code[^5]

when booting, the system will start executing firmware code that is stored in the motherboard's Read-Only Memory (ROM)

does:

- power-on self test (POST): checks if the hardware is working properly
- detects available hardware components (CPU, RAM, storage devices, etc.)
- looks for a bootable disk (hard drive, USB drive, etc.) and starts booting the operating system kernel

on x86, there are two firmware standards: BIOS and UEFI

```bash
# from rust-book 
# rustup toolchain install nightly
rustup override set nightly # set the nightly toolchain for the current directory
```

[^1]: [minimal rust kernel](https://os.phil-opp.com/minimal-rust-kernel/)
[^2]: [rust release channels](https://doc.rust-lang.org/book/appendix-07-nightly-rust.html#choo-choo-release-channels-and-riding-the-trains)
[^3]: [multiboot-kernel](https://os.phil-opp.com/multiboot-kernel/)
[^4]: [multiboot spec](https://nongnu.askapache.com/grub/phcoder/multiboot.pdf)
[^5]: [unsafe rust](https://doc.rust-lang.org/stable/book/ch20-01-unsafe-rust.html)
