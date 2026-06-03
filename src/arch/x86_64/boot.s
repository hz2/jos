/* multiboot2 boot trampoline for jos.
   grub hands control here in 32-bit protected mode, paging off, flat segments,
   a20 enabled, with eax=0x36d76289 (the multiboot2 loader magic) and ebx=the
   multiboot2 info pointer. this stub saves those values, builds
   identity-mapped page tables for the first 1 GiB, enables long mode, and
   far-jumps into 64-bit rust at kernel_main(magic, info_ptr).

   grub loads our elf64 kernel directly (qemu's built-in -kernel multiboot1
   loader rejects 64-bit elfs, hence grub + an iso). bios boot keeps the legacy
   text-mode vga at 0xb8000 live, so the vga driver works at entry.

   note: the boot path is x86_64 specific by nature; other arches get their own
   trampoline behind the hal when they are brought up. */

/* page-table frames live just below the loaded kernel image. */
.set PML4, 0x1000
.set PDPT, 0x2000
.set PD,   0x3000

.code32

/* multiboot2 header: magic, architecture, header length, checksum, then the
   required end tag. the first four longs must satisfy
   magic + arch + length + checksum == 0 (mod 2^32). */
.section .multiboot_header, "a"
.align 8
multiboot_header:
    .long 0xe85250d6                                  /* multiboot2 magic */
    .long 0                                           /* architecture: i386 */
    .long multiboot_header_end - multiboot_header     /* header length */
    .long -(0xe85250d6 + 0 + (multiboot_header_end - multiboot_header))
    /* required end tag: type=0, flags=0, size=8 */
    .word 0
    .word 0
    .long 8
multiboot_header_end:

.section .text
.global _start32
.type _start32, @function
_start32:
    /* set up the boot stack */
    mov $stack_top, %esp

    /* save multiboot magic and info pointer into memory so the page-table
       setup below is free to clobber the general registers. */
    mov %eax, mb_magic
    mov %ebx, mb_info

    /* zero the three page-table frames at 0x1000..0x4000 */
    mov $PML4, %edi
    xor %eax, %eax
    mov $((0x4000 - 0x1000) / 4), %ecx
    rep stosl

    /* pml4[0] -> pdpt, present + writable */
    movl $(PDPT | 0x3), PML4

    /* pdpt[0] -> pd, present + writable */
    movl $(PD | 0x3), PDPT

    /* pd[0..512]: 512 huge 2 MiB pages identity-mapping the first 1 GiB.
       each entry is phys | present | writable | hugepage (0x83). */
    mov $PD, %edi
    mov $0x83, %eax
    mov $512, %ecx
.fill_pd:
    mov %eax, (%edi)
    add $0x200000, %eax
    add $8, %edi
    loop .fill_pd

    /* load cr3 with the pml4 base */
    mov $PML4, %eax
    mov %eax, %cr3

    /* enable pae: cr4.pae = bit 5 */
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4

    /* set efer.lme: msr 0xC0000080, bit 8 */
    mov $0xC0000080, %ecx
    rdmsr
    or $(1 << 8), %eax
    wrmsr

    /* enable paging: cr0.pg = bit 31 (pe is already set by the loader) */
    mov %cr0, %eax
    or $(1 << 31), %eax
    mov %eax, %cr0

    /* now in 32-bit compatibility mode. load the 64-bit gdt and far-jump to
       reload cs with the 64-bit code selector. */
    lgdt gdt64_ptr
    ljmp $0x08, $_start64

.code64
.global _start64
.type _start64, @function
_start64:
    /* reload the data segment registers with the data selector */
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    /* pass saved magic/info to rust per the sysv64 abi: rdi, rsi.
       the 32-bit loads zero-extend into the full 64-bit registers. */
    mov mb_magic, %edi
    mov mb_info, %esi

    call kernel_main

    /* kernel_main diverges; halt forever if it ever returns. */
1:  cli
    hlt
    jmp 1b

/* 64-bit gdt: null, kernel code (long mode), kernel data. */
.section .rodata
.align 8
gdt64:
    .quad 0x0000000000000000          /* [0x00] null */
    .quad 0x00AF9A000000FFFF          /* [0x08] code: present, dpl0, exec/read, L=1 */
    .quad 0x00CF92000000FFFF          /* [0x10] data: present, dpl0, read/write */
gdt64_ptr:
    .word gdt64_ptr - gdt64 - 1
    .long gdt64

.section .bss
.align 4
mb_magic:
    .skip 4
mb_info:
    .skip 4
.align 16
stack_bottom:
    .skip 16384                       /* 16 KiB boot stack */
stack_top:
