/* linker script for the multiboot2 + grub boot path.
   grub loads the elf at 1 MiB, so that is where we link.
   the multiboot2 header must appear within the first 32 KiB of the image,
   so .multiboot_header is placed first. */
ENTRY(_start32)

SECTIONS {
    . = 1M;

    .multiboot_header : {
        KEEP(*(.multiboot_header))
    }

    .text : {
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /* end of the kernel image; the frame allocator reserves everything below
       this so it never hands out a frame the kernel is using. */
    _kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
