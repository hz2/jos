/* linker script for the multiboot1 + qemu -kernel boot path.
   qemu loads the elf at 1 MiB, so that is where we link.
   the multiboot header must appear within the first 8 KiB of the image,
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

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
