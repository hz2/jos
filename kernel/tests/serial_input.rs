// tests/serial_input.rs
//
// console input end to end below the syscall layer: with COM1 in loopback
// mode every byte the kernel transmits comes straight back as received, which
// raises IRQ4 exactly as typing would. the bytes must come out of the console
// buffer, in order, through the interrupt handler alone (this test never polls
// the uart). a missing idt entry would fault, a masked IRQ4 or a handler that
// did not drain the fifo would leave the buffer empty, and both fail here.
//
// loopback also cuts the line to the host, so nothing is printed while it is
// on.
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(jos::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use x86_64::instructions::port::Port;

/// COM1's modem control register.
const MODEM_CONTROL: u16 = 0x3FC;

/// DTR, RTS, and OUT2, as the serial driver leaves them.
const MODEM_NORMAL: u8 = 0x0B;

/// The same with loopback on.
const MODEM_LOOPBACK: u8 = MODEM_NORMAL | 0x10;

/// COM1's line status register: bit 5 is set while the transmitter can take a byte.
const LINE_STATUS: u16 = 0x3FD;

/// COM1's transmit register.
const TRANSMIT: u16 = 0x3F8;

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(_magic: u32, _info_ptr: u32) -> ! {
    test_main();
    jos::hlt_loop()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    jos::test_panic_handler(info)
}

/// Sends `bytes` on COM1 directly, one at a time as the transmitter frees up.
fn transmit(bytes: &[u8]) {
    let mut status: Port<u8> = Port::new(LINE_STATUS);
    let mut data: Port<u8> = Port::new(TRANSMIT);
    for &byte in bytes {
        // SAFETY: COM1's line status register; reading it has no effect that
        // matters here.
        while unsafe { status.read() } & 0x20 == 0 {
            core::hint::spin_loop();
        }
        // SAFETY: the transmitter is free; in loopback the byte is received.
        unsafe { data.write(byte) };
    }
}

#[test_case]
fn looped_back_bytes_reach_the_console_buffer() {
    jos::init();
    let sent = b"jos\r\n";
    let mut modem: Port<u8> = Port::new(MODEM_CONTROL);
    // SAFETY: switching COM1 to loopback only redirects its own line.
    unsafe { modem.write(MODEM_LOOPBACK) };
    transmit(sent);
    let mut got = [0u8; 8];
    let mut count = 0;
    // each wakeup is an interrupt: the receive one, or a timer tick.
    for _ in 0..200 {
        count += jos::console::take(&mut got[count..]);
        if count >= sent.len() {
            break;
        }
        x86_64::instructions::hlt();
    }
    // SAFETY: back to normal, so the result reaches the host.
    unsafe { modem.write(MODEM_NORMAL) };
    assert_eq!(&got[..count], sent, "the console buffer did not get the looped-back bytes");
    assert_eq!(jos::console::dropped(), 0);
}
