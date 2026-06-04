use spin::Mutex;
use uart_16550::SerialPort;

// COM1 lives at the standard 0x3F8 i/o port base. SerialPort::new is a const fn,
// so this static is built at compile time, with no lazy_static first-access
// path (which hung the boot sequence elsewhere). the port still needs a runtime
// init() before use; that happens once in init_serial() during kernel init.
pub static SERIAL1: Mutex<SerialPort> = Mutex::new(
    // SAFETY: 0x3F8 is the fixed COM1 base on x86; qemu always emulates a 16550
    // uart there, and this is the only SerialPort constructed for that base.
    unsafe { SerialPort::new(0x3F8) },
);

/// Initializes the COM1 serial port. Call once during early kernel init,
/// before any serial output is expected to be readable on the host.
pub fn init_serial() {
    SERIAL1.lock().init();
}

#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;
    // hold the serial lock with interrupts disabled. otherwise a timer or
    // keyboard interrupt firing mid-print would try to lock SERIAL1 again and
    // spin-deadlock forever (spin::Mutex is not reentrant, and single-core
    // means the held lock never releases). without_interrupts saves/restores
    // the interrupt flag, so it is a no-op before interrupts are enabled.
    interrupts::without_interrupts(|| {
        SERIAL1
            .lock()
            .write_fmt(args)
            .expect("Printing to serial failed");
    });
}

/// Prints to the host through the serial interface.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*));
    };
}

/// Prints to the host through the serial interface, appending a newline.
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(
        concat!($fmt, "\n"), $($arg)*));
}
