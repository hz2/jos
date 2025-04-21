# Testing

- `test` crate depends on stdlib, so we need `custom_test_frameworks`
  - as a result, many advanced features are not available


- there are two different approaches for communicating between CPU and
  peripheral hardware on x86:
  - memory-mapped I/O
    - this is what we used for the VGA buffer
  - port-mapped I/O
    - this uses a separate I/O bus for communication
    - each connected peripheral has 1+ port numbers
    - uses a special CPU instruction `in` and `out` which take a port number and
      a data byte
    - `isa-debug-exit` device uses port-mapped I/O
      - when a value is written to the I/O port specified by `iobase`, it causes
        QEMU to exit with exit-status `(value << 1) | 1`
        - so when we write `0` to port, QEMU will exit with exit status: 
          `(0 << 1) | 1 = 3`
          - see the `Cargo.toml` for  `test-success-exit-code = 33 # (0x10 << 1) | 1`

## printing to the console

- to see output from the console, we need to send the data from our kernel to
  the host system somehow, some use a TCP network interface but because setting up
  a networking stack can be complex, we will use a serial port instead
- simple way to send data is through a _serial port_ which most modern computers
  no longer support
  - we will use the `uart_16550` crate

