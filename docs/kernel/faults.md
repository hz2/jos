# Faults

What happens when a thread does something the CPU refuses: a page fault, an
invalid opcode, a division by zero. In jos a fault is the faulting thread's
business, never the kernel's: it becomes a message to whoever the thread named
to handle it, the seL4 model. The code is `kernel/src/exceptions.rs`; the
message format and fault kinds are `jos_core::abi::{FaultKind, fault_message}`.

## Entry

Every vector a thread can raise has a stub (`jos_exception_<n>`): vectors
without a CPU-pushed error code push a zero in its place, then every stub
pushes its vector and joins one common path. That path swaps to the kernel GS
only when the exception came from ring 3 (the saved CS says), saves all 15
general registers as an `ExceptionFrame`, clears DF, and calls
`exception_handler`. Handled vectors: 0 to 7 (less NMI), 10 to 14, 16, 17, 19,
20, 21. The double fault keeps its own handler on its IST stack; NMI and
machine checks are not a thread's doing.

```
cpu pushes ss, rsp, rflags, cs, rip [, error]
stub: [push 0] push vector, jmp common
common: swapgs if ring 3; push r15..rax; cld; call exception_handler
        (returns only for kernel traps) pop; swapgs if ring 3; add rsp, 16; iretq
```

## Ring 0

An exception in the kernel is a kernel bug. The two traps resume (`#DB`, and
`#BP` so a kernel `int3` works); anything else prints the vector, `rip`, error
code, and `CR2`, and fails the run (`exit_qemu(Failed)`).

## Ring 3

1. The thread's registers are saved into its TCB from the frame, with `rip`
   at the faulting instruction, so a resumption retries it.
2. Its fault endpoint is looked up: `tcb_set_fault_handler(tcb, slot)` (25)
   names a slot in the thread's **own** capability space, resolved now, at
   fault time. The capability there must name an endpoint and carry `WRITE`.
   Revoking it takes the handler away; setting the handler before the
   capability arrives is fine.
3. With an endpoint, the thread is marked `Faulted` and delivered as if it
   had made a `call` with the fault message, with the badge of the fault
   endpoint capability (so one handler can tell its threads apart):

   | word | meaning |
   |---|---|
   | 0 | the vector (`FaultKind`), also returned in `rax` |
   | 1 | the address a page fault was about (`CR2`), zero otherwise |
   | 2 | the faulting instruction |
   | 3 | the error code the CPU pushed, zero for vectors without one |

   A handler parked in `recv_reply` gets it at once, with its reply object
   bound to the faulting thread; otherwise the call waits in the endpoint's
   queue like any other caller, served oldest first.
4. The kernel then runs whatever else is ready (or idles).

An answer through the reply object (`reply`, `reply_recv`) resumes the thread
at the faulting instruction **with every register as it was**: the reply's
words are not written into it, as they would be for an ordinary call. That is
what lets a userspace pager map the missing page and simply answer. A fault
that can never be answered (a plain receive took it, or the reply object was
revoked) stops the thread instead of returning an error into its registers.

## No handler

A thread with no usable fault endpoint is stopped, and only it: it leaves the
scheduler and every wait for good (as if its TCB were revoked), the kernel logs
the vector, `rip`, address, and error code, and everything else keeps running.
Two cases stop the machine instead, with failure: a kernel test (no root task,
so the old fail-fast behavior holds) and the root task itself, which nothing
could answer.

## Demand paging from userspace

The root task's `handled_page_fault_resumes_the_thread` check is the whole
mechanism in miniature:

```
thread: mov rax, 0x1111; mov rdx, 0x2222; mov rcx, [unmapped]   -> #PF
kernel: park the thread, deliver [14, unmapped, rip, 0b100] to its endpoint
root:   recv_reply(faults, reply) -> the fault
        map a fresh frame at `unmapped`, write 0x77 into it
        reply(reply, 0)
thread: mov rcx, [unmapped] runs again, rcx = 0x77, rax and rdx intact
```

Letting the answer write the reply into the faulted thread's registers makes
that check fail; so does removing the Faulted case on any other path.
