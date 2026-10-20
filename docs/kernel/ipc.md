# IPC Paths

How the kernel's send and receive paths fit together. `docs/architecture.md`
gives the model; this is the mechanism, in `kernel/src/syscall/ipc.rs`.

## Where a message can wait

An endpoint has two places a message or a thread can wait:

- **the slot**: the endpoint object (`jos_core::endpoint`, capacity one) holds
  at most one undelivered message, put there by a send that found no receiver;
- **the parking tables**: `BLOCKED_SENDS` and `BLOCKED_RECVS` hold threads
  parked in a blocking call, each entry with its endpoint, the parked thread,
  and a park sequence number. A caller (`call`, or a fault) always parks here;
  it never uses the slot.

## The rules

Every path, blocking or not, keeps the same order:

1. **Send**: a receiver parked on the endpoint takes the message directly
   (the oldest one first); otherwise the message goes into the slot if it is
   free; otherwise a blocking send parks, and a non-blocking one fails with
   `WouldBlock`.
2. **Receive**: the message in the slot comes first, because it is the oldest
   (a sender parks only once the slot is full); then the oldest parked sender,
   whose send completes (or, for a caller, whose reply object is bound, and a
   plain receive fails it with `NoReply`); otherwise a blocking receive parks,
   and a non-blocking one fails with `WouldBlock`.
3. Parked threads are served oldest first by their park sequence number, not
   by their position in the table, whose entries are reused in any order.

A receiver is parked only when the slot is empty, and a send hands off to a
parked receiver before it would use the slot, so a parked receiver never sits
next to a message in the slot.

## What broke before

Before these rules, a non-blocking `ipc_send` only ever used the slot, so a
receiver parked by `ipc_recv_blocking` slept forever beside a message meant
for it; a non-blocking `ipc_recv` never saw a sender parked by
`ipc_send_blocking`; and both receive paths took a parked sender before the
older message in the slot. The root task's checks
`nonblocking_send_reaches_a_parked_receiver` and
`nonblocking_recv_takes_a_parked_sender` each fail if their half of the
handoff is removed, and the second also fails if the slot is read after the
parked sender.

## Waking

A woken thread does not wait for the next timer tick: when the thread on the
CPU blocks or exits (`enter_idle_from_syscall`), the next ready thread runs at
once. Only an idle CPU waits for an interrupt.
