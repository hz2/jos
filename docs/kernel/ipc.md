# IPC Paths

How the kernel's send and receive paths fit together. `docs/architecture.md`
gives the model; this is the mechanism, in `kernel/src/syscall/ipc.rs`.

## Where a message can wait

An endpoint has two places a message or a thread can wait:

- **the slot**: the endpoint object (`jos_core::endpoint`, capacity one) holds
  at most one undelivered message, put there by a send that found no receiver;
- **the parking tables**: `BLOCKED_SENDS` and `BLOCKED_RECVS` hold threads
  parked in a blocking call. Both are `jos_core::wait_table::WaitTable`s
  (BLOCK-1): each entry names the endpoint, the parked thread, and an optional
  deadline, and carries what finishing the operation needs (a sender's message
  and badge, a receiver's reply object). A caller (`call`, or a fault) always
  parks here; it never uses the slot.

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
3. Parked threads are served oldest first by the order they parked in, not by
   their position in the table, whose entries are reused in any order. Every
   take goes through the table, which also lets each waiter leave exactly once.

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

## Timeouts

`recv_timeout` parks a receiver with a deadline in timer ticks (54.9 ms each,
rounded up, plus the tick in progress). On every tick the timer interrupt
takes each receiver whose deadline has passed out of `BLOCKED_RECVS`, oldest
first, and resumes it with `TimedOut`. A receiver that timed out has left the
table, so a later message waits in the endpoint for the next receive instead of
reaching a thread that stopped waiting. The interrupt only tries the table's
lock: a revoke run by a kernel task may hold it with interrupts on, and a tick
that finds it busy leaves the wake to the next one.

## When an endpoint goes away

A thread parked in a blocking call holds no capability the kernel could find
stale; it only names the endpoint by address. So when a revoke removes the last
capability to an endpoint, every wait on it ends there (seL4's
`cancelAllIPC`): receivers and callers resume with `BadCap` (flagged), plain
blocking senders with `BadCap`, and a thread parked by a fault, which has no
call to fail, is stopped. Revoking one copy while others remain changes
nothing for the waiters.

## What broke before the wait tables

A `call` took the first matching receiver by table position instead of the one
that had waited longest, so a receiver that parked in an entry freed by an
earlier waiter could jump the queue; and revoking an endpoint left its blocked
receivers parked forever. The root task's checks
`calls_reach_the_longest_waiting_receiver` and
`revoking_an_endpoint_ends_its_waits` fail if either fix is undone, and
`a_timed_receive_runs_out` hangs without the timer's expiry.

## Notifications

A thread blocked in `wait` parks in a fourth wait table, `NTFN_WAITERS`, keyed
by the notification's address. `signal` takes the oldest waiter there and
resumes it with the bits; only with no thread waiting do the bits go into the
notification object (the verified `jos_core::notification` state, NTFN-1),
which coalesces them by OR and wakes a kernel task waiting through the async
path. So the bits are never pending while a thread waits, and the in-kernel
`cap_signal` goes through the same function, so a kernel task and a thread
cannot strand each other's wake. `wait` collects pending bits first and only
then parks; the timer tick expires a timed wait as it does a timed receive,
and revoking the last capability to the notification ends every wait on it,
through the same `cancel_waits_on` an endpoint uses. The root task's checks
`a_signal_reaches_a_waiting_thread` and `revoking_a_notification_ends_its_waits`
fail if the handoff or the cancel is taken out.
