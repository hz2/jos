# Syscall Reference

Every jos syscall, its arguments, what it returns, and how it fails. The
authoritative source is the `Syscall` enum in `kernel/src/syscall.rs`; this page
is the map. Capabilities are named by slot number in the calling thread's
capability space, and every call checks the rights the capability carries.

## Calling convention

| register | role |
|---|---|
| `rax` | syscall number on entry; result on return |
| `rdi`, `rsi`, `rdx` | arguments 0, 1, 2 |
| `rdx` | second result on return (the sender's badge after a receive) |
| `rcx`, `r11` | clobbered by `syscall` itself |

Calls that return data (a received word, a slot, a count) report errors with
bit 63 set (`IPC_ERR_FLAG`), so any value below `1 << 63` is a real result.
Calls that only succeed or fail return `0` or a plain error code. The tables
below mark the first kind with "flagged".

## Syscalls

### Probes

| nr | name | arguments | returns |
|---|---|---|---|
| 0 | `add` | `a`, `b` | `a + b` (wrapping) |
| 1 | `exit` | `code` | does not return; `0x10` ends a QEMU test with success |

### Objects and capabilities

| nr | name | arguments | returns |
|---|---|---|---|
| 4 | `retype` | untyped slot, type word, destination slot | `0` or a retype error |
| 8 | `mint` | source slot, rights mask (low 8 bits), badge | new slot, flagged errors |
| 20 | `cnode_copy` | destination CNode slot, source slot, `dest_slot \| rights << 16` | `0` or an error |
| 21 | `revoke` | slot | number of capabilities removed, flagged errors |

`retype` carves an object from untyped memory and installs a full-rights
capability to it. The type word's low byte is the object type and bits 8 to 15
its size in bits where one applies (a CNode is `1 | 12 << 8`):

| id | object | size |
|---|---|---|
| 0 | Endpoint | small |
| 1 | CNode | `1 << size_bits` bytes (4096) |
| 2 | Untyped | not carvable by syscall |
| 3 | PageTable | 4096 |
| 4 | Tcb | 20 KiB (header, guard page, kernel stack) |
| 5 | Frame | 4096 |
| 6 | Notification | small |
| 7 | Reply | small |
| 8 | VSpace | 4096 |

`mint` derives an attenuated copy into the lowest free slot of the caller's own
space; a nonzero badge stamps an unbadged source. `cnode_copy` puts a copy into
another space's CNode (which needs `WRITE`). Both stay in the derivation tree,
so `revoke` on the source removes them, in every space. Revoking also wakes
threads blocked on a revoked endpoint, fails a call waiting on a revoked reply
object, unmaps revoked frames and page tables, and stops a thread whose TCB,
CNode, or VSpace loses its last capability.

### IPC

| nr | name | arguments | returns |
|---|---|---|---|
| 2 | `ipc_send` | endpoint slot, word | `0` or an error (`WouldBlock` if full) |
| 3 | `ipc_recv` | endpoint slot | word, badge in `rdx`; flagged errors |
| 6 | `ipc_send_blocking` | endpoint slot, word | `0` once delivered, or an error |
| 7 | `ipc_recv_blocking` | endpoint slot | word, badge in `rdx`; flagged errors |
| 9 | `call` | endpoint slot, word | the answer word; flagged errors |
| 10 | `recv_reply` | endpoint slot, reply slot | word, badge in `rdx`; flagged errors |
| 11 | `reply` | reply slot, word | `0` or an error |
| 13 | `reply_recv` | endpoint slot, reply slot, word | as `recv_reply` |
| 5 | `invoke` | slot, method, argument | method result; flagged errors |

Sending needs `WRITE` on the endpoint capability, receiving needs `READ`. A
message is four words: word 0 travels in a register, words 1 to 3 through the
IPC buffer (below). `call` blocks until a server that received with
`recv_reply` answers through the reply object; a call that meets a plain
receive fails with `NoReply`. `reply_recv` answers the bound caller, if any,
then receives, which is a whole server loop iteration in one call.

### IPC buffer and capability transfer

| nr | name | arguments | returns |
|---|---|---|---|
| 12 | `set_ipc_buffer` | frame slot (`READ` and `WRITE`) | `0` or an error |

The buffer is a frame the thread registers and maps into its own address
space; the kernel reaches it through its own identity mapping, never through a
user pointer. Its layout:

| offset | field | written by |
|---|---|---|
| `0x00` | `mrs[0..4]`, message words 0 to 3 | kernel on delivery; sender words 1 to 3 |
| `0x20` | `send_cap`: slot of a capability to send, plus one | sender |
| `0x28` | `recv_slot`: slot an incoming capability lands in, plus one | receiver |
| `0x30` | `caps_received`: 1 if a capability arrived | kernel |

A capability rides along with `ipc_send`, `ipc_send_blocking`, or `call` when
`send_cap` is set; that needs `GRANT` on the endpoint capability. The receiver
gets a copy derived from the sender's, so revoking the original reaches it. A
receiver that accepts nothing, or whose slot is taken, still gets the message,
without the capability. Replies carry words only.

### Address spaces

| nr | name | arguments | returns |
|---|---|---|---|
| 14 | `map_page_table` | VSpace slot, table slot, vaddr | `0` or an error |
| 15 | `map_frame` | VSpace slot, frame slot, `vaddr \| flags` | `0` or an error |
| 16 | `unmap` | frame or table slot | `0` or an error |

Userspace supplies every page table (the seL4 model): `map_page_table` installs
a table at the first missing level on the path to `vaddr`, once per level.
`map_frame` flags are `WRITE` (bit 0) and `EXECUTE` (bit 1); a mapping is never
both. Each object is mapped at most once; unmapping a table unmaps everything
beneath it.

### Threads

| nr | name | arguments | returns |
|---|---|---|---|
| 17 | `tcb_configure` | TCB slot, CNode slot, VSpace slot | `0` or an error |
| 18 | `tcb_set_ipc_buffer` | TCB slot, frame slot | `0` or an error |
| 19 | `tcb_start` | TCB slot, entry, stack top | `0` or an error |

A thread is configured, given a buffer, and started once; it then runs in ring
3 under the scheduler. Configuring or starting it again fails with
`AlreadyStarted`.

## Error codes

### IPC and object errors (`IpcSyscallError`)

| code | name | meaning |
|---|---|---|
| 1 | `BadCap` | the slot is out of range or empty |
| 2 | `Denied` | the capability lacks a needed right (including `GRANT` to send one) |
| 3 | `NotEndpoint` | the slot does not name an endpoint |
| 4 | `WouldBlock` | a non-blocking operation would have to wait |
| 5 | `NotReply` | the slot does not name a reply object |
| 6 | `ReplyBusy` | the reply object is already bound to a caller |
| 7 | `NoReply` | the call can never be answered (plain receive, or reply revoked) |
| 8 | `NoCaller` | `reply` found no caller waiting |
| 9 | `NotFrame` | the slot does not name a frame |
| 10 | `NoThread` | there is no current thread |
| 11 | `NotVSpace` | the slot does not name an address space |
| 12 | `NotPageTable` | the slot does not name a page table |
| 13 | `BadAddress` | the address is outside the user half or carries unknown flags |
| 14 | `MissingTable` | a page table is missing on the path; map one first |
| 15 | `AlreadyMapped` | the table or frame is mapped somewhere already |
| 16 | `AlreadyPresent` | every level, or a frame, is already mapped there |
| 17 | `WritableExecutable` | a mapping asked to be writable and executable |
| 18 | `MappingsFull` | the kernel's mapping registry is full |
| 19 | `NotMapped` | `unmap` named something that is not mapped |
| 20 | `NotTcb` | the slot does not name a thread |
| 21 | `NotCNode` | the slot does not name a CNode |
| 22 | `AlreadyStarted` | the thread has started and can no longer be configured |
| 23 | `NotConfigured` | `tcb_start` named a thread without a CNode and VSpace |
| 24 | `ThreadsFull` | the scheduler has no room for another thread |
| 25 | `SameSpace` | a capability cannot be copied into its own space |
| 26 | `SlotOccupied` | the destination slot is taken |
| 27 | `SlotOutOfRange` | the destination slot is out of range |
| 28 | `NotRegistered` | a capability was sent from an unregistered space |

### Retype errors (`RetypeSyscallError`)

| code | name | meaning |
|---|---|---|
| 1 | `BadCap` | the untyped slot is out of range or empty |
| 2 | `NotUntyped` | the capability is not an untyped region |
| 3 | `BadArgs` | unknown type or malformed size bits |
| 4 | `NoRoom` | the region has no room for the object |
| 5 | `DestOccupied` | the destination slot is taken |
| 6 | `DestOutOfRange` | the destination slot is out of range |
| 7 | `BadAlign` | the region is too misaligned for the object |
| 8 | `BadType` | the type cannot be carved by syscall |

### Mint errors (`MintSyscallError`, flagged)

| code | name | meaning |
|---|---|---|
| 1 | `BadCap` | the source slot is out of range or empty |
| 2 | `AlreadyBadged` | a badge was asked for on an already badged source |
| 3 | `SpaceFull` | the caller's space has no free slot |

### Invoke errors (`InvokeError`, flagged)

| code | name | meaning |
|---|---|---|
| 1 | `BadCap` | the slot is out of range or empty |
| 2 | `Denied` | the capability lacks the right the method needs |
| 3 | `BadMethod` | the method is not defined for this object kind |
| 4 | `WouldBlock` | the endpoint is full (send) or empty (receive) |
