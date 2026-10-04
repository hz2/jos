# TODO

The concrete next steps, highest leverage first. The milestone context lives in
`docs/roadmap.md`; verification targets in `docs/verification.md`.
Check items off in the same commit that finishes them.

## Now: finish real IPC (M1)

- [x] `Reply` kernel object wrapping `jos_core::reply::Reply` (`ObjectType::Reply`)
- [x] `Call` (9), `RecvReply` (10), `Reply` (11) syscalls; revoking a bound reply
      fails the caller with `NoReply`
- [x] integration tests: a badged call answered once, in both handoff orders
- [x] test the `NoReply` path where a plain receive takes a call (both orders)
- [ ] test the `NoReply` path where a bound reply object is revoked (needs a
      revoke syscall or a kernel-side test hook)
- [ ] `ReplyRecv` fast path: answer, then receive, in one syscall
- [ ] a server answering two clients by badge (needs `ReplyRecv` or a loop)
- [ ] per-TCB IPC buffer page mapped at a fixed user address; copy words 1..3
      inside `arch::x86_64::with_user_access`
- [ ] decide cross-CSpace derivation (ROADMAP open decision 1), then cap transfer
- [ ] JPC-1 Verus proof (rendezvous deadlock-freedom)

## Next: userspace that is not hand-assembled (M2)

- [ ] `user/` crate with syscall stubs; build it for `x86_64-unknown-none`
- [ ] ELF64 parser in jos-core with Kani bounds harnesses and a fuzz target
- [ ] loader maps PT_LOAD segments with W^X; root task gets the initial caps

## Hardening (small, do alongside)

- [ ] FPU/SSE save on context switch (latent bug once user code touches xmm)
- [ ] NMI / #MC on IST stacks
- [ ] give the blocking-IPC tables (`BLOCKED_SENDS` / `BLOCKED_RECVS`) a pure
      model in jos-core so the direct-handoff path is covered by Kani like the
      async path is
- [ ] lock-order checker (WITNESS-style), see ROADMAP

## Verification backlog

- [ ] ARITH-2: frame allocator abstract spec (Verus + Kani)
- [ ] JPC-2: user-pointer slice validation for the IPC buffer
- [ ] ARITH-3: trace encoding round-trip harness

## Docs and process

- [x] git hooks (`.githooks/`): style, clippy, tests on commit; full gate on push
- [x] SMEP/SMAP on, QEMU runs `-cpu max` with a timeout
- [x] `EFER.NXE` enabled: W^X `NO_EXECUTE` user pages were malformed before
- [x] `scripts/check.sh` as the single entry point for every gate (hooks and CI call it)
- [x] docs consolidated under `docs/`
- [ ] knowledge notes on seL4, Hubris, Capsicum, APIC/ACPI in `~/srcs/knowledge`
