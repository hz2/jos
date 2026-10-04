//! A call taken by a plain receive fails with `NoReply`, server first: the call
//! meets a parked plain receiver, so `sys_call` fails it immediately.
//!
//! The scenario lives in `common/call_no_reply.rs`.
#![no_std]
#![no_main]

const SERVER_FIRST: bool = true;
const TEST_NAME: &str = "call_no_reply_server_first::plain_recv_fails_the_call";

include!("common/call_no_reply.rs");
