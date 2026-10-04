//! A call taken by a plain receive fails with `NoReply`, client first: the plain
//! receive meets a parked call, so it fails the caller through `abort_call`.
//!
//! The scenario lives in `common/call_no_reply.rs`.
#![no_std]
#![no_main]

const SERVER_FIRST: bool = false;
const TEST_NAME: &str = "call_no_reply_client_first::plain_recv_fails_the_call";

include!("common/call_no_reply.rs");
