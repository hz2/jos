//! Call/Reply IPC end to end, server first: the server parks in recv_reply
//! first; the client's call finds it and hands over directly.
//!
//! The scenario lives in `common/call_reply.rs`.
#![no_std]
#![no_main]

const SERVER_FIRST: bool = true;
const TEST_NAME: &str = "call_reply_server_first::server_answers_badged_call";

include!("common/call_reply.rs");
