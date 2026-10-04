//! Call/Reply IPC end to end, client first: the client's call parks first;
//! the server's recv_reply finds the parked call and binds it.
//!
//! The scenario lives in `common/call_reply.rs`.
#![no_std]
#![no_main]

const SERVER_FIRST: bool = false;
const TEST_NAME: &str = "call_reply_client_first::server_answers_badged_call";

include!("common/call_reply.rs");
