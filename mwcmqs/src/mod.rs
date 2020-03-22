#[macro_use]
pub mod macros;
pub mod base58;
pub mod crypto;
pub mod error_kind;
pub mod message;

pub use self::error_kind::ErrorKind;
pub use self::macros::*;
pub use failure::Error;
use grin_wallet_util::grin_api;
pub use parking_lot::{Mutex, MutexGuard};
use serde::Serialize;
use std::result::Result as StdResult;
pub use std::sync::Arc;

#[derive(Clone, PartialEq)]
pub enum RuntimeMode {
	Cli,
	Daemon,
}

static mut RUNTIME_MODE: RuntimeMode = RuntimeMode::Cli;

pub unsafe fn set_runtime_mode(runtime_mode: &RuntimeMode) {
	RUNTIME_MODE = runtime_mode.clone();
}

pub fn is_cli() -> bool {
	unsafe { RUNTIME_MODE == RuntimeMode::Cli }
}

pub const COLORED_PROMPT: &'static str = "\x1b[36mmwc-wallet>\x1b[0m ";
pub const PROMPT: &'static str = "mwc-wallet> ";

pub fn post<IN>(
	url: &str,
	api_secret: Option<String>,
	basic_auth_key: Option<String>,
	input: &IN,
) -> StdResult<String, grin_api::Error>
where
	IN: Serialize,
{
	let req = grin_api::client::create_post_request_ex(url, api_secret, basic_auth_key, input)?;
	let res = grin_api::client::send_request(req)?;
	Ok(res)
}
