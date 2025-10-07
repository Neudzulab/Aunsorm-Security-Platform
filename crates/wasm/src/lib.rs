#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) mod internal;

#[cfg(target_arch = "wasm32")]
mod bindings;

#[cfg(test)]
mod tests;
