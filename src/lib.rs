//! DEX parsing, instruction decoding, control-flow recovery, and configurable
//! hashing.
//!
//! [`dex::Dex::parse`] owns one DEX file and resolves its tables eagerly.
//! Method bodies stay encoded until [`dex::Dex::decode`] produces a
//! [`bytecode::Code`], and hashing only runs when [`bytecode::Code::hashes`]
//! is called with a [`hash::Config`].

#![deny(missing_docs)]

pub mod annotation;
pub mod bytecode;
#[cfg(feature = "containers")] pub mod containers;
mod decode;
pub mod dex;
pub mod error;
mod graph;
pub mod hash;
pub mod mutf8;
mod reader;
mod references;
