//! Error types and the crate-wide validation macros.

use std::{
   io,
   result,
};

#[cfg(feature = "containers")] use zip::result::ZipError;

/// An error produced while reading DEX data or a containing artifact.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
   /// The input ended before a complete value could be read.
   #[error(
      "{what} is truncated at offset {offset:#x}, need {needed} bytes with {available} available"
   )]
   Truncated {
      /// The value being read.
      what:      &'static str,
      /// The byte or code-unit offset of the value.
      offset:    usize,
      /// The number of bytes or code units required.
      needed:    usize,
      /// The number of bytes or code units available.
      available: usize,
   },

   /// The input does not begin with standard DEX magic.
   #[error("invalid dex magic")]
   BadMagic,

   /// The DEX uses an unsupported byte order.
   #[error("unsupported dex endianness {value:#x}")]
   UnsupportedEndianness {
      /// The endian tag stored in the header.
      value: u32,
   },

   /// A format feature is valid but unsupported by this crate.
   #[error("unsupported {what}")]
   Unsupported {
      /// The unsupported format feature.
      what: String,
   },

   /// Modified UTF-8 data is invalid.
   #[error("invalid modified UTF-8 at byte {offset}: {reason}")]
   InvalidMutf8 {
      /// The byte offset of the invalid sequence.
      offset: usize,
      /// The validation failure.
      reason: String,
   },

   /// A table index refers outside its target table.
   #[error("{context} references invalid {kind} {index}, table has {available} entries")]
   InvalidReference {
      /// The object containing the reference.
      context:   String,
      /// The referenced table kind.
      kind:      &'static str,
      /// The invalid table index.
      index:     usize,
      /// The number of available table entries.
      available: usize,
   },

   /// Arithmetic required to locate input data overflowed.
   #[error("{what} overflow")]
   Overflow {
      /// The offset or size calculation that overflowed.
      what: &'static str,
   },

   /// Structurally invalid DEX data was encountered.
   #[error("malformed {what}")]
   Malformed {
      /// The malformed structure and reason.
      what: String,
   },

   /// Reading a containing artifact failed.
   #[error(transparent)]
   Io(#[from] io::Error),

   /// Reading a ZIP container failed.
   #[cfg(feature = "containers")]
   #[error(transparent)]
   Zip(#[from] ZipError),
}

impl Error {
   /// Builds a truncation error, clamping the available count to the input
   /// length.
   pub(crate) const fn truncated(
      what: &'static str,
      offset: usize,
      needed: usize,
      length: usize,
   ) -> Self {
      Self::Truncated {
         what,
         offset,
         needed,
         available: length.saturating_sub(offset),
      }
   }

   /// Builds a malformed-structure error.
   pub(crate) fn malformed(what: impl Into<String>) -> Self {
      Self::Malformed { what: what.into() }
   }

   /// Builds an out-of-range table index error.
   pub(crate) fn invalid_reference(
      context: impl Into<String>,
      kind: &'static str,
      index: usize,
      available: usize,
   ) -> Self {
      Self::InvalidReference {
         context: context.into(),
         kind,
         index,
         available,
      }
   }
}

/// A result produced by Pokedex operations.
pub type Result<T> = result::Result<T, Error>;

/// Returns a malformed-structure error unless the condition holds.
macro_rules! ensure {
   ($condition:expr, $($argument:tt)*) => {
      if !$condition {
         return Err($crate::error::Error::malformed(format!($($argument)*)));
      }
   };
}

/// Returns a malformed-structure error.
macro_rules! bail {
   ($($argument:tt)*) => {
      return Err($crate::error::Error::malformed(format!($($argument)*)))
   };
}

pub(crate) use bail;
pub(crate) use ensure;
