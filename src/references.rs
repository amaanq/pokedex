//! The resolved ID tables shared between parsing and instruction decoding.

use std::{
   ops::Range,
   sync::Arc,
};

use crate::annotation;

/// The resolved DEX tables shared by the parser and the instruction decoder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct References {
   /// The decoded string table.
   pub strings:        Vec<String>,
   /// The MUTF-8 payload byte ranges, excluding length prefixes and NULs.
   pub string_ranges:  Vec<Range<usize>>,
   /// The type descriptors.
   pub types:          Vec<String>,
   /// The field signatures.
   pub fields:         Vec<String>,
   /// The method signatures.
   pub methods:        Vec<String>,
   /// The method prototypes.
   pub prototypes:     Vec<String>,
   /// The method handle descriptions.
   pub method_handles: Vec<String>,
   /// The call site value lists.
   pub call_sites:     Vec<Arc<[annotation::Value]>>,
}
