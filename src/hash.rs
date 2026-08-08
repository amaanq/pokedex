//! Configurable structural and full method hashing.

use std::{
   fmt,
   ops::{
      BitOr,
      BitOrAssign,
   },
};

use hmac_sha256::Hash;

use crate::{
   annotation,
   bytecode::{
      Code,
      Edge,
      EdgeKind,
      Instruction,
      Operand,
      ReferenceKind,
   },
};

/// The structural and full content digests for one method body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MethodHashes {
   /// The digest produced by the structural hash profile.
   pub structural: [u8; 32],
   /// The digest produced by the full hash profile.
   pub full:       [u8; 32],
}

/// The treatment of register operands while hashing instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegisterHashMode {
   /// Hash only that an instruction carries register operands.
   Omit,
   /// Hash the normalized number of register operands.
   Count,
   /// Hash the normalized ordered register identities.
   Identity,
}

/// Whether basic-block placement contributes to a method hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BlockOrder {
   /// Sort blocks and edges by content so layout changes do not affect the
   /// hash.
   Canonical,
   /// Hash blocks and edges in their placement order.
   Placement,
}

/// The operand contents a hash profile includes beyond operand kinds.
///
/// Combine details with `|`, for example
/// `OperandDetails::REFERENCE_NAMES | OperandDetails::ARRAY_SHAPE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OperandDetails(u8);

impl OperandDetails {
   /// No operand contents, only operand kinds and counts.
   pub const NONE: Self = Self(0);
   /// Numeric literal values.
   pub const LITERAL_VALUES: Self = Self(1 << 0_u32);
   /// Resolved string contents.
   pub const STRING_VALUES: Self = Self(1 << 1_u32);
   /// Resolved reference names and call site values.
   pub const REFERENCE_NAMES: Self = Self(1 << 2_u32);
   /// Switch keys on operands and CFG edges.
   pub const SWITCH_KEYS: Self = Self(1 << 3_u32);
   /// Array element width and count.
   pub const ARRAY_SHAPE: Self = Self(1 << 4_u32);
   /// Raw fill-array-data contents.
   pub const ARRAY_DATA: Self = Self(1 << 5_u32);
   /// Every operand detail.
   pub const ALL: Self = Self(0b11_1111);

   /// Reports whether every detail in `other` is included.
   #[must_use]
   #[inline]
   pub const fn contains(self, other: Self) -> bool {
      self.0 & other.0 == other.0
   }
}

impl BitOr for OperandDetails {
   type Output = Self;

   #[inline]
   fn bitor(self, rhs: Self) -> Self {
      Self(self.0 | rhs.0)
   }
}

impl BitOrAssign for OperandDetails {
   #[inline]
   fn bitor_assign(&mut self, rhs: Self) {
      self.0 |= rhs.0;
   }
}

/// The data included by one method hash profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Profile {
   /// How basic-block placement contributes to the hash.
   pub block_order: BlockOrder,
   /// How register operands contribute to the hash.
   pub registers:   RegisterHashMode,
   /// Which operand contents contribute to the hash.
   pub details:     OperandDetails,
}

/// A policy that maps raw opcodes into caller-defined equivalence classes.
pub trait OpcodeNormalizer {
   /// Returns the equivalence class for one raw DEX opcode.
   fn normalize(&self, opcode: u8) -> u8;
}

impl<F> OpcodeNormalizer for F
where
   F: Fn(u8) -> u8,
{
   #[inline]
   fn normalize(&self, opcode: u8) -> u8 {
      self(opcode)
   }
}

/// Configuration for structural and full method content hashing.
#[derive(Clone, Copy)]
pub struct Config<N = fn(u8) -> u8> {
   /// The policy mapping raw opcodes to equivalence classes.
   normalize_opcode: N,
   /// The operand profile for the structural hash.
   structural:       Profile,
   /// The operand profile for the full hash.
   full:             Profile,
}

impl<N> Config<N> {
   /// Creates a method hashing policy from explicit opcode and operand
   /// profiles.
   #[inline]
   pub const fn new(normalize_opcode: N, structural: Profile, full: Profile) -> Self {
      Self {
         normalize_opcode,
         structural,
         full,
      }
   }

   /// Returns the opcode equivalence policy.
   #[must_use]
   #[inline]
   pub const fn opcode_normalizer(&self) -> &N {
      &self.normalize_opcode
   }

   /// Returns the structural hash profile.
   #[must_use]
   #[inline]
   pub const fn structural_profile(&self) -> Profile {
      self.structural
   }

   /// Returns the full hash profile.
   #[must_use]
   #[inline]
   pub const fn full_profile(&self) -> Profile {
      self.full
   }

   /// Returns a mutable structural hash profile.
   #[inline]
   pub const fn structural_profile_mut(&mut self) -> &mut Profile {
      &mut self.structural
   }

   /// Returns a mutable full hash profile.
   #[inline]
   pub const fn full_profile_mut(&mut self) -> &mut Profile {
      &mut self.full
   }
}

impl Config<fn(u8) -> u8> {
   /// Returns a hashing policy tuned to ignore block placement and register
   /// identity while separating literals into the full hash.
   #[must_use]
   #[inline]
   pub fn recompilation_stable() -> Self {
      let structural = Profile {
         block_order: BlockOrder::Canonical,
         registers:   RegisterHashMode::Count,
         details:     OperandDetails::REFERENCE_NAMES | OperandDetails::ARRAY_SHAPE,
      };
      let full = Profile {
         details: OperandDetails::ALL,
         ..structural
      };
      Self::new(recompilation_stable_opcode, structural, full)
   }
}

impl Default for Config<fn(u8) -> u8> {
   #[inline]
   fn default() -> Self {
      Self::recompilation_stable()
   }
}

impl<N> fmt::Debug for Config<N> {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("Config")
         .field("structural", &self.structural)
         .field("full", &self.full)
         .finish_non_exhaustive()
   }
}

/// Computes both digests of a method body under `config`.
pub(crate) fn method_hashes<N>(code: &Code, config: &Config<N>) -> MethodHashes
where
   N: OpcodeNormalizer,
{
   MethodHashes {
      structural: MethodHasher::new(config.structural, &config.normalize_opcode).method(code),
      full:       MethodHasher::new(config.full, &config.normalize_opcode).method(code),
   }
}

/// Hashes method bodies under one operand profile and opcode policy.
struct MethodHasher<'config, N> {
   /// The operand data included in the hash.
   profile:   Profile,
   /// The opcode equivalence policy.
   normalize: &'config N,
}

impl<N> MethodHasher<'_, N>
where
   N: OpcodeNormalizer,
{
   /// Creates a hasher for one profile and opcode policy.
   const fn new(profile: Profile, normalize: &N) -> MethodHasher<'_, N> {
      MethodHasher { profile, normalize }
   }

   /// Hashes a method body, canonicalizing block order when the profile asks
   /// for it.
   fn method(&self, code: &Code) -> [u8; 32] {
      let block_hashes = code
         .blocks()
         .iter()
         .map(|block| self.block(&code[block]))
         .collect::<Vec<_>>();
      let mut sink = Sink::new();
      sink.len(block_hashes.len());
      if self.profile.block_order == BlockOrder::Canonical {
         let mut canonical_blocks = block_hashes.clone();
         canonical_blocks.sort_unstable();
         for hash in canonical_blocks {
            sink.raw(hash);
         }

         let mut canonical_edges = code
            .edges()
            .iter()
            .map(|edge| {
               (
                  block_hashes[edge.source()],
                  block_hashes[edge.target()],
                  edge.kind(),
                  edge.case_index(),
                  self.edge_key(edge),
               )
            })
            .collect::<Vec<_>>();
         canonical_edges.sort_unstable();
         sink.len(canonical_edges.len());
         for (source, target, kind, case_index, key) in canonical_edges {
            sink.raw(source);
            sink.raw(target);
            sink.edge_tail(kind, case_index, key);
         }
      } else {
         for hash in block_hashes {
            sink.raw(hash);
         }
         sink.len(code.edges().len());
         for edge in code.edges() {
            sink.len(edge.source());
            sink.len(edge.target());
            sink.edge_tail(edge.kind(), edge.case_index(), self.edge_key(edge));
         }
      }
      sink.finish()
   }

   /// Returns the switch key of an edge when the profile includes switch keys.
   fn edge_key(&self, edge: &Edge) -> Option<i32> {
      self
         .profile
         .details
         .contains(OperandDetails::SWITCH_KEYS)
         .then_some(edge.key())
         .flatten()
   }

   /// Hashes the instructions of one basic block.
   fn block(&self, instructions: &[Instruction]) -> [u8; 32] {
      let mut sink = Sink::new();
      sink.len(instructions.len());
      for instruction in instructions {
         sink.raw([self.normalize.normalize(instruction.opcode())]);
         sink.len(instruction.operands().len());
         for operand in instruction.operands() {
            self.operand(&mut sink, operand);
         }
      }
      sink.finish()
   }

   /// Instruction formats carry at most 255 registers, so the count always
   /// fits one byte.
   fn register_count(registers: &[u16]) -> u8 {
      u8::try_from(registers.len()).unwrap_or(u8::MAX)
   }

   /// Feeds one operand into the block digest according to the profile.
   fn operand(&self, sink: &mut Sink, operand: &Operand) {
      let profile = self.profile;
      match *operand {
         Operand::Registers(ref registers) => {
            match profile.registers {
               RegisterHashMode::Omit => sink.raw([0x01]),
               RegisterHashMode::Count => sink.raw([0x01, Self::register_count(registers)]),
               RegisterHashMode::Identity => {
                  sink.raw([0x01, Self::register_count(registers)]);
                  for register in registers {
                     sink.raw(register.to_le_bytes());
                  }
               },
            }
         },
         Operand::Literal(value) => {
            sink.raw([0x02]);
            if profile.details.contains(OperandDetails::LITERAL_VALUES) {
               sink.raw(value.to_le_bytes());
            }
         },
         Operand::String(ref value) => {
            sink.raw([0x03]);
            if profile.details.contains(OperandDetails::STRING_VALUES) {
               sink.bytes(value.as_bytes());
            }
         },
         Operand::Reference(kind, ref value) => {
            sink.raw([0x04, kind.tag()]);
            if profile.details.contains(OperandDetails::REFERENCE_NAMES) {
               sink.bytes(value.as_bytes());
            }
         },
         Operand::CallSite(ref values) => {
            sink.raw([0x04, ReferenceKind::CallSite.tag()]);
            if profile.details.contains(OperandDetails::REFERENCE_NAMES) {
               sink.len(values.len());
               for value in values.iter() {
                  sink.annotation_value(value);
               }
            }
         },
         Operand::SwitchKeys(ref keys) => {
            sink.raw([0x05]);
            sink.len(keys.len());
            if profile.details.contains(OperandDetails::SWITCH_KEYS) {
               for key in keys {
                  sink.raw(key.to_le_bytes());
               }
            }
         },
         Operand::ArrayData {
            element_width,
            element_count,
            ref data,
         } => {
            sink.raw([0x06]);
            if profile.details.contains(OperandDetails::ARRAY_SHAPE) {
               sink.raw(element_width.to_le_bytes());
               sink.raw(element_count.to_le_bytes());
            }
            if profile.details.contains(OperandDetails::ARRAY_DATA) {
               sink.bytes(data);
            }
         },
      }
   }
}

/// A SHA-256 stream with the length-prefixed encodings the hash format uses.
struct Sink(Hash);

impl Sink {
   /// Starts an empty digest.
   fn new() -> Self {
      Self(Hash::new())
   }

   /// Feeds raw bytes without a length prefix.
   fn raw(&mut self, value: impl AsRef<[u8]>) {
      self.0.update(value);
   }

   /// Feeds a length as a little-endian 64-bit value.
   fn len(&mut self, value: usize) {
      self.raw(u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes());
   }

   /// Feeds a byte string prefixed by its length.
   fn bytes(&mut self, value: &[u8]) {
      self.len(value.len());
      self.raw(value);
   }

   /// Feeds the kind, case ordinal, and optional key of an edge.
   fn edge_tail(&mut self, kind: EdgeKind, case_index: u32, key: Option<i32>) {
      self.raw([kind.tag()]);
      self.raw(case_index.to_le_bytes());
      if let Some(switch_key) = key {
         self.raw(switch_key.to_le_bytes());
      }
   }

   /// Feeds a structured annotation value with a tag byte per variant.
   fn annotation_value(&mut self, annotation: &annotation::Value) {
      match *annotation {
         annotation::Value::Byte(value) => {
            self.raw([0x00]);
            self.raw(value.to_le_bytes());
         },
         annotation::Value::Short(value) => {
            self.raw([0x02]);
            self.raw(value.to_le_bytes());
         },
         annotation::Value::Char(value) => {
            self.raw([0x03]);
            self.raw(value.to_le_bytes());
         },
         annotation::Value::Int(value) => {
            self.raw([0x04]);
            self.raw(value.to_le_bytes());
         },
         annotation::Value::Long(value) => {
            self.raw([0x06]);
            self.raw(value.to_le_bytes());
         },
         annotation::Value::Float(value) => {
            self.raw([0x10]);
            self.raw(value.to_le_bytes());
         },
         annotation::Value::Double(value) => {
            self.raw([0x11]);
            self.raw(value.to_le_bytes());
         },
         annotation::Value::MethodType(ref value) => {
            self.raw([0x15]);
            self.bytes(value.as_bytes());
         },
         annotation::Value::MethodHandle(ref value) => {
            self.raw([0x16]);
            self.bytes(value.as_bytes());
         },
         annotation::Value::String(ref value) => {
            self.raw([0x17]);
            self.bytes(value.as_bytes());
         },
         annotation::Value::Type(ref value) => {
            self.raw([0x18]);
            self.bytes(value.as_bytes());
         },
         annotation::Value::Field(ref value) => {
            self.raw([0x19]);
            self.bytes(value.as_bytes());
         },
         annotation::Value::Method(ref value) => {
            self.raw([0x1A]);
            self.bytes(value.as_bytes());
         },
         annotation::Value::Enum(ref value) => {
            self.raw([0x1B]);
            self.bytes(value.as_bytes());
         },
         annotation::Value::Array(ref values) => {
            self.raw([0x1C]);
            self.len(values.len());
            for value in values {
               self.annotation_value(value);
            }
         },
         annotation::Value::Annotation {
            ref annotation_type,
            ref elements,
         } => {
            self.raw([0x1D]);
            self.bytes(annotation_type.as_bytes());
            self.len(elements.len());
            for (name, value) in elements {
               self.bytes(name.as_bytes());
               self.annotation_value(value);
            }
         },
         annotation::Value::Null => self.raw([0x1E]),
         annotation::Value::Boolean(value) => self.raw([0x1F, u8::from(value)]),
      }
   }

   /// Finalizes the digest.
   fn finish(self) -> [u8; 32] {
      self.0.finalize()
   }
}

/// Collapses opcode variants that differ only in operand width or register
/// range.
const fn recompilation_stable_opcode(opcode: u8) -> u8 {
   match opcode {
      0x02 | 0x03 => 0x01,
      0x05 | 0x06 => 0x04,
      0x08 | 0x09 => 0x07,
      0x13..=0x15 => 0x12,
      0x17..=0x19 => 0x16,
      0x1B => 0x1A,
      0x25 => 0x24,
      0x29 | 0x2A => 0x28,
      0x74..=0x78 => opcode - 6,
      0xB0..=0xCF => opcode - 0x20,
      0xD8..=0xDF => opcode - 8,
      0xFB => 0xFA,
      0xFD => 0xFC,
      _ => opcode,
   }
}
