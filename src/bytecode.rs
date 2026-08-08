//! Decoded instructions, operands, and the control-flow graph of one method.

use std::{
   ops::{
      Index,
      Range,
   },
   sync::Arc,
};

use crate::{
   annotation,
   decode::Decoder,
   error::{
      Error,
      Result,
   },
   graph::GraphBuilder,
   hash::{
      self,
      Config,
      MethodHashes,
      OpcodeNormalizer,
   },
   reader::Reader,
   references::References,
};

/// The resolved table referenced by an instruction operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ReferenceKind {
   /// A string table entry.
   String,
   /// A type table entry.
   Type,
   /// A field table entry.
   Field,
   /// A method table entry.
   Method,
   /// A prototype table entry.
   Prototype,
   /// A method handle table entry.
   MethodHandle,
   /// A call site table entry.
   CallSite,
}

/// A normalized operand carried by a decoded instruction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Operand {
   /// The ordered registers used by the instruction.
   Registers(Vec<u16>),
   /// A signed numeric literal.
   Literal(i64),
   /// A resolved string literal.
   String(String),
   /// A resolved non-string DEX reference.
   ///
   /// String and call-site references are decoded as [`Operand::String`] and
   /// [`Operand::CallSite`] instead, so the kind is never
   /// [`ReferenceKind::String`] or [`ReferenceKind::CallSite`].
   Reference(ReferenceKind, String),
   /// The structured values from a resolved call site.
   CallSite(Arc<[annotation::Value]>),
   /// The keys from a switch payload.
   SwitchKeys(Vec<i32>),
   /// The values from a fill-array-data payload.
   ArrayData {
      /// The width of each encoded array element.
      element_width: u16,
      /// The number of encoded array elements.
      element_count: u32,
      /// The raw encoded array contents.
      data:          Vec<u8>,
   },
}

/// The control-flow behavior of a decoded instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ControlFlow {
   /// Execution continues to the following instruction.
   Continue,
   /// Execution returns from the method.
   Return,
   /// Execution throws an exception.
   Throw,
   /// Execution jumps by a relative code-unit offset.
   Goto(i32),
   /// Execution conditionally jumps by a relative code-unit offset.
   Conditional(i32),
   /// Execution dispatches through a switch payload.
   Switch(i32),
   /// Execution reads an array-data payload without branching.
   FillArrayData(i32),
}

/// A decoded DEX instruction with normalized operands.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Instruction {
   /// The offset in 16-bit code units.
   offset:   usize,
   /// The raw DEX opcode.
   opcode:   u8,
   /// The decoded operands.
   operands: Vec<Operand>,
   /// The control-flow effect.
   control:  ControlFlow,
}

impl Instruction {
   /// Creates an instruction from its decoded parts.
   pub(crate) const fn new(
      offset: usize,
      opcode: u8,
      operands: Vec<Operand>,
      control: ControlFlow,
   ) -> Self {
      Self {
         offset,
         opcode,
         operands,
         control,
      }
   }

   /// Appends an operand resolved after decoding, such as a payload.
   pub(crate) fn push_operand(&mut self, operand: Operand) {
      self.operands.push(operand);
   }

   /// Returns the instruction offset in 16-bit code units.
   #[must_use]
   #[inline]
   pub const fn offset(&self) -> usize {
      self.offset
   }

   /// Returns the raw DEX opcode.
   #[must_use]
   #[inline]
   pub const fn opcode(&self) -> u8 {
      self.opcode
   }

   /// Returns the decoded normalized operands.
   #[must_use]
   #[inline]
   pub fn operands(&self) -> &[Operand] {
      &self.operands
   }

   /// Returns the decoded control-flow behavior.
   #[must_use]
   #[inline]
   pub const fn control_flow(&self) -> ControlFlow {
      self.control
   }

   /// Resolves a branch delta against this instruction's offset.
   pub(crate) fn relative(&self, delta: i32) -> Result<usize> {
      isize::try_from(delta)
         .ok()
         .and_then(|signed_delta| self.offset.checked_add_signed(signed_delta))
         .ok_or_else(|| Error::malformed("relative dex target is outside the code item"))
   }
}

/// The semantic kind of a control-flow graph edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EdgeKind {
   /// Sequential control flow into the following block.
   Fallthrough,
   /// A conditional branch target.
   Branch,
   /// An unconditional branch target.
   Goto,
   /// A switch case target.
   Switch,
}

impl EdgeKind {
   /// Returns the byte identifying this kind in hash encodings.
   pub(crate) const fn tag(self) -> u8 {
      match self {
         Self::Fallthrough => 0,
         Self::Branch => 1,
         Self::Goto => 2,
         Self::Switch => 3,
      }
   }
}

/// A contiguous range of instructions forming one basic block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BasicBlock {
   /// The instruction indexes covered by this block.
   instruction_range: Range<usize>,
}

impl BasicBlock {
   /// Creates a block covering the given instruction indexes.
   pub(crate) const fn new(instruction_range: Range<usize>) -> Self {
      Self { instruction_range }
   }

   /// Returns the instruction indexes covered by this block.
   #[must_use]
   #[inline]
   pub const fn instruction_range(&self) -> Range<usize> {
      self.instruction_range.start..self.instruction_range.end
   }
}

/// A directed edge between decoded basic blocks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Edge {
   /// The source basic-block index.
   source:     usize,
   /// The target basic-block index.
   target:     usize,
   /// The semantic edge kind.
   kind:       EdgeKind,
   /// The ordinal of the switch case, zero for other kinds.
   case_index: u32,
   /// The switch key for case edges.
   key:        Option<i32>,
}

impl Edge {
   /// Creates an edge between two blocks.
   pub(crate) const fn new(
      source: usize,
      target: usize,
      kind: EdgeKind,
      case_index: u32,
      key: Option<i32>,
   ) -> Self {
      Self {
         source,
         target,
         kind,
         case_index,
         key,
      }
   }

   /// Returns the source basic-block index.
   #[must_use]
   #[inline]
   pub const fn source(&self) -> usize {
      self.source
   }

   /// Returns the target basic-block index.
   #[must_use]
   #[inline]
   pub const fn target(&self) -> usize {
      self.target
   }

   /// Returns the semantic edge kind.
   #[must_use]
   #[inline]
   pub const fn kind(&self) -> EdgeKind {
      self.kind
   }

   /// Returns the stable ordinal of a switch case edge.
   #[must_use]
   #[inline]
   pub const fn case_index(&self) -> u32 {
      self.case_index
   }

   /// Returns the switch key attached to a case edge.
   #[must_use]
   #[inline]
   pub const fn key(&self) -> Option<i32> {
      self.key
   }
}

/// Decoded instructions and their control-flow graph without any content
/// hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Code {
   /// The decoded instructions in code-unit order.
   instructions:       Vec<Instruction>,
   /// The byte range of the encoded instruction array in the original DEX file.
   instructions_range: Range<usize>,
   /// The basic blocks partitioning the instructions.
   blocks:             Vec<BasicBlock>,
   /// The control-flow edges between blocks.
   edges:              Vec<Edge>,
}

impl Code {
   /// Returns the decoded instruction stream in code-unit order.
   #[must_use]
   #[inline]
   pub fn instructions(&self) -> &[Instruction] {
      &self.instructions
   }

   /// Returns the instruction array's byte range in the original DEX file.
   #[must_use]
   #[inline]
   pub const fn instructions_range(&self) -> Range<usize> {
      self.instructions_range.start..self.instructions_range.end
   }

   /// Returns the decoded basic blocks.
   #[must_use]
   #[inline]
   pub fn blocks(&self) -> &[BasicBlock] {
      &self.blocks
   }

   /// Returns the decoded control-flow edges.
   #[must_use]
   #[inline]
   pub fn edges(&self) -> &[Edge] {
      &self.edges
   }

   /// Computes structural and full hashes using an explicit normalization
   /// policy.
   #[must_use]
   #[inline]
   pub fn hashes<N>(&self, config: &Config<N>) -> MethodHashes
   where
      N: OpcodeNormalizer,
   {
      hash::method_hashes(self, config)
   }

   /// Decodes one DEX code item into instructions and a control-flow graph.
   pub(crate) fn decode(bytes: &[u8], code_offset: usize, references: &References) -> Result<Self> {
      let instruction_count = Reader::at(bytes, code_offset + 12).u32_usize()?;
      let instruction_offset = code_offset.checked_add(16).ok_or(Error::Overflow {
         what: "code item instruction offset",
      })?;
      let instruction_bytes = instruction_count.checked_mul(2).ok_or(Error::Overflow {
         what: "code item instruction size",
      })?;
      let instruction_end =
         instruction_offset
            .checked_add(instruction_bytes)
            .ok_or(Error::Overflow {
               what: "code item instruction end",
            })?;
      let encoded = bytes
         .get(instruction_offset..instruction_end)
         .ok_or_else(|| {
            Error::truncated(
               "code item instructions",
               instruction_offset,
               instruction_bytes,
               bytes.len(),
            )
         })?;
      let units = encoded
         .as_chunks::<2>()
         .0
         .iter()
         .map(|unit| u16::from_le_bytes(*unit))
         .collect::<Vec<_>>();
      Self::from_units(&units, references, instruction_offset..instruction_end)
   }

   /// Decodes instructions and recovers the control-flow graph from code units.
   fn from_units(
      units: &[u16],
      references: &References,
      instructions_range: Range<usize>,
   ) -> Result<Self> {
      let (instructions, payloads) = Decoder::new(units, references).decode()?;
      let (blocks, edges) = GraphBuilder::new(&instructions, &payloads).build()?;
      Ok(Self {
         instructions,
         instructions_range,
         blocks,
         edges,
      })
   }
}

impl Index<&BasicBlock> for Code {
   type Output = [Instruction];

   #[inline]
   fn index(&self, index: &BasicBlock) -> &[Instruction] {
      &self.instructions[index.instruction_range()]
   }
}
