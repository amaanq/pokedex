//! Instruction stream decoding against the resolved DEX tables.

use std::{
   collections::BTreeMap,
   sync::Arc,
};

use crate::{
   annotation,
   bytecode::{
      ControlFlow,
      Instruction,
      Operand,
      ReferenceKind,
   },
   error::{
      Error,
      Result,
      bail,
      ensure,
   },
   references::References,
};

/// The DEX instruction encoding formats, named as in the bytecode
/// specification.
#[derive(Clone, Copy)]
enum Format {
   /// One code unit with no operands.
   F10x,
   /// Two 4-bit registers.
   F12x,
   /// One 4-bit register and a 4-bit literal.
   F11n,
   /// One 8-bit register.
   F11x,
   /// An 8-bit branch offset.
   F10t,
   /// A 16-bit branch offset.
   F20t,
   /// One 8-bit and one 16-bit register.
   F22x,
   /// One 8-bit register and a 16-bit branch offset.
   F21t,
   /// One 8-bit register and a 16-bit literal.
   F21s,
   /// One 8-bit register and the high 16 bits of a literal.
   F21h,
   /// One 8-bit register and a 16-bit table index.
   F21c,
   /// Three 8-bit registers.
   F23x,
   /// Two 8-bit registers and an 8-bit literal.
   F22b,
   /// Two 4-bit registers and a 16-bit branch offset.
   F22t,
   /// Two 4-bit registers and a 16-bit literal.
   F22s,
   /// Two 4-bit registers and a 16-bit table index.
   F22c,
   /// Two 16-bit registers.
   F32x,
   /// A 32-bit branch offset.
   F30t,
   /// One 8-bit register and a 32-bit branch offset.
   F31t,
   /// One 8-bit register and a 32-bit literal.
   F31i,
   /// One 8-bit register and a 32-bit table index.
   F31c,
   /// Up to five 4-bit registers and a 16-bit table index.
   F35c,
   /// A register range and a 16-bit table index.
   F3rc,
   /// Up to five 4-bit registers with method and prototype indexes.
   F45cc,
   /// A register range with method and prototype indexes.
   F4rcc,
   /// One 8-bit register and a 64-bit literal.
   F51l,
}

impl Format {
   /// Returns the encoding format of an opcode, or `None` for opcodes the DEX
   /// specification leaves unused.
   const fn of(opcode: u8) -> Option<Self> {
      let format = match opcode {
         0x3E..=0x43 | 0x73 | 0x79 | 0x7A | 0xE3..=0xF9 => return None,
         0x00 | 0x0E => Self::F10x,
         0x01 | 0x04 | 0x07 | 0x21 | 0x7B..=0x8F | 0xB0..=0xCF => Self::F12x,
         0x02 | 0x05 | 0x08 => Self::F22x,
         0x03 | 0x06 | 0x09 => Self::F32x,
         0x0A..=0x0D | 0x0F..=0x11 | 0x1D | 0x1E | 0x27 => Self::F11x,
         0x12 => Self::F11n,
         0x13 | 0x16 => Self::F21s,
         0x14 | 0x17 => Self::F31i,
         0x15 | 0x19 => Self::F21h,
         0x18 => Self::F51l,
         0x1A | 0x1C | 0x1F | 0x22 | 0x60..=0x6D | 0xFE | 0xFF => Self::F21c,
         0x1B => Self::F31c,
         0x20 | 0x23 | 0x52..=0x5F => Self::F22c,
         0x24 | 0x6E..=0x72 | 0xFC => Self::F35c,
         0x25 | 0x74..=0x78 | 0xFD => Self::F3rc,
         0x26 | 0x2B | 0x2C => Self::F31t,
         0x28 => Self::F10t,
         0x29 => Self::F20t,
         0x2A => Self::F30t,
         0x2D..=0x31 | 0x44..=0x51 | 0x90..=0xAF => Self::F23x,
         0x32..=0x37 => Self::F22t,
         0x38..=0x3D => Self::F21t,
         0xD0..=0xD7 => Self::F22s,
         0xD8..=0xE2 => Self::F22b,
         0xFA => Self::F45cc,
         0xFB => Self::F4rcc,
      };
      Some(format)
   }

   /// Returns the instruction width in 16-bit code units.
   const fn width(self) -> usize {
      match self {
         Self::F10x | Self::F12x | Self::F11n | Self::F11x | Self::F10t => 1,
         Self::F20t
         | Self::F22x
         | Self::F21t
         | Self::F21s
         | Self::F21h
         | Self::F21c
         | Self::F23x
         | Self::F22b
         | Self::F22t
         | Self::F22s
         | Self::F22c => 2,
         Self::F32x
         | Self::F30t
         | Self::F31t
         | Self::F31i
         | Self::F31c
         | Self::F35c
         | Self::F3rc => 3,
         Self::F45cc | Self::F4rcc => 4,
         Self::F51l => 5,
      }
   }
}

impl ReferenceKind {
   /// Returns the byte identifying this kind in hash encodings.
   pub(crate) const fn tag(self) -> u8 {
      match self {
         Self::String => 0,
         Self::Type => 1,
         Self::Field => 2,
         Self::Method => 3,
         Self::Prototype => 4,
         Self::MethodHandle => 5,
         Self::CallSite => 6,
      }
   }

   /// Returns the table an opcode indexes, or `None` when it carries no
   /// reference.
   const fn of_opcode(opcode: u8) -> Option<Self> {
      match opcode {
         0x1A | 0x1B => Some(Self::String),
         0x1C | 0x1F | 0x20 | 0x22..=0x25 => Some(Self::Type),
         0x52..=0x6D => Some(Self::Field),
         0x6E..=0x72 | 0x74..=0x78 => Some(Self::Method),
         0xFC | 0xFD => Some(Self::CallSite),
         0xFE => Some(Self::MethodHandle),
         0xFF => Some(Self::Prototype),
         _ => None,
      }
   }
}

/// A reference operand resolved against the DEX tables.
enum Resolved<'code> {
   /// A rendered string, type, field, method, prototype, or method handle.
   Name(&'code str),
   /// The structured values of a call site.
   CallSite(&'code Arc<[annotation::Value]>),
}

/// A code item's instruction stream addressed in 16-bit code units.
#[derive(Clone, Copy)]
struct CodeUnits<'code>(&'code [u16]);

impl CodeUnits<'_> {
   /// Returns the number of code units.
   const fn len(self) -> usize {
      self.0.len()
   }

   /// Reads a unit whose presence was already established by a width check.
   const fn unit(self, offset: usize) -> u16 {
      self.0[offset]
   }

   /// Reads one code unit with a bounds check.
   fn u16(self, offset: usize) -> Result<u16> {
      self
         .0
         .get(offset)
         .copied()
         .ok_or_else(|| Error::truncated("code unit", offset, 1, self.0.len()))
   }

   /// Reads a little-endian 32-bit value spanning two code units.
   fn u32(self, offset: usize) -> Result<u32> {
      let low = u32::from(self.u16(offset)?);
      let high = u32::from(self.u16(offset + 1)?);
      Ok(low | (high << 16))
   }

   /// Reads a 32-bit table index spanning two code units as a `usize`.
   fn u32_usize(self, offset: usize) -> Result<usize> {
      usize::try_from(self.u32(offset)?)
         .ok()
         .ok_or(Error::Overflow {
            what: "32-bit code unit index",
         })
   }

   /// Reads a signed 32-bit value spanning two code units.
   fn i32(self, offset: usize) -> Result<i32> {
      Ok(self.u32(offset)?.cast_signed())
   }

   /// Reads a little-endian 64-bit value spanning four code units.
   fn u64(self, offset: usize) -> Result<u64> {
      let low = u64::from(self.u32(offset)?);
      let high = u64::from(self.u32(offset + 2)?);
      Ok(low | (high << 32))
   }
}

/// Decodes one instruction stream against the tables it references.
pub struct Decoder<'code> {
   /// The instruction stream being decoded.
   units:      CodeUnits<'code>,
   /// The resolved tables that reference operands index into.
   references: &'code References,
}

impl<'code> Decoder<'code> {
   /// Creates a decoder over one code item's instruction units.
   pub const fn new(units: &'code [u16], references: &'code References) -> Self {
      Self {
         units: CodeUnits(units),
         references,
      }
   }

   /// Decodes every instruction and payload, attaching payload contents to
   /// the instructions that reference them.
   pub fn decode(&self) -> Result<(Vec<Instruction>, BTreeMap<usize, Payload>)> {
      let mut instructions = Vec::new();
      let mut payloads = BTreeMap::new();
      let mut offset = 0_usize;
      while offset < self.units.len() {
         let [opcode, high] = self.units.unit(offset).to_le_bytes();
         if opcode == 0 && high != 0 {
            let (payload, width) = self.payload(offset)?;
            payloads.insert(offset, payload);
            offset = offset.checked_add(width).ok_or(Error::Overflow {
               what: "payload offset",
            })?;
            continue;
         }

         let Some(format) = Format::of(opcode) else {
            bail!("unused dex opcode 0x{opcode:02X}")
         };
         let width = format.width();
         ensure!(
            offset + width <= self.units.len(),
            "opcode 0x{opcode:02X} extends past code item"
         );
         if opcode != 0 {
            instructions.push(Instruction::new(
               offset,
               opcode,
               self.operands(offset, opcode, format)?,
               self.control(offset, opcode)?,
            ));
         }
         offset += width;
      }
      Self::attach_payloads(&mut instructions, &payloads)?;
      Ok((instructions, payloads))
   }

   /// Decodes the payload at `offset` and returns it with its width in code
   /// units.
   fn payload(&self, offset: usize) -> Result<(Payload, usize)> {
      let units = self.units;
      match units.unit(offset) {
         0x0100 => {
            let count = units.u16(offset + 1)?;
            let first_key = units.i32(offset + 2)?;
            let mut keys = Vec::with_capacity(usize::from(count));
            let mut targets = Vec::with_capacity(usize::from(count));
            for index in 0..count {
               keys.push(first_key.wrapping_add(i32::from(index)));
               targets.push(units.i32(offset + 4 + usize::from(index) * 2)?);
            }
            Ok((
               Payload::Switch(SwitchPayload { keys, targets }),
               4 + usize::from(count) * 2,
            ))
         },
         0x0200 => {
            let count = usize::from(units.u16(offset + 1)?);
            let mut keys = Vec::with_capacity(count);
            let mut targets = Vec::with_capacity(count);
            for index in 0..count {
               keys.push(units.i32(offset + 2 + index * 2)?);
               targets.push(units.i32(offset + 2 + count * 2 + index * 2)?);
            }
            Ok((
               Payload::Switch(SwitchPayload { keys, targets }),
               2 + count * 4,
            ))
         },
         0x0300 => {
            let element_width = units.u16(offset + 1)?;
            ensure!(element_width != 0, "array payload has zero-width elements");
            let element_count = units.u32(offset + 2)?;
            let byte_count = usize::try_from(element_count)
               .ok()
               .ok_or(Error::Overflow {
                  what: "array payload element count",
               })?
               .checked_mul(usize::from(element_width))
               .ok_or(Error::Overflow {
                  what: "array payload byte count",
               })?;
            let code_units = byte_count.div_ceil(2);
            let end = offset.checked_add(4 + code_units).ok_or(Error::Overflow {
               what: "array payload end",
            })?;
            ensure!(end <= units.len(), "array payload extends past code item");
            let mut data = Vec::with_capacity(byte_count);
            for unit in &units.0[offset + 4..end] {
               data.extend_from_slice(&unit.to_le_bytes());
            }
            data.truncate(byte_count);
            Ok((
               Payload::ArrayData(ArrayPayload {
                  element_width,
                  element_count,
                  data,
               }),
               4 + code_units,
            ))
         },
         signature => bail!("unknown dex payload signature 0x{signature:04X}"),
      }
   }

   /// Decodes the register, literal, and reference operands of one instruction.
   fn operands(&self, offset: usize, opcode: u8, format: Format) -> Result<Vec<Operand>> {
      let mut operands = Vec::new();
      let registers = self.registers(offset, opcode, format)?;
      if !registers.is_empty() {
         operands.push(Operand::Registers(registers));
      }
      if let Some(value) = self.literal(offset, opcode) {
         operands.push(Operand::Literal(value));
      }
      self.reference_operands(offset, opcode, format, &mut operands)?;
      Ok(operands)
   }

   /// Appends the resolved table references an instruction carries, if any.
   fn reference_operands(
      &self,
      offset: usize,
      opcode: u8,
      format: Format,
      operands: &mut Vec<Operand>,
   ) -> Result<()> {
      let units = self.units;
      if matches!(format, Format::F45cc | Format::F4rcc) {
         let method =
            self.resolve_named(ReferenceKind::Method, usize::from(units.unit(offset + 1)))?;
         let prototype = self.resolve_named(
            ReferenceKind::Prototype,
            usize::from(units.unit(offset + 3)),
         )?;
         operands.push(Operand::Reference(ReferenceKind::Method, method.to_owned()));
         operands.push(Operand::Reference(
            ReferenceKind::Prototype,
            prototype.to_owned(),
         ));
         return Ok(());
      }
      let Some(kind) = ReferenceKind::of_opcode(opcode) else {
         return Ok(());
      };
      let index = if matches!(format, Format::F31c) {
         units.u32_usize(offset + 1)?
      } else {
         usize::from(units.unit(offset + 1))
      };
      match self.resolve(kind, index)? {
         Resolved::Name(reference) if matches!(kind, ReferenceKind::String) => {
            operands.push(Operand::String(reference.to_owned()));
         },
         Resolved::Name(reference) => {
            operands.push(Operand::Reference(kind, reference.to_owned()));
         },
         Resolved::CallSite(values) => {
            operands.push(Operand::CallSite(Arc::clone(values)));
         },
      }
      Ok(())
   }

   /// Extracts the register operands according to the instruction format.
   fn registers(&self, offset: usize, opcode: u8, format: Format) -> Result<Vec<u16>> {
      let units = self.units;
      let first = units.unit(offset);
      let low_nibble = (first >> 8_u32) & 0xF;
      let high_nibble = (first >> 12_u32) & 0xF;
      let registers = match format {
         Format::F12x if (0xB0..=0xCF).contains(&opcode) => {
            vec![low_nibble, low_nibble, high_nibble]
         },
         Format::F12x | Format::F22t | Format::F22s | Format::F22c => {
            vec![low_nibble, high_nibble]
         },
         Format::F11n => vec![low_nibble],
         Format::F11x
         | Format::F21t
         | Format::F21s
         | Format::F21h
         | Format::F21c
         | Format::F31t
         | Format::F31i
         | Format::F31c
         | Format::F51l => vec![first >> 8_u32],
         Format::F22x => vec![first >> 8_u32, units.unit(offset + 1)],
         Format::F32x => vec![units.unit(offset + 1), units.unit(offset + 2)],
         Format::F23x => {
            let second = units.unit(offset + 1);
            vec![first >> 8_u32, second & 0xFF, second >> 8_u32]
         },
         Format::F22b => {
            let second = units.unit(offset + 1);
            vec![first >> 8_u32, second & 0xFF]
         },
         Format::F35c | Format::F45cc => {
            let count = usize::from(first >> 12_u32);
            ensure!(count <= 5, "opcode 0x{opcode:02X} has too many registers");
            let packed = units.unit(offset + 2);
            let mut values = vec![
               packed & 0xF,
               (packed >> 4_u32) & 0xF,
               (packed >> 8_u32) & 0xF,
               (packed >> 12_u32) & 0xF,
               (first >> 8_u32) & 0xF,
            ];
            values.truncate(count);
            values
         },
         Format::F3rc | Format::F4rcc => {
            let count = first >> 8_u32;
            let start = units.unit(offset + 2);
            (0..count).map(|index| start.wrapping_add(index)).collect()
         },
         Format::F10x | Format::F10t | Format::F20t | Format::F30t => Vec::new(),
      };
      Ok(registers)
   }

   /// Extracts the numeric literal carried by constant-loading instructions.
   fn literal(&self, offset: usize, opcode: u8) -> Option<i64> {
      let units = self.units;
      match opcode {
         0x12 => {
            let nibble = (units.unit(offset).to_le_bytes()[1] >> 4).cast_signed();
            Some(i64::from((nibble << 4) >> 4))
         },
         0x13 | 0x16 | 0xD0..=0xD7 => Some(i64::from(units.unit(offset + 1).cast_signed())),
         0x14 | 0x17 => Some(i64::from(units.u32(offset + 1).ok()?.cast_signed())),
         0x15 => {
            Some(i64::from(
               (u32::from(units.unit(offset + 1)) << 16).cast_signed(),
            ))
         },
         0x18 => Some(units.u64(offset + 1).ok()?.cast_signed()),
         0x19 => Some((u64::from(units.unit(offset + 1)) << 48).cast_signed()),
         0xD8..=0xE2 => {
            Some(i64::from(
               units.unit(offset + 1).to_le_bytes()[1].cast_signed(),
            ))
         },
         _ => None,
      }
   }

   /// Classifies the control-flow effect of one instruction.
   fn control(&self, offset: usize, opcode: u8) -> Result<ControlFlow> {
      let units = self.units;
      let control = match opcode {
         0x0E..=0x11 => ControlFlow::Return,
         0x27 => ControlFlow::Throw,
         0x28 => ControlFlow::Goto(i32::from(units.u16(offset)?.to_le_bytes()[1].cast_signed())),
         0x29 => ControlFlow::Goto(i32::from(units.u16(offset + 1)?.cast_signed())),
         0x2A => ControlFlow::Goto(units.i32(offset + 1)?),
         0x2B | 0x2C => ControlFlow::Switch(units.i32(offset + 1)?),
         0x26 => ControlFlow::FillArrayData(units.i32(offset + 1)?),
         0x32..=0x3D => ControlFlow::Conditional(i32::from(units.u16(offset + 1)?.cast_signed())),
         _ => ControlFlow::Continue,
      };
      Ok(control)
   }

   /// Attaches switch keys and array data to the instructions that reference
   /// them.
   fn attach_payloads(
      instructions: &mut [Instruction],
      payloads: &BTreeMap<usize, Payload>,
   ) -> Result<()> {
      for instruction in instructions {
         let (ControlFlow::Switch(delta) | ControlFlow::FillArrayData(delta)) =
            instruction.control_flow()
         else {
            continue;
         };
         let payload_offset = instruction.relative(delta)?;
         let payload = payloads.get(&payload_offset).ok_or_else(|| {
            Error::malformed(format!(
               "opcode 0x{:02X} references missing payload at code unit {payload_offset}",
               instruction.opcode()
            ))
         })?;
         let is_switch = matches!(instruction.control_flow(), ControlFlow::Switch(_));
         ensure!(
            is_switch == payload.switch().is_some(),
            "opcode 0x{:02X} references the wrong payload kind",
            instruction.opcode()
         );
         instruction.push_operand(payload.operand());
      }
      Ok(())
   }

   /// Resolves an operand index against the table selected by `kind`.
   fn resolve(&self, kind: ReferenceKind, index: usize) -> Result<Resolved<'code>> {
      if matches!(kind, ReferenceKind::CallSite) {
         let call_sites = &self.references.call_sites;
         return call_sites
            .get(index)
            .map(Resolved::CallSite)
            .ok_or_else(|| {
               Error::invalid_reference("instruction", "call site", index, call_sites.len())
            });
      }
      self.resolve_named(kind, index).map(Resolved::Name)
   }

   /// Resolves an operand index against a table of rendered names.
   fn resolve_named(&self, kind: ReferenceKind, index: usize) -> Result<&'code str> {
      let references = self.references;
      let named = |name: &'static str, values: &'code [String]| {
         values
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| Error::invalid_reference("instruction", name, index, values.len()))
      };
      match kind {
         ReferenceKind::String => named("string", &references.strings),
         ReferenceKind::Type => named("type", &references.types),
         ReferenceKind::Field => named("field", &references.fields),
         ReferenceKind::Method => named("method", &references.methods),
         ReferenceKind::Prototype => named("prototype", &references.prototypes),
         ReferenceKind::MethodHandle => named("method handle", &references.method_handles),
         ReferenceKind::CallSite => Err(Error::malformed("call site is not a named reference")),
      }
   }
}

/// Data embedded in the instruction stream and referenced by a single
/// instruction.
pub enum Payload {
   /// A packed or sparse switch table.
   Switch(SwitchPayload),
   /// A fill-array-data table.
   ArrayData(ArrayPayload),
}

/// The keys and relative branch targets of a switch table.
pub struct SwitchPayload {
   /// The case keys in table order.
   pub keys:    Vec<i32>,
   /// The branch offsets in table order, relative to the switch instruction.
   pub targets: Vec<i32>,
}

/// The raw contents of a fill-array-data table.
pub struct ArrayPayload {
   /// The width of each element in bytes.
   pub element_width: u16,
   /// The number of elements.
   pub element_count: u32,
   /// The encoded element bytes.
   pub data:          Vec<u8>,
}

impl Payload {
   /// Returns the switch table when this payload is one.
   pub const fn switch(&self) -> Option<&SwitchPayload> {
      match *self {
         Self::Switch(ref switch) => Some(switch),
         Self::ArrayData(_) => None,
      }
   }

   /// Returns the operand carrying this payload's contents. Switch targets
   /// are not included since they live on CFG edges.
   pub fn operand(&self) -> Operand {
      match *self {
         Self::Switch(ref switch) => Operand::SwitchKeys(switch.keys.clone()),
         Self::ArrayData(ref array) => {
            Operand::ArrayData {
               element_width: array.element_width,
               element_count: array.element_count,
               data:          array.data.clone(),
            }
         },
      }
   }
}
