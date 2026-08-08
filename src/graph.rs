//! Basic-block and edge recovery from decoded instructions.

use std::collections::{
   BTreeMap,
   BTreeSet,
};

use crate::{
   bytecode::{
      BasicBlock,
      ControlFlow,
      Edge,
      EdgeKind,
      Instruction,
   },
   decode::Payload,
   error::{
      Error,
      Result,
      bail,
   },
};

/// One control-flow successor of an instruction before blocks are assigned.
#[derive(Clone, Copy)]
struct Successor {
   /// The code-unit offset of the successor instruction.
   target:     usize,
   /// The kind of edge leading to the successor.
   kind:       EdgeKind,
   /// The ordinal of the switch case producing this successor.
   case_index: u32,
   /// The switch key producing this successor.
   key:        Option<i32>,
}

impl Successor {
   /// Creates the sequential successor into the following instruction.
   const fn fallthrough(target: usize) -> Self {
      Self {
         target,
         kind: EdgeKind::Fallthrough,
         case_index: 0,
         key: None,
      }
   }
}

/// Recovers basic blocks and edges from a decoded instruction stream.
pub struct GraphBuilder<'code> {
   /// The decoded instructions in code-unit order.
   instructions: &'code [Instruction],
   /// The switch and array payloads keyed by code-unit offset.
   payloads:     &'code BTreeMap<usize, Payload>,
}

impl<'code> GraphBuilder<'code> {
   /// Creates a builder over decoded instructions and their payloads.
   pub const fn new(
      instructions: &'code [Instruction],
      payloads: &'code BTreeMap<usize, Payload>,
   ) -> Self {
      Self {
         instructions,
         payloads,
      }
   }

   /// Splits the instructions into basic blocks and connects them with edges.
   pub fn build(&self) -> Result<(Vec<BasicBlock>, Vec<Edge>)> {
      let Some(first) = self.instructions.first() else {
         return Ok((Vec::new(), Vec::new()));
      };
      let mut starts = BTreeSet::from([first.offset()]);
      for (index, instruction) in self.instructions.iter().enumerate() {
         if !matches!(
            instruction.control_flow(),
            ControlFlow::Continue | ControlFlow::FillArrayData(_)
         ) {
            for successor in self.successors(index)? {
               starts.insert(successor.target);
            }
            if let Some(next) = self.instructions.get(index + 1) {
               starts.insert(next.offset());
            }
         }
      }

      let mut blocks = Vec::new();
      let mut offset_to_block = BTreeMap::new();
      let mut block_start = 0;
      for (instruction_index, instruction) in self.instructions.iter().enumerate() {
         if instruction_index != 0 && starts.contains(&instruction.offset()) {
            blocks.push(BasicBlock::new(block_start..instruction_index));
            block_start = instruction_index;
         }
         offset_to_block.insert(instruction.offset(), blocks.len());
      }
      blocks.push(BasicBlock::new(block_start..self.instructions.len()));

      let mut edges = Vec::new();
      for (source, block) in blocks.iter().enumerate() {
         let instruction_index = block.instruction_range().end - 1;
         for successor in self.successors(instruction_index)? {
            let target = *offset_to_block
               .get(&successor.target)
               .ok_or_else(|| Error::malformed("control-flow target does not begin a block"))?;
            if source != target || successor.kind != EdgeKind::Fallthrough {
               edges.push(Edge::new(
                  source,
                  target,
                  successor.kind,
                  successor.case_index,
                  successor.key,
               ));
            }
         }
      }
      Ok((blocks, edges))
   }

   /// Lists the successors of the instruction at `index`.
   fn successors(&self, index: usize) -> Result<Vec<Successor>> {
      let instruction = &self.instructions[index];
      let next = self.instructions.get(index + 1).map(Instruction::offset);
      let mut output = Vec::new();
      match instruction.control_flow() {
         ControlFlow::Continue | ControlFlow::FillArrayData(_) => {
            output.extend(next.map(Successor::fallthrough));
         },
         ControlFlow::Return | ControlFlow::Throw => {},
         ControlFlow::Goto(delta) => {
            output.push(Successor {
               target:     self.target(instruction.relative(delta)?)?,
               kind:       EdgeKind::Goto,
               case_index: 0,
               key:        None,
            });
         },
         ControlFlow::Conditional(delta) => {
            output.push(Successor {
               target:     self.target(instruction.relative(delta)?)?,
               kind:       EdgeKind::Branch,
               case_index: 0,
               key:        None,
            });
            output.extend(next.map(Successor::fallthrough));
         },
         ControlFlow::Switch(delta) => {
            let payload_offset = instruction.relative(delta)?;
            let Some(switch) = self.payloads.get(&payload_offset).and_then(Payload::switch) else {
               bail!("switch references invalid payload at code unit {payload_offset}")
            };
            for (case_index, (&key, &case_delta)) in
               (0..).zip(switch.keys.iter().zip(&switch.targets))
            {
               output.push(Successor {
                  target: self.target(instruction.relative(case_delta)?)?,
                  kind: EdgeKind::Switch,
                  case_index,
                  key: Some(key),
               });
            }
            output.extend(next.map(Successor::fallthrough));
         },
      }
      Ok(output)
   }

   /// Snaps a code-unit offset to the first instruction at or after it.
   fn target(&self, offset: usize) -> Result<usize> {
      let index = self
         .instructions
         .partition_point(|instruction| instruction.offset() < offset);
      self
         .instructions
         .get(index)
         .map(Instruction::offset)
         .ok_or_else(|| {
            Error::malformed(format!(
               "branch target {offset} is past the last instruction"
            ))
         })
   }
}
