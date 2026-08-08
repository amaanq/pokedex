//! A bounds-checked cursor over raw DEX bytes.

use crate::error::{
   Error,
   Result,
};

#[derive(Clone, Copy, Debug)]
/// A bounds-checked little-endian cursor over DEX bytes.
pub struct Reader<'dex> {
   /// The complete input.
   bytes:    &'dex [u8],
   /// The byte offset of the next read.
   position: usize,
}

impl<'dex> Reader<'dex> {
   /// Creates a reader positioned at `position`.
   pub const fn at(bytes: &'dex [u8], position: usize) -> Self {
      Self { bytes, position }
   }

   /// Returns the byte offset of the next read.
   pub const fn position(&self) -> usize {
      self.position
   }

   /// Returns the number of bytes left after the position.
   pub const fn remaining(&self) -> usize {
      self.bytes.len().saturating_sub(self.position)
   }

   /// Advances past `size` bytes.
   pub fn skip(&mut self, size: usize) -> Result<()> {
      self.take(size, "skipped bytes")?;
      Ok(())
   }

   /// Reads one byte.
   pub fn u8(&mut self) -> Result<u8> {
      Ok(self.take(1, "u8")?[0])
   }

   /// Reads a little-endian 16-bit value.
   pub fn u16(&mut self) -> Result<u16> {
      let mut value = [0; 2];
      value.copy_from_slice(self.take(2, "u16")?);
      Ok(u16::from_le_bytes(value))
   }

   /// Reads a little-endian 32-bit value.
   pub fn u32(&mut self) -> Result<u32> {
      let mut value = [0; 4];
      value.copy_from_slice(self.take(4, "u32")?);
      Ok(u32::from_le_bytes(value))
   }

   /// Reads a little-endian 32-bit offset, count, or index as a `usize`.
   pub fn u32_usize(&mut self) -> Result<usize> {
      usize::try_from(self.u32()?).ok().ok_or(Error::Overflow {
         what: "32-bit value",
      })
   }

   /// Reads an unsigned LEB128 value of at most five bytes.
   pub fn uleb128(&mut self) -> Result<u64> {
      let mut value = 0_u64;
      for shift in (0_u32..35).step_by(7) {
         let byte = self.take(1, "ULEB128")?[0];
         value |= u64::from(byte & 0x7F) << shift;
         if byte & 0x80 == 0 {
            return Ok(value);
         }
      }
      Err(Error::malformed("ULEB128 exceeds five bytes"))
   }

   /// Reads an unsigned LEB128 value that must fit a `usize`.
   pub fn uleb128_usize(&mut self) -> Result<usize> {
      usize::try_from(self.uleb128()?)
         .ok()
         .ok_or(Error::Overflow {
            what: "ULEB128 value",
         })
   }

   /// Reads a `size`-byte little-endian table index from an encoded value.
   pub fn encoded_index(&mut self, size: usize) -> Result<usize> {
      usize::try_from(self.encoded_unsigned(size)?)
         .ok()
         .ok_or(Error::Overflow {
            what: "annotation index",
         })
   }

   /// Reads a `size`-byte little-endian unsigned encoded value.
   pub fn encoded_unsigned(&mut self, size: usize) -> Result<u64> {
      if size > 8 {
         return Err(Error::malformed("encoded value exceeds eight bytes"));
      }
      Ok(self
         .take(size, "encoded value")?
         .iter()
         .enumerate()
         .fold(0, |result, (index, byte)| {
            result | (u64::from(*byte) << (index * 8))
         }))
   }

   /// Reads a `size`-byte little-endian encoded value and sign-extends it.
   pub fn encoded_signed(&mut self, size: usize) -> Result<i64> {
      if size == 0 {
         return Err(Error::malformed("signed encoded value has zero width"));
      }
      let value = self.encoded_unsigned(size)?;
      if size == 8 || value & (1 << (size * 8 - 1)) == 0 {
         Ok(value.cast_signed())
      } else {
         Ok((value | (!0_u64 << (size * 8))).cast_signed())
      }
   }

   /// Returns the next `size` bytes, reporting `what` on truncation.
   fn take(&mut self, size: usize, what: &'static str) -> Result<&'dex [u8]> {
      let start = self.position;
      let end = start.checked_add(size).ok_or(Error::Overflow {
         what: "reader offset",
      })?;
      let value = self
         .bytes
         .get(start..end)
         .ok_or_else(|| Error::truncated(what, start, size, self.bytes.len()))?;
      self.position = end;
      Ok(value)
   }
}
