//! DEX modified UTF-8 decoding.

use std::str;

use crate::error::{
   Error,
   Result,
};

/// Decodes DEX modified UTF-8 while preserving isolated UTF-16 surrogates.
///
/// `expected_utf16_size` is the code-unit count declared by the string data
/// header and must match the decoded length.
///
/// # Errors
///
/// Returns [`Error::InvalidMutf8`] when the bytes are not well-formed MUTF-8
/// or decode to a different number of UTF-16 code units than declared.
#[inline]
pub fn decode(bytes: &[u8], expected_utf16_size: usize) -> Result<String> {
   Mutf8Decoder { bytes }.decode(expected_utf16_size)
}

/// Decodes one DEX string payload from modified UTF-8.
struct Mutf8Decoder<'dex> {
   /// The encoded bytes without the trailing null.
   bytes: &'dex [u8],
}

impl Mutf8Decoder<'_> {
   /// A private-use character marking an isolated surrogate in the decoded
   /// string.
   const UNPAIRED_SENTINEL: char = '\u{f0000}';

   /// Decodes the payload and verifies it has the declared number of UTF-16
   /// units.
   fn decode(&self, expected_utf16_size: usize) -> Result<String> {
      if let Ok(value) = str::from_utf8(self.bytes) {
         return self.check_utf8(value, expected_utf16_size);
      }

      let mut units = Vec::with_capacity(expected_utf16_size);
      let mut cursor = 0;
      while cursor < self.bytes.len() {
         let first = self.bytes[cursor];
         let unit = match first {
            0x01..=0x7F => {
               cursor += 1;
               u16::from(first)
            },
            0xC0 => {
               if self.bytes.get(cursor + 1) != Some(&0x80) {
                  return Err(Self::invalid(cursor, "invalid null encoding"));
               }
               cursor += 2;
               0
            },
            0xC2..=0xDF => {
               let second = self.continuation(cursor + 1)?;
               cursor += 2;
               (u16::from(first & 0x1F) << 6_u32) | u16::from(second)
            },
            0xE0..=0xEF => {
               let second_raw = *self
                  .bytes
                  .get(cursor + 1)
                  .ok_or_else(|| Self::invalid(cursor, "truncated sequence"))?;
               if first == 0xE0 && second_raw < 0xA0 {
                  return Err(Self::invalid(cursor, "overlong sequence"));
               }
               let second = self.continuation(cursor + 1)?;
               let third = self.continuation(cursor + 2)?;
               cursor += 3;
               (u16::from(first & 0x0F) << 12_u32) | (u16::from(second) << 6_u32) | u16::from(third)
            },
            _ => {
               return Err(Self::invalid(
                  cursor,
                  format!("invalid leading byte 0x{first:02x}"),
               ));
            },
         };
         units.push(unit);
      }
      if units.len() != expected_utf16_size {
         return Err(Self::invalid(
            self.bytes.len(),
            format!(
               "decoded {} UTF-16 units but header declares {expected_utf16_size}",
               units.len()
            ),
         ));
      }
      Ok(Self::string_from_units(&units))
   }

   /// Validates already well-formed UTF-8 against the declared UTF-16 length.
   fn check_utf8(&self, value: &str, expected_utf16_size: usize) -> Result<String> {
      if self.bytes.len() == expected_utf16_size {
         return Ok(value.to_owned());
      }
      let mut decoded_size = 0;
      for character in value.chars() {
         if u32::from(character) > 0xFFFF {
            return Err(Self::invalid(0, "four-byte UTF-8 is not valid DEX MUTF-8"));
         }
         decoded_size += 1;
      }
      if decoded_size != expected_utf16_size {
         return Err(Self::invalid(
            0,
            format!(
               "decoded {decoded_size} UTF-16 units but header declares {expected_utf16_size}"
            ),
         ));
      }
      Ok(value.to_owned())
   }

   /// Reads the payload bits of a continuation byte at `offset`.
   fn continuation(&self, offset: usize) -> Result<u8> {
      let byte = *self
         .bytes
         .get(offset)
         .ok_or_else(|| Self::invalid(offset, "truncated sequence"))?;
      if byte & 0xC0 != 0x80 {
         return Err(Self::invalid(
            offset,
            format!("invalid continuation byte 0x{byte:02x}"),
         ));
      }
      Ok(byte & 0x3F)
   }

   /// Converts UTF-16 units to a string, preserving isolated surrogates.
   fn string_from_units(units: &[u16]) -> String {
      let mut output = String::with_capacity(units.len());
      for decoded in char::decode_utf16(units.iter().copied()) {
         match decoded {
            Ok(character) => {
               output.push(character);
               if character == Self::UNPAIRED_SENTINEL {
                  output.push(character);
               }
            },
            Err(error) => {
               // DEX permits isolated surrogates, so preserve their identity in
               // Rust strings.
               output.push(Self::UNPAIRED_SENTINEL);
               output.push(
                  char::from_u32(0xE000 + u32::from(error.unpaired_surrogate() - 0xD800))
                     .unwrap_or(char::REPLACEMENT_CHARACTER),
               );
            },
         }
      }
      output
   }

   /// Builds an invalid modified UTF-8 error.
   fn invalid(offset: usize, reason: impl Into<String>) -> Error {
      Error::InvalidMutf8 {
         offset,
         reason: reason.into(),
      }
   }
}
