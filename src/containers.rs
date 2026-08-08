//! APK, JAR, ZIP, and VDEX container handling.

use std::io::{
   Read,
   Seek,
};

use zip::ZipArchive;

use crate::{
   error::{
      Error,
      Result,
   },
   reader::Reader,
};

/// A named DEX payload extracted from an artifact or container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexFile {
   /// The entry or synthesized file name.
   pub name:  String,
   /// The complete standard DEX payload.
   pub bytes: Vec<u8>,
}

/// Reports whether a ZIP container includes a conventional classes DEX entry.
///
/// # Errors
///
/// Returns an error when the reader does not hold a readable ZIP archive.
#[inline]
pub fn zip_contains_dex<R>(reader: R) -> Result<bool>
where
   R: Read + Seek,
{
   let archive = ZipArchive::new(reader)?;
   Ok(archive.file_names().any(is_classes_dex))
}

impl DexFile {
   /// Extracts conventional classes DEX entries from a ZIP container in name
   /// order.
   ///
   /// # Errors
   ///
   /// Returns an error when the reader does not hold a readable ZIP archive or
   /// a DEX entry cannot be inflated.
   #[inline]
   pub fn from_zip<R>(reader: R) -> Result<Vec<Self>>
   where
      R: Read + Seek,
   {
      let mut archive = ZipArchive::new(reader)?;
      let mut names = (0..archive.len())
         .filter_map(|index| {
            archive
               .by_index(index)
               .ok()
               .map(|entry| entry.name().to_owned())
         })
         .filter(|name| is_classes_dex(name))
         .collect::<Vec<_>>();
      names.sort();
      let mut sources = Vec::new();
      for name in names {
         let mut entry = archive.by_name(&name)?;
         let mut bytes = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or_default());
         entry.read_to_end(&mut bytes)?;
         sources.push(Self { name, bytes });
      }
      Ok(sources)
   }

   /// Extracts embedded standard DEX payloads from a VDEX container.
   ///
   /// # Errors
   ///
   /// Returns an error when an embedded DEX header is truncated or declares an
   /// impossible size, or [`Error::Unsupported`] when the container only holds
   /// compact DEX.
   #[inline]
   pub fn from_vdex(bytes: &[u8]) -> Result<Vec<Self>> {
      let mut sources = Vec::new();
      let mut offset = 0;
      while let Some(found) = bytes[offset..]
         .windows(4)
         .position(|window| window == b"dex\n")
      {
         let start = offset + found;
         let size_offset = start.checked_add(32).ok_or(Error::Overflow {
            what: "embedded dex size offset",
         })?;
         let size = Reader::at(bytes, size_offset).u32_usize()?;
         if size < 112 {
            return Err(Error::malformed(format!("embedded dex size {size}")));
         }
         let end = start.checked_add(size).ok_or(Error::Overflow {
            what: "embedded dex end offset",
         })?;
         if end > bytes.len() {
            return Err(Error::truncated("embedded dex", start, size, bytes.len()));
         }
         sources.push(Self {
            name:  format!("classes{}.dex", sources.len() + 1),
            bytes: bytes[start..end].to_vec(),
         });
         offset = end;
      }
      if sources.is_empty() && bytes.windows(4).any(|window| window == b"cdex") {
         return Err(Error::Unsupported {
            what: "compact dex container".to_owned(),
         });
      }
      Ok(sources)
   }
}

impl AsRef<[u8]> for DexFile {
   #[inline]
   fn as_ref(&self) -> &[u8] {
      &self.bytes
   }
}

/// Reports whether a ZIP entry name is `classes.dex` or `classesN.dex` in any
/// directory.
fn is_classes_dex(name: &str) -> bool {
   let file_name = name.rsplit('/').next().unwrap_or(name);
   if file_name == "classes.dex" {
      return true;
   }
   file_name
      .strip_prefix("classes")
      .and_then(|suffix| suffix.strip_suffix(".dex"))
      .is_some_and(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
}
