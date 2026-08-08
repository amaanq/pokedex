//! Owning DEX files with their resolved tables, methods, and annotations.

use std::{
   collections::BTreeMap,
   fmt,
   ops::Range,
   sync::Arc,
};

use crate::{
   annotation,
   bytecode::Code,
   error::{
      Error,
      Result,
      bail,
      ensure,
   },
   mutf8,
   reader::Reader,
   references::References,
};

/// An owning parsed DEX file with lazily decoded method bodies.
#[derive(Clone, Debug)]
pub struct Dex {
   /// The complete DEX file contents.
   bytes:       Vec<u8>,
   /// The methods defined by classes, in class data order.
   methods:     Vec<Method>,
   /// The decoded annotations.
   annotations: Vec<Annotation>,
   /// The resolved ID tables.
   references:  References,
   /// The descriptors of defined classes.
   classes:     Vec<String>,
}

/// A method definition encoded by a DEX class.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Method {
   /// The full `class->name prototype` signature.
   signature:    String,
   /// The byte length of the class descriptor prefix of `signature`.
   class_len:    usize,
   /// The byte length of the name following the `->` separator.
   name_len:     usize,
   /// The encoded access flags.
   access_flags: u32,
   /// The first source line from debug information.
   first_line:   Option<usize>,
   /// The byte offset of the code item, when the method has code.
   code_offset:  Option<usize>,
}

/// A decoded annotation attached to a DEX declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Annotation {
   /// The declaration the annotation applies to.
   target:     annotation::Target,
   /// The annotation type descriptor.
   descriptor: String,
   /// The encoded visibility.
   visibility: annotation::Visibility,
   /// The element values keyed by name.
   elements:   BTreeMap<String, annotation::Value>,
}

impl Dex {
   /// Parses and owns one complete standard DEX file.
   ///
   /// # Errors
   ///
   /// Returns an error when the header, ID tables, class data, or annotations
   /// are truncated, malformed, or reference entries outside their tables.
   #[inline]
   pub fn parse(bytes: Vec<u8>) -> Result<Self> {
      let tables = Parser::new(&bytes)?.parse()?;
      Ok(Self {
         bytes,
         methods: tables.methods,
         annotations: tables.annotations,
         references: tables.references,
         classes: tables.classes,
      })
   }

   /// Lazily decodes a method body when the method has code.
   ///
   /// The method must come from this file's [`Dex::methods`]. Passing a method
   /// from another file resolves its code offset against the wrong bytes.
   ///
   /// # Errors
   ///
   /// Returns an error when the code item is truncated or malformed, or when
   /// an instruction references a table entry that does not exist.
   #[inline]
   pub fn decode(&self, method: &Method) -> Result<Option<Code>> {
      let Some(code_offset) = method.code_offset else {
         return Ok(None);
      };
      Code::decode(&self.bytes, code_offset, &self.references).map(Some)
   }

   /// Returns the original DEX file contents.
   #[must_use]
   #[inline]
   pub fn bytes(&self) -> &[u8] {
      &self.bytes
   }

   /// Consumes the parsed DEX file and returns its original bytes.
   #[must_use]
   #[inline]
   pub fn into_bytes(self) -> Vec<u8> {
      self.bytes
   }

   /// Returns the decoded string table.
   #[must_use]
   #[inline]
   pub fn strings(&self) -> &[String] {
      &self.references.strings
   }

   /// Returns a string's MUTF-8 byte range, excluding its prefix and NUL.
   #[must_use]
   #[inline]
   pub fn string_range(&self, index: usize) -> Option<Range<usize>> {
      self.references.string_ranges.get(index).cloned()
   }

   /// Returns the resolved type descriptors.
   #[must_use]
   #[inline]
   pub fn types(&self) -> &[String] {
      &self.references.types
   }

   /// Returns the resolved method prototypes.
   #[must_use]
   #[inline]
   pub fn prototypes(&self) -> &[String] {
      &self.references.prototypes
   }

   /// Returns the resolved field signatures.
   #[must_use]
   #[inline]
   pub fn fields(&self) -> &[String] {
      &self.references.fields
   }

   /// Returns the method definitions encoded by classes.
   #[must_use]
   #[inline]
   pub fn methods(&self) -> &[Method] {
      &self.methods
   }

   /// Returns all method signatures referenced by the DEX method table.
   #[must_use]
   #[inline]
   pub fn method_references(&self) -> &[String] {
      &self.references.methods
   }

   /// Returns the resolved method handle descriptions.
   #[must_use]
   #[inline]
   pub fn method_handles(&self) -> &[String] {
      &self.references.method_handles
   }

   /// Returns the decoded call site value lists.
   #[must_use]
   #[inline]
   pub fn call_sites(&self) -> &[Arc<[annotation::Value]>] {
      &self.references.call_sites
   }

   /// Returns the class descriptors defined by the DEX file.
   #[must_use]
   #[inline]
   pub fn classes(&self) -> &[String] {
      &self.classes
   }

   /// Returns the decoded declaration annotations.
   #[must_use]
   #[inline]
   pub fn annotations(&self) -> &[Annotation] {
      &self.annotations
   }
}

impl Method {
   /// Returns the declaring class descriptor.
   #[must_use]
   #[inline]
   pub fn class(&self) -> &str {
      self.signature.get(..self.class_len).unwrap_or_default()
   }

   /// Returns the method name.
   #[must_use]
   #[inline]
   pub fn name(&self) -> &str {
      let start = self.class_len + 2;
      self
         .signature
         .get(start..start + self.name_len)
         .unwrap_or_default()
   }

   /// Returns the method prototype, including parameter and return types.
   #[must_use]
   #[inline]
   pub fn prototype(&self) -> &str {
      self
         .signature
         .get(self.class_len + 2 + self.name_len..)
         .unwrap_or_default()
   }

   /// Returns the fully resolved method signature.
   #[must_use]
   #[inline]
   pub fn signature(&self) -> &str {
      &self.signature
   }

   /// Reports whether the method carries a code item.
   #[must_use]
   #[inline]
   pub const fn has_code(&self) -> bool {
      self.code_offset.is_some()
   }

   /// Returns the byte offset of the code item when the method has code.
   #[must_use]
   #[inline]
   pub const fn code_offset(&self) -> Option<usize> {
      self.code_offset
   }

   /// Returns the encoded DEX access flags.
   #[must_use]
   #[inline]
   pub const fn access_flags(&self) -> u32 {
      self.access_flags
   }

   /// Returns the initial source line from debug information when present.
   #[must_use]
   #[inline]
   pub const fn first_line(&self) -> Option<usize> {
      self.first_line
   }
}

impl fmt::Display for Method {
   #[inline]
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str(&self.signature)
   }
}

impl Annotation {
   /// Returns the declaration targeted by the annotation.
   #[must_use]
   #[inline]
   pub const fn target(&self) -> &annotation::Target {
      &self.target
   }

   /// Returns the annotation type descriptor.
   #[must_use]
   #[inline]
   pub fn annotation_type(&self) -> &str {
      &self.descriptor
   }

   /// Returns the encoded annotation visibility.
   #[must_use]
   #[inline]
   pub const fn visibility(&self) -> annotation::Visibility {
      self.visibility
   }

   /// Returns the decoded annotation elements.
   #[must_use]
   #[inline]
   pub const fn elements(&self) -> &BTreeMap<String, annotation::Value> {
      &self.elements
   }
}

/// A resolved entry of the `field_ids` table.
struct FieldId {
   /// The declaring class descriptor.
   class:      String,
   /// The field name.
   name:       String,
   /// The field type descriptor.
   field_type: String,
}

impl FieldId {
   /// Returns the `name:type` member part of the signature.
   fn member(&self) -> String {
      format!("{}:{}", self.name, self.field_type)
   }
}

impl fmt::Display for FieldId {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{}->{}", self.class, self.member())
   }
}

/// A resolved entry of the `method_ids` table.
struct MethodId {
   /// The declaring class descriptor.
   class:     String,
   /// The method name.
   name:      String,
   /// The method prototype.
   prototype: String,
}

impl MethodId {
   /// Returns the `name(params)return` member part of the signature.
   fn member(&self) -> String {
      format!("{}{}", self.name, self.prototype)
   }
}

impl fmt::Display for MethodId {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{}->{}", self.class, self.member())
   }
}

/// Narrows an encoded value whose width was already validated against the
/// target type.
fn narrow<T, U>(value: T) -> Result<U>
where
   U: TryFrom<T>,
{
   U::try_from(value)
      .ok()
      .ok_or_else(|| Error::malformed("encoded value exceeds its declared width"))
}

/// Everything parsed from a DEX file besides the bytes themselves.
struct DexTables {
   /// The methods defined by classes.
   methods:     Vec<Method>,
   /// The decoded annotations.
   annotations: Vec<Annotation>,
   /// The resolved ID tables.
   references:  References,
   /// The descriptors of defined classes.
   classes:     Vec<String>,
}

/// Bounds-checked table indexing that reports [`Error::InvalidReference`].
trait Lookup<T> {
   /// Returns the entry at `index`, naming the table kind and the referrer on
   /// failure.
   fn lookup(&self, index: usize, kind: &'static str, context: impl Into<String>) -> Result<&T>;
}

impl<T> Lookup<T> for [T] {
   fn lookup(&self, index: usize, kind: &'static str, context: impl Into<String>) -> Result<&T> {
      self
         .get(index)
         .ok_or_else(|| Error::invalid_reference(context, kind, index, self.len()))
   }
}

/// A validated run of fixed-width table entries.
#[derive(Clone, Copy)]
struct TableRange<'dex> {
   /// The complete DEX file contents.
   bytes:  &'dex [u8],
   /// The number of entries.
   count:  usize,
   /// The byte offset of the first entry.
   offset: usize,
   /// The byte width of each entry.
   width:  usize,
}

impl<'dex> TableRange<'dex> {
   /// Validates that `count` entries of `width` bytes fit within the input.
   fn new(
      bytes: &'dex [u8],
      count: usize,
      offset: usize,
      width: usize,
      name: &str,
   ) -> Result<Self> {
      let length = count
         .checked_mul(width)
         .ok_or(Error::Overflow { what: "table size" })?;
      let end = offset.checked_add(length).ok_or(Error::Overflow {
         what: "table offset",
      })?;
      ensure!(end <= bytes.len(), "{name} table exceeds dex input");
      Ok(Self {
         bytes,
         count,
         offset,
         width,
      })
   }

   /// Returns the number of entries.
   const fn count(self) -> usize {
      self.count
   }

   /// Returns a reader positioned at the first entry.
   const fn reader(self) -> Reader<'dex> {
      Reader::at(self.bytes, self.offset)
   }
}

impl<'dex> IntoIterator for TableRange<'dex> {
   type IntoIter = Box<dyn Iterator<Item = Reader<'dex>> + 'dex>;
   type Item = Reader<'dex>;

   fn into_iter(self) -> Self::IntoIter {
      Box::new(
         (0..self.count).map(move |index| Reader::at(self.bytes, self.offset + index * self.width)),
      )
   }
}

/// Resolves the DEX ID tables in dependency order, keeping each resolved
/// table for the ones that follow.
struct Parser<'dex> {
   /// The complete DEX file contents.
   bytes:          &'dex [u8],
   /// The decoded `string_ids` table.
   strings:        Vec<String>,
   /// The `type_ids` table resolved to descriptors.
   types:          Vec<String>,
   /// The `proto_ids` table rendered as `(params)return`.
   prototypes:     Vec<String>,
   /// The resolved `field_ids` table.
   fields:         Vec<FieldId>,
   /// The resolved `method_ids` table.
   methods:        Vec<MethodId>,
   /// The `method_handle_items` rendered as `kind:target`.
   method_handles: Vec<String>,
}

impl<'dex> Parser<'dex> {
   /// Validates the header and creates a parser with empty tables.
   fn new(bytes: &'dex [u8]) -> Result<Self> {
      if bytes.len() < 112 {
         return Err(Error::truncated("dex header", 0, 112, bytes.len()));
      }
      if &bytes[..4] != b"dex\n" {
         return Err(Error::BadMagic);
      }
      let endianness = Reader::at(bytes, 40).u32()?;
      if endianness != 0x1234_5678 {
         return Err(Error::UnsupportedEndianness { value: endianness });
      }
      ensure!(
         Reader::at(bytes, 32).u32_usize()? <= bytes.len(),
         "dex file size exceeds input"
      );
      Ok(Self {
         bytes,
         strings: Vec::new(),
         types: Vec::new(),
         prototypes: Vec::new(),
         fields: Vec::new(),
         methods: Vec::new(),
         method_handles: Vec::new(),
      })
   }

   /// Resolves every table and class definition.
   fn parse(mut self) -> Result<DexTables> {
      let (strings, string_ranges) = self.read_strings()?;
      self.strings = strings;
      self.types = self.read_types()?;
      self.prototypes = self.read_prototypes()?;
      self.fields = self.read_field_ids()?;
      self.methods = self.read_method_ids()?;
      self.method_handles = self.read_method_handles()?;
      let call_sites = self.read_call_sites()?;
      let class_definitions = self.table(96, 32, "class definitions")?;
      let classes = self.read_class_names(class_definitions)?;
      let methods = self.read_class_methods(class_definitions)?;
      let annotations = self.read_annotations(class_definitions)?;
      Ok(DexTables {
         methods,
         annotations,
         references: References {
            fields: self.fields.iter().map(ToString::to_string).collect(),
            methods: self.methods.iter().map(ToString::to_string).collect(),
            strings: self.strings,
            string_ranges,
            types: self.types,
            prototypes: self.prototypes,
            method_handles: self.method_handles,
            call_sites,
         },
         classes,
      })
   }

   /// Reads a `(size, offset)` header pair into a validated table range.
   fn table(&self, header_offset: usize, width: usize, name: &str) -> Result<TableRange<'dex>> {
      let mut reader = Reader::at(self.bytes, header_offset);
      TableRange::new(
         self.bytes,
         reader.u32_usize()?,
         reader.u32_usize()?,
         width,
         name,
      )
   }

   /// Locates a map-list section by item type, if the file has one.
   fn map_section(
      &self,
      item_type: u16,
      item_width: usize,
      name: &str,
   ) -> Result<Option<TableRange<'dex>>> {
      let map_offset = Reader::at(self.bytes, 52).u32_usize()?;
      if map_offset == 0 {
         return Ok(None);
      }
      let map_count = Reader::at(self.bytes, map_offset).u32_usize()?;
      let map = TableRange::new(self.bytes, map_count, map_offset + 4, 12, "map")?;
      for mut entry in map {
         let entry_type = entry.u16()?;
         entry.skip(2)?;
         let count = entry.u32_usize()?;
         let offset = entry.u32_usize()?;
         if entry_type == item_type {
            return TableRange::new(self.bytes, count, offset, item_width, name).map(Some);
         }
      }
      Ok(None)
   }

   /// Decodes the `string_ids` table.
   fn read_strings(&self) -> Result<(Vec<String>, Vec<Range<usize>>)> {
      let bytes = self.bytes;
      let table = self.table(56, 4, "string IDs")?;
      let mut strings = Vec::with_capacity(table.count());
      let mut string_ranges = Vec::with_capacity(table.count());
      for (index, mut entry) in table.into_iter().enumerate() {
         let string_offset = entry.u32_usize()?;
         let mut reader = Reader::at(bytes, string_offset);
         let utf16_size = reader.uleb128_usize()?;
         let cursor = reader.position();
         let end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|length| cursor + length)
            .ok_or_else(|| Error::truncated("terminated dex string", cursor, 1, bytes.len()))?;
         strings.push(
            mutf8::decode(&bytes[cursor..end], utf16_size).map_err(|error| {
               Error::InvalidMutf8 {
                  offset: cursor,
                  reason: format!("dex string {index} {error}"),
               }
            })?,
         );
         string_ranges.push(cursor..end);
      }
      Ok((strings, string_ranges))
   }

   /// Resolves the `type_ids` table against the strings.
   fn read_types(&self) -> Result<Vec<String>> {
      self
         .table(64, 4, "type IDs")?
         .into_iter()
         .enumerate()
         .map(|(index, mut entry)| {
            let string_index = entry.u32_usize()?;
            self
               .strings
               .lookup(string_index, "string", format!("type {index}"))
               .cloned()
         })
         .collect()
   }

   /// Renders each `proto_ids` entry as `(params)return`.
   fn read_prototypes(&self) -> Result<Vec<String>> {
      let table = self.table(72, 12, "prototype IDs")?;
      let mut prototypes = Vec::with_capacity(table.count());
      for (index, mut entry) in table.into_iter().enumerate() {
         entry.skip(4)?;
         let return_index = entry.u32_usize()?;
         let return_type =
            self
               .types
               .lookup(return_index, "return type", format!("prototype {index}"))?;
         let parameters_offset = entry.u32_usize()?;
         let mut prototype = String::from("(");
         if parameters_offset != 0 {
            let mut parameter_header = Reader::at(self.bytes, parameters_offset);
            let parameter_count = parameter_header.u32_usize()?;
            let parameters = TableRange::new(
               self.bytes,
               parameter_count,
               parameters_offset + 4,
               2,
               "prototype parameters",
            )?;
            for mut parameter in parameters {
               let type_index = usize::from(parameter.u16()?);
               prototype.push_str(self.types.lookup(
                  type_index,
                  "parameter type",
                  format!("prototype {index}"),
               )?);
            }
         }
         prototype.push(')');
         prototype.push_str(return_type);
         prototypes.push(prototype);
      }
      Ok(prototypes)
   }

   /// Resolves the `field_ids` table.
   fn read_field_ids(&self) -> Result<Vec<FieldId>> {
      let table = self.table(80, 8, "field IDs")?;
      let mut fields = Vec::with_capacity(table.count());
      for (index, mut entry) in table.into_iter().enumerate() {
         let class_index = usize::from(entry.u16()?);
         let type_index = usize::from(entry.u16()?);
         let name_index = entry.u32_usize()?;
         fields.push(FieldId {
            class:      self
               .types
               .lookup(class_index, "class", format!("field {index}"))
               .cloned()?,
            name:       self
               .strings
               .lookup(name_index, "name", format!("field {index}"))
               .cloned()?,
            field_type: self
               .types
               .lookup(type_index, "type", format!("field {index}"))
               .cloned()?,
         });
      }
      Ok(fields)
   }

   /// Resolves the `method_ids` table.
   fn read_method_ids(&self) -> Result<Vec<MethodId>> {
      let table = self.table(88, 8, "method IDs")?;
      let mut methods = Vec::with_capacity(table.count());
      for (index, mut entry) in table.into_iter().enumerate() {
         let class_index = usize::from(entry.u16()?);
         let prototype_index = usize::from(entry.u16()?);
         let name_index = entry.u32_usize()?;
         methods.push(MethodId {
            class:     self
               .types
               .lookup(class_index, "class", format!("method {index}"))
               .cloned()?,
            name:      self
               .strings
               .lookup(name_index, "name", format!("method {index}"))
               .cloned()?,
            prototype: self
               .prototypes
               .lookup(prototype_index, "prototype", format!("method {index}"))
               .cloned()?,
         });
      }
      Ok(methods)
   }

   /// Renders the `method_handle_items` section as `kind:target` strings.
   fn read_method_handles(&self) -> Result<Vec<String>> {
      let Some(table) = self.map_section(0x0008, 8, "method handles")? else {
         return Ok(Vec::new());
      };
      let mut handles = Vec::with_capacity(table.count());
      for (index, mut entry) in table.into_iter().enumerate() {
         let kind = entry.u16()?;
         entry.skip(2)?;
         let target_index = usize::from(entry.u16()?);
         let (kind_name, target) = match kind {
            0 => ("static_put", self.field_signature(target_index)?),
            1 => ("static_get", self.field_signature(target_index)?),
            2 => ("instance_put", self.field_signature(target_index)?),
            3 => ("instance_get", self.field_signature(target_index)?),
            4 => ("invoke_static", self.method_signature(target_index)?),
            5 => ("invoke_instance", self.method_signature(target_index)?),
            6 => ("invoke_constructor", self.method_signature(target_index)?),
            7 => ("invoke_direct", self.method_signature(target_index)?),
            8 => ("invoke_interface", self.method_signature(target_index)?),
            _ => bail!("method handle {index} has invalid kind {kind}"),
         };
         handles.push(format!("{kind_name}:{target}"));
      }
      Ok(handles)
   }

   /// Decodes the `call_site_ids` section into encoded value lists.
   fn read_call_sites(&self) -> Result<Vec<Arc<[annotation::Value]>>> {
      let Some(table) = self.map_section(0x0007, 4, "call site IDs")? else {
         return Ok(Vec::new());
      };
      let mut call_sites = Vec::with_capacity(table.count());
      for (index, mut entry) in table.into_iter().enumerate() {
         let value_offset = entry.u32_usize()?;
         let mut reader = Reader::at(self.bytes, value_offset);
         let value_count = reader.uleb128_usize()?;
         ensure!(
            value_count >= 3,
            "call site {index} has fewer than three values"
         );
         let mut values = Vec::with_capacity(value_count);
         for _ in 0..value_count {
            values.push(self.encoded_value(&mut reader, 0)?);
         }
         call_sites.push(values.into());
      }
      Ok(call_sites)
   }

   /// Reads the descriptor of each class definition.
   fn read_class_names(&self, table: TableRange<'_>) -> Result<Vec<String>> {
      table
         .into_iter()
         .map(|mut entry| {
            let class_index = entry.u32_usize()?;
            self
               .types
               .lookup(class_index, "type", "class definition")
               .cloned()
         })
         .collect()
   }

   /// Reads the direct and virtual methods of every class with class data.
   fn read_class_methods(&self, table: TableRange<'_>) -> Result<Vec<Method>> {
      let mut methods = Vec::new();
      for mut entry in table {
         entry.skip(24)?;
         let class_data_offset = entry.u32_usize()?;
         if class_data_offset == 0 {
            continue;
         }
         let mut reader = Reader::at(self.bytes, class_data_offset);
         let static_fields = reader.uleb128_usize()?;
         let instance_fields = reader.uleb128_usize()?;
         let direct_methods = reader.uleb128_usize()?;
         let virtual_methods = reader.uleb128_usize()?;
         for _ in 0..static_fields + instance_fields {
            reader.uleb128()?;
            reader.uleb128()?;
         }
         self.read_encoded_methods(&mut reader, direct_methods, &mut methods)?;
         self.read_encoded_methods(&mut reader, virtual_methods, &mut methods)?;
      }
      Ok(methods)
   }

   /// Reads `count` encoded methods, resolving their delta-encoded method
   /// indexes.
   fn read_encoded_methods(
      &self,
      reader: &mut Reader<'_>,
      count: usize,
      methods: &mut Vec<Method>,
   ) -> Result<()> {
      let mut method_index = 0_usize;
      for _ in 0..count {
         method_index =
            method_index
               .checked_add(reader.uleb128_usize()?)
               .ok_or(Error::Overflow {
                  what: "method index",
               })?;
         let access_flags = u32::try_from(reader.uleb128()?)
            .ok()
            .ok_or_else(|| Error::malformed("method access flags exceed u32"))?;
         let code_offset = reader.uleb128_usize()?;
         let method = self
            .methods
            .lookup(method_index, "method", "encoded method")?;
         let first_line = if code_offset == 0 {
            None
         } else {
            let debug_info_offset = Reader::at(self.bytes, code_offset + 8).u32_usize()?;
            if debug_info_offset == 0 {
               None
            } else {
               Some(Reader::at(self.bytes, debug_info_offset).uleb128_usize()?)
            }
         };
         methods.push(Method {
            signature: method.to_string(),
            class_len: method.class.len(),
            name_len: method.name.len(),
            access_flags,
            first_line,
            code_offset: (code_offset != 0).then_some(code_offset),
         });
      }
      Ok(())
   }

   /// Decodes the annotation directory of every class definition that has one.
   fn read_annotations(&self, table: TableRange<'_>) -> Result<Vec<Annotation>> {
      let mut annotations = Vec::new();
      for mut entry in table {
         let class_index = entry.u32_usize()?;
         let class = self.types.lookup(class_index, "type", "class definition")?;
         entry.skip(16)?;
         let directory_offset = entry.u32_usize()?;
         if directory_offset != 0 {
            self.annotation_directory(class, directory_offset, &mut annotations)?;
         }
      }
      Ok(annotations)
   }

   /// Decodes class, field, method, and parameter annotation sets of one
   /// directory.
   fn annotation_directory(
      &self,
      class: &str,
      offset: usize,
      annotations: &mut Vec<Annotation>,
   ) -> Result<()> {
      let mut header = Reader::at(self.bytes, offset);
      let class_annotations_offset = header.u32_usize()?;
      let field_count = header.u32_usize()?;
      let method_count = header.u32_usize()?;
      let parameter_count = header.u32_usize()?;
      let entry_count = field_count
         .checked_add(method_count)
         .and_then(|count| count.checked_add(parameter_count))
         .ok_or(Error::Overflow {
            what: "annotation directory size",
         })?;
      let entries = TableRange::new(
         self.bytes,
         entry_count,
         offset + 16,
         8,
         "annotation directory",
      )?;

      if class_annotations_offset != 0 {
         self.annotation_set(
            &annotation::Target {
               kind:            annotation::TargetKind::Class,
               class:           class.to_owned(),
               member:          None,
               parameter_index: None,
            },
            class_annotations_offset,
            annotations,
         )?;
      }

      let mut reader = entries.reader();
      for _ in 0..field_count {
         let field_index = reader.u32_usize()?;
         let annotations_offset = reader.u32_usize()?;
         let field = self.fields.lookup(field_index, "field", "annotation")?;
         self.annotation_set(
            &annotation::Target {
               kind:            annotation::TargetKind::Field,
               class:           field.class.clone(),
               member:          Some(field.member()),
               parameter_index: None,
            },
            annotations_offset,
            annotations,
         )?;
      }
      for _ in 0..method_count {
         let method_index = reader.u32_usize()?;
         let annotations_offset = reader.u32_usize()?;
         let method = self.methods.lookup(method_index, "method", "annotation")?;
         self.annotation_set(
            &annotation::Target {
               kind:            annotation::TargetKind::Method,
               class:           method.class.clone(),
               member:          Some(method.member()),
               parameter_index: None,
            },
            annotations_offset,
            annotations,
         )?;
      }
      for _ in 0..parameter_count {
         let method_index = reader.u32_usize()?;
         let annotation_list_offset = reader.u32_usize()?;
         let method = self.methods.lookup(method_index, "method", "annotation")?;
         self.parameter_annotations(method, annotation_list_offset, annotations)?;
      }
      Ok(())
   }

   /// Decodes the per-parameter annotation sets of one method.
   fn parameter_annotations(
      &self,
      method: &MethodId,
      offset: usize,
      annotations: &mut Vec<Annotation>,
   ) -> Result<()> {
      let count = Reader::at(self.bytes, offset).u32_usize()?;
      let entries = TableRange::new(
         self.bytes,
         count,
         offset + 4,
         4,
         "parameter annotation list",
      )?;
      for (parameter_index, mut entry) in entries.into_iter().enumerate() {
         let annotations_offset = entry.u32_usize()?;
         if annotations_offset == 0 {
            continue;
         }
         self.annotation_set(
            &annotation::Target {
               kind:            annotation::TargetKind::Parameter,
               class:           method.class.clone(),
               member:          Some(method.member()),
               parameter_index: Some(parameter_index),
            },
            annotations_offset,
            annotations,
         )?;
      }
      Ok(())
   }

   /// Decodes every annotation in one annotation set for `target`.
   fn annotation_set(
      &self,
      target: &annotation::Target,
      offset: usize,
      annotations: &mut Vec<Annotation>,
   ) -> Result<()> {
      let count = Reader::at(self.bytes, offset).u32_usize()?;
      let entries = TableRange::new(self.bytes, count, offset + 4, 4, "annotation set")?;
      for mut entry in entries {
         let annotation_offset = entry.u32_usize()?;
         let mut reader = Reader::at(self.bytes, annotation_offset);
         let visibility = match reader.u8()? {
            0 => annotation::Visibility::Build,
            1 => annotation::Visibility::Runtime,
            2 => annotation::Visibility::System,
            value => bail!("annotation has invalid visibility {value}"),
         };
         let (descriptor, elements) = self.encoded_annotation(&mut reader, 0)?;
         annotations.push(Annotation {
            target: target.clone(),
            descriptor,
            visibility,
            elements,
         });
      }
      Ok(())
   }

   /// Decodes an `encoded_annotation` into its type and named elements.
   fn encoded_annotation(
      &self,
      reader: &mut Reader<'_>,
      depth: usize,
   ) -> Result<(String, BTreeMap<String, annotation::Value>)> {
      ensure!(depth < 64, "annotation nesting exceeds 64 levels");
      let type_index = reader.uleb128_usize()?;
      let annotation_type = self
         .types
         .lookup(type_index, "type", "annotation")
         .cloned()?;
      let count = reader.uleb128_usize()?;
      ensure!(
         count <= reader.remaining(),
         "annotation element count exceeds remaining input"
      );
      let mut elements = BTreeMap::new();
      for _ in 0..count {
         let name_index = reader.uleb128_usize()?;
         let name = self
            .strings
            .lookup(name_index, "name", "annotation")
            .cloned()?;
         let value = self.encoded_value(reader, depth + 1)?;
         ensure!(
            elements.insert(name.clone(), value).is_none(),
            "annotation repeats element {name}"
         );
      }
      Ok((annotation_type, elements))
   }

   /// Decodes one `encoded_value`, recursing into arrays and nested
   /// annotations.
   #[expect(clippy::too_many_lines, reason = "one arm per encoded value type")]
   fn encoded_value(&self, reader: &mut Reader<'_>, depth: usize) -> Result<annotation::Value> {
      ensure!(depth < 64, "annotation value nesting exceeds 64 levels");
      let header = reader.u8()?;
      let value_type = header & 0x1F;
      let value_arg = usize::from(header >> 5_u32);
      let size = value_arg + 1;
      match value_type {
         0x00 => {
            ensure!(value_arg == 0, "byte annotation value has invalid width");
            Ok(annotation::Value::Byte(narrow(
               reader.encoded_signed(size)?,
            )?))
         },
         0x02 => {
            ensure!(value_arg <= 1, "short annotation value has invalid width");
            Ok(annotation::Value::Short(narrow(
               reader.encoded_signed(size)?,
            )?))
         },
         0x03 => {
            ensure!(value_arg <= 1, "char annotation value has invalid width");
            Ok(annotation::Value::Char(narrow(
               reader.encoded_unsigned(size)?,
            )?))
         },
         0x04 => {
            ensure!(value_arg <= 3, "int annotation value has invalid width");
            Ok(annotation::Value::Int(narrow(
               reader.encoded_signed(size)?,
            )?))
         },
         0x06 => Ok(annotation::Value::Long(reader.encoded_signed(size)?)),
         0x10 => {
            ensure!(value_arg <= 3, "float annotation value has invalid width");
            let bits = narrow(reader.encoded_unsigned(size)? << ((4 - size) * 8))?;
            Ok(annotation::Value::Float(bits))
         },
         0x11 => {
            let bits = reader.encoded_unsigned(size)? << ((8 - size) * 8);
            Ok(annotation::Value::Double(bits))
         },
         0x15 => {
            ensure!(value_arg <= 3, "method type value has invalid width");
            let index = reader.encoded_index(size)?;
            Ok(annotation::Value::MethodType(
               self
                  .prototypes
                  .lookup(index, "prototype", "annotation")
                  .cloned()?,
            ))
         },
         0x16 => {
            ensure!(value_arg <= 3, "method handle value has invalid width");
            let index = reader.encoded_index(size)?;
            Ok(annotation::Value::MethodHandle(
               self
                  .method_handles
                  .lookup(index, "method handle", "annotation")
                  .cloned()?,
            ))
         },
         0x17 => {
            ensure!(value_arg <= 3, "string annotation value has invalid width");
            let index = reader.encoded_index(size)?;
            Ok(annotation::Value::String(
               self
                  .strings
                  .lookup(index, "string", "annotation")
                  .cloned()?,
            ))
         },
         0x18 => {
            ensure!(value_arg <= 3, "type annotation value has invalid width");
            let index = reader.encoded_index(size)?;
            Ok(annotation::Value::Type(
               self.types.lookup(index, "type", "annotation").cloned()?,
            ))
         },
         0x19 => {
            ensure!(value_arg <= 3, "field annotation value has invalid width");
            let index = reader.encoded_index(size)?;
            Ok(annotation::Value::Field(self.field_signature(index)?))
         },
         0x1A => {
            ensure!(value_arg <= 3, "method annotation value has invalid width");
            let index = reader.encoded_index(size)?;
            Ok(annotation::Value::Method(self.method_signature(index)?))
         },
         0x1B => {
            ensure!(value_arg <= 3, "enum annotation value has invalid width");
            let index = reader.encoded_index(size)?;
            Ok(annotation::Value::Enum(self.field_signature(index)?))
         },
         0x1C => {
            ensure!(
               value_arg == 0,
               "array annotation value has invalid argument"
            );
            let count = reader.uleb128_usize()?;
            ensure!(
               count <= reader.remaining(),
               "annotation array count exceeds remaining input"
            );
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
               values.push(self.encoded_value(reader, depth + 1)?);
            }
            Ok(annotation::Value::Array(values))
         },
         0x1D => {
            ensure!(value_arg == 0, "nested annotation has invalid argument");
            let (annotation_type, elements) = self.encoded_annotation(reader, depth + 1)?;
            Ok(annotation::Value::Annotation {
               annotation_type,
               elements,
            })
         },
         0x1E => {
            ensure!(value_arg == 0, "null annotation value has invalid argument");
            Ok(annotation::Value::Null)
         },
         0x1F => {
            ensure!(
               value_arg <= 1,
               "boolean annotation value has invalid argument"
            );
            Ok(annotation::Value::Boolean(value_arg != 0))
         },
         _ => bail!("unsupported annotation value type 0x{value_type:02x}"),
      }
   }

   /// Renders the field at `index` as a signature.
   fn field_signature(&self, index: usize) -> Result<String> {
      self
         .fields
         .lookup(index, "field", "annotation")
         .map(ToString::to_string)
   }

   /// Renders the method at `index` as a signature.
   fn method_signature(&self, index: usize) -> Result<String> {
      self
         .methods
         .lookup(index, "method", "annotation")
         .map(ToString::to_string)
   }
}
