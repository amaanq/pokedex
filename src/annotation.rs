//! Annotation targets, visibility, and encoded values.

use std::collections::BTreeMap;

/// A class, field, method, or parameter targeted by an annotation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Target {
   /// The declaration category receiving the annotation.
   pub kind:            TargetKind,
   /// The descriptor of the declaring class.
   pub class:           String,
   /// The field or method signature when the target is a member.
   #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
   pub member:          Option<String>,
   /// The zero-based parameter index when the target is a parameter.
   #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
   pub parameter_index: Option<usize>,
}

/// The declaration category receiving an annotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TargetKind {
   /// A class definition.
   Class,
   /// A field definition.
   Field,
   /// A method definition.
   Method,
   /// A method parameter.
   Parameter,
}

/// The encoded runtime visibility of an annotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Visibility {
   /// An annotation retained only in build artifacts.
   Build,
   /// An annotation visible through runtime reflection.
   Runtime,
   /// An annotation retained for platform tooling.
   System,
}

/// A fully resolved value stored in an encoded annotation element.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(
   feature = "serde",
   serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Value {
   /// An 8-bit signed integer.
   Byte(i8),
   /// A 16-bit signed integer.
   Short(i16),
   /// A UTF-16 code unit.
   Char(u16),
   /// A 32-bit signed integer.
   Int(i32),
   /// A 64-bit signed integer.
   Long(i64),
   /// A single-precision floating-point bit pattern.
   Float(u32),
   /// A double-precision floating-point bit pattern.
   Double(u64),
   /// A resolved method prototype.
   MethodType(String),
   /// A resolved method handle.
   MethodHandle(String),
   /// A decoded DEX string.
   String(String),
   /// A resolved type descriptor.
   Type(String),
   /// A resolved field signature.
   Field(String),
   /// A resolved method signature.
   Method(String),
   /// A resolved enum field signature.
   Enum(String),
   /// An ordered array of annotation values.
   Array(Vec<Self>),
   /// A nested encoded annotation.
   Annotation {
      /// The nested annotation type descriptor.
      annotation_type: String,
      /// The nested annotation elements keyed by name.
      elements:        BTreeMap<String, Self>,
   },
   /// The null annotation value.
   Null,
   /// A boolean annotation value.
   Boolean(bool),
}
