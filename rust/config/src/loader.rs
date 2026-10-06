// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::path::PathBuf;

use saphyr::MappingOwned;
use saphyr::ScalarOwned;
use saphyr::Tag;
use saphyr::YamlOwned;

use crate::Config;
use crate::ParseError;
use thiserror::Error;

const INCLUDE_RECURSION_LIMIT: usize = 128;

/// Errors returned while loading a configuration file.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("invalid include directive: {0}")]
    InvalidInclude(String),
    #[error("maximum include recursion level reached ({0})")]
    IncludeRecursionLimit(usize),
    #[error("invalid dotted key {key:?}: {reason}")]
    InvalidDottedKey { key: String, reason: String },
}

/// Parse a configuration file and apply transformations (includes, etc).
///
/// Relative include paths, including those in included files, are
/// resolved from the directory of this file.
pub fn load_file(path: &Path) -> Result<Config, LoadError> {
    let include_dir = path.parent().unwrap_or_else(|| Path::new("."));
    load_file_with_include_dir(path, include_dir)
}

/// Parse a configuration file and apply transformations (includes, etc).
///
/// Relative include paths, including those in included files, are
/// resolved from `include_dir`. This matches the C loader, which resolves
/// all includes from the directory of the top-level configuration file.
pub fn load_file_with_include_dir(path: &Path, include_dir: &Path) -> Result<Config, LoadError> {
    let config = load_yaml_file(path)?;

    finalize_config(config, include_dir)
}

/// Parse a configuration string and apply transformations (includes, etc).
pub fn load_string(input: &str) -> Result<Config, LoadError> {
    let config = crate::parse_yaml(input)?;
    finalize_config(config, Path::new("."))
}

// Apply all post-parse loader transformations to a parsed config tree.
fn finalize_config(config: Config, include_dir: &Path) -> Result<Config, LoadError> {
    resolve_value(config, include_dir, 0)
}

// Read and parse one YAML file without applying loader transformations.
fn load_yaml_file(path: &Path) -> Result<Config, LoadError> {
    let input = std::fs::read_to_string(path)?;
    crate::parse_yaml(&input).map_err(LoadError::from)
}

// Resolve includes and dotted keys in a parsed node, and remove YAML tags.
fn resolve_value(
    node: YamlOwned, include_dir: &Path, depth: usize,
) -> Result<YamlOwned, LoadError> {
    match node {
        YamlOwned::Mapping(mapping) => {
            let mut resolved = MappingOwned::new();
            for (key, value) in mapping {
                apply_entry(&mut resolved, key, value, include_dir, depth)?;
            }
            Ok(YamlOwned::Mapping(resolved))
        }
        YamlOwned::Sequence(sequence) => sequence
            .into_iter()
            .map(|value| resolve_value(value, include_dir, depth))
            .collect::<Result<Vec<_>, _>>()
            .map(YamlOwned::Sequence),
        YamlOwned::Tagged(_, value) => resolve_value(*value, include_dir, depth),
        other => Ok(other),
    }
}

/// Apply one mapping entry to the target mapping.
///
/// Entries are applied in document order with last-writer-wins
/// semantics, matching the C loader:
///
/// - An `include:` key inlines the entries of the included file(s) at
///   this point, so later entries override them.
/// - A dotted key walks the path below the target, creating mappings as
///   needed, and merges the value into the node found there. Numeric
///   path segments index into sequences.
/// - Any other key replaces an existing value.
fn apply_entry(
    target: &mut MappingOwned, key: YamlOwned, value: YamlOwned, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    let key = unwrap_tagged_values(key);

    if key.as_str() == Some("include") {
        return inline_include_value(target, &value, include_dir, depth + 1);
    }

    match include_path_from_tag(&value)? {
        Some(include_name) => {
            let included = load_include(include_dir, include_name, depth + 1)?;
            set_entry(target, key, included, include_dir, depth + 1)
        }
        None => set_entry(target, key, value, include_dir, depth),
    }
}

// Set the value for a plain or dotted key in the target mapping.
fn set_entry(
    target: &mut MappingOwned, key: YamlOwned, value: YamlOwned, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    match dotted_key_segments(&key) {
        Some(segments) => {
            let node = dotted_path_node(target, &segments).map_err(|reason| {
                LoadError::InvalidDottedKey {
                    key: segments.join("."),
                    reason,
                }
            })?;
            merge_value(node, value, include_dir, depth)
        }
        None => {
            let value = resolve_value(value, include_dir, depth)?;
            upsert_mapping_entry(target, key, value);
            Ok(())
        }
    }
}

// Merge a value into an existing node. A mapping value merged into a
// mapping is applied entry by entry, anything else replaces the node.
fn merge_value(
    node: &mut YamlOwned, value: YamlOwned, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    match (node, strip_tags(value)) {
        (YamlOwned::Mapping(existing), YamlOwned::Mapping(entries)) => {
            for (key, value) in entries {
                apply_entry(existing, key, value, include_dir, depth)?;
            }
            Ok(())
        }
        (node, value) => {
            *node = resolve_value(value, include_dir, depth)?;
            Ok(())
        }
    }
}

// Remove the outer YAML tags from a node.
fn strip_tags(mut node: YamlOwned) -> YamlOwned {
    while let YamlOwned::Tagged(_, value) = node {
        node = *value;
    }
    node
}

// Extract the include filename from a !include tag if present.
fn include_path_from_tag(node: &YamlOwned) -> Result<Option<&str>, LoadError> {
    if let YamlOwned::Tagged(tag, value) = node {
        if is_include_tag(tag) {
            let Some(include_name) = value.as_str() else {
                return Err(LoadError::InvalidInclude(
                    "!include value must be a string".into(),
                ));
            };
            return Ok(Some(include_name));
        }
    }

    Ok(None)
}

// Inline one include value which can be a filename or a list of filenames.
fn inline_include_value(
    mapping: &mut MappingOwned, include_value: &YamlOwned, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    if include_value.is_null() {
        return Ok(());
    }

    if let Some(include_name) = include_value.as_str() {
        return inline_include_file(mapping, include_name, include_dir, depth);
    }

    let Some(sequence) = include_value.as_sequence() else {
        return Err(LoadError::InvalidInclude(
            "\"include\" expects a filename or a sequence of filenames".into(),
        ));
    };

    for entry in sequence {
        if entry.is_null() {
            continue;
        }

        let Some(include_name) = entry.as_str() else {
            return Err(LoadError::InvalidInclude(
                "\"include\" sequence entries must be strings".into(),
            ));
        };

        inline_include_file(mapping, include_name, include_dir, depth)?;
    }

    Ok(())
}

// Load one include file and apply the entries of its root mapping to the
// target mapping.
fn inline_include_file(
    mapping: &mut MappingOwned, include_name: &str, include_dir: &Path, depth: usize,
) -> Result<(), LoadError> {
    let included = load_include(include_dir, include_name, depth)?;

    let YamlOwned::Mapping(included_mapping) = strip_tags(included) else {
        return Err(LoadError::InvalidInclude(format!(
            "included file {include_name:?} must contain a mapping at the document root"
        )));
    };

    for (key, value) in included_mapping {
        apply_entry(mapping, key, value, include_dir, depth)?;
    }

    Ok(())
}

// Insert a key/value pair or overwrite the existing value for that key.
fn upsert_mapping_entry(mapping: &mut MappingOwned, key: YamlOwned, value: YamlOwned) {
    if let Some(existing) = mapping.get_mut(&key) {
        *existing = value;
    } else {
        mapping.insert(key, value);
    }
}

// Remove all YAML tag wrappers from a parsed config tree.
fn unwrap_tagged_values(node: YamlOwned) -> YamlOwned {
    match node {
        YamlOwned::Tagged(_, value) => unwrap_tagged_values(*value),
        YamlOwned::Mapping(mapping) => {
            let mut unwrapped = MappingOwned::new();
            for (key, value) in mapping {
                unwrapped.insert(unwrap_tagged_values(key), unwrap_tagged_values(value));
            }
            YamlOwned::Mapping(unwrapped)
        }
        YamlOwned::Sequence(sequence) => {
            YamlOwned::Sequence(sequence.into_iter().map(unwrap_tagged_values).collect())
        }
        other => other,
    }
}

// Split a dotted mapping key into path segments when applicable.
fn dotted_key_segments(key: &YamlOwned) -> Option<Vec<&str>> {
    let key = key.as_str()?;
    if !key.contains('.') {
        return None;
    }

    let segments = key.split('.').collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }

    Some(segments)
}

// Walk a dotted key path below a mapping and return the node at the end
// of the path, creating missing nodes along the way. Errors are returned
// as a reason string.
fn dotted_path_node<'a>(
    mapping: &'a mut MappingOwned, segments: &[&str],
) -> Result<&'a mut YamlOwned, String> {
    let Some((first, rest)) = segments.split_first() else {
        return Err("empty key".into());
    };

    let child = dotted_mapping_child(mapping, first)?;
    descend_dotted_path(child, rest)
}

// Continue walking a dotted key path below a node.
//
// Like the C configuration tree, a numeric segment selects a sequence
// entry. An index one past the end appends a new entry. A node that is
// neither a mapping nor a sequence is replaced with a mapping.
fn descend_dotted_path<'a>(
    node: &'a mut YamlOwned, segments: &[&str],
) -> Result<&'a mut YamlOwned, String> {
    let Some((first, rest)) = segments.split_first() else {
        return Ok(node);
    };

    if !matches!(node, YamlOwned::Mapping(_) | YamlOwned::Sequence(_)) {
        *node = YamlOwned::Mapping(MappingOwned::new());
    }

    let child = match node {
        YamlOwned::Mapping(mapping) => dotted_mapping_child(mapping, first)?,
        YamlOwned::Sequence(sequence) => {
            let Some(index) = first
                .parse::<usize>()
                .ok()
                .filter(|index| *index <= sequence.len())
            else {
                return Err(format!(
                    "{first:?} is not a valid index for a sequence of length {}",
                    sequence.len()
                ));
            };
            if index == sequence.len() {
                sequence.push(YamlOwned::Value(ScalarOwned::Null));
            }
            &mut sequence[index]
        }
        _ => {
            return Err(format!("cannot descend into {first:?}"));
        }
    };

    descend_dotted_path(child, rest)
}

// Return the child of a mapping for a dotted-path segment, inserting a
// null child if missing. Existing entries keep their position.
fn dotted_mapping_child<'a>(
    mapping: &'a mut MappingOwned, segment: &str,
) -> Result<&'a mut YamlOwned, String> {
    let key = dotted_segment_key(segment);
    if !mapping.contains_key(&key) {
        mapping.insert(key.clone(), YamlOwned::Value(ScalarOwned::Null));
    }
    mapping
        .get_mut(&key)
        .ok_or_else(|| format!("failed to insert {segment:?}"))
}

// Build a YAML string key node for a dotted-path segment.
fn dotted_segment_key(segment: &str) -> YamlOwned {
    YamlOwned::Value(ScalarOwned::String(segment.into()))
}

// Resolve and load one include file. Relative paths are resolved from
// the top-level include directory, also for includes in included files.
fn load_include(include_dir: &Path, include_name: &str, depth: usize) -> Result<Config, LoadError> {
    if depth > INCLUDE_RECURSION_LIMIT {
        return Err(LoadError::IncludeRecursionLimit(INCLUDE_RECURSION_LIMIT));
    }

    let include_path = if Path::new(include_name).is_absolute() {
        PathBuf::from(include_name)
    } else {
        include_dir.join(include_name)
    };

    load_yaml_file(&include_path)
}

// Check whether a YAML tag corresponds to !include.
fn is_include_tag(tag: &Tag) -> bool {
    tag.handle == "!" && tag.suffix == "include"
}
