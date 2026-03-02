// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashSet;
use std::fmt;

use jsonschema::output::BasicOutput;
use jsonschema::Draft;
use jsonschema::JSONSchema;
use saphyr::ScalarOwned;
use saphyr::YamlOwned;
use serde_json::Map;
use serde_json::Value;

/// One schema validation issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Convert a parsed Suricata config tree into JSON values used by schema validation.
pub fn config_to_json(config: &YamlOwned) -> Value {
    yaml_to_json(config)
}

/// Validate one JSON document against a JSON Schema using the `jsonschema` crate.
///
/// Returns all validation issues. If the schema itself is invalid, one root-level
/// issue is returned with details.
pub fn validate_json_schema(instance: &Value, schema: &Value) -> Vec<ValidationError> {
    let compiled = match JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
    {
        Ok(compiled) => compiled,
        Err(err) => {
            return vec![ValidationError {
                path: "/".into(),
                message: format!("invalid schema: {err}"),
            }];
        }
    };

    let mut issues = match compiled.apply(instance).basic() {
        BasicOutput::Valid(_) => Vec::new(),
        BasicOutput::Invalid(errors) => errors
            .into_iter()
            .map(|error| DetailedValidationIssue {
                path: json_pointer_or_root(error.instance_location().to_string()),
                schema_path: json_pointer_or_root(error.keyword_location().to_string()),
                message: error.error_description().to_string(),
            })
            .collect(),
    };

    issues = dedupe_issues(issues);
    issues = filter_generic_combinator_issues(issues);
    issues = filter_redundant_branch_issues(issues);
    issues.sort_by(|lhs, rhs| {
        pointer_depth(&rhs.path)
            .cmp(&pointer_depth(&lhs.path))
            .then_with(|| lhs.path.cmp(&rhs.path))
            .then_with(|| lhs.message.cmp(&rhs.message))
    });

    issues
        .into_iter()
        .map(|issue| ValidationError {
            path: issue.path,
            message: issue.message,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DetailedValidationIssue {
    path: String,
    schema_path: String,
    message: String,
}

fn dedupe_issues(issues: Vec<DetailedValidationIssue>) -> Vec<DetailedValidationIssue> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut unique = Vec::new();

    for issue in issues {
        let key = (issue.path.clone(), issue.message.clone());
        if seen.insert(key) {
            unique.push(issue);
        }
    }

    unique
}

fn filter_generic_combinator_issues(
    issues: Vec<DetailedValidationIssue>,
) -> Vec<DetailedValidationIssue> {
    let has_specific_issue = issues
        .iter()
        .any(|issue| !is_generic_combinator_issue(issue));

    if !has_specific_issue {
        return issues;
    }

    issues
        .into_iter()
        .filter(|issue| !is_generic_combinator_issue(issue))
        .collect()
}

fn filter_redundant_branch_issues(
    issues: Vec<DetailedValidationIssue>,
) -> Vec<DetailedValidationIssue> {
    let filtered: Vec<DetailedValidationIssue> = issues
        .iter()
        .filter(|issue| !is_redundant_branch_issue(issue, &issues))
        .cloned()
        .collect();

    if filtered.is_empty() {
        issues
    } else {
        filtered
    }
}

fn is_redundant_branch_issue(
    issue: &DetailedValidationIssue, issues: &[DetailedValidationIssue],
) -> bool {
    if is_type_issue(issue)
        && issues
            .iter()
            .any(|other| other.path == issue.path && is_additional_properties_issue(other))
    {
        return true;
    }

    if is_additional_properties_issue(issue)
        && additional_properties_shadowed_by_nested_issue(issue, issues)
    {
        return true;
    }

    false
}

fn is_additional_properties_issue(issue: &DetailedValidationIssue) -> bool {
    issue
        .message
        .starts_with("Additional properties are not allowed")
}

fn is_type_issue(issue: &DetailedValidationIssue) -> bool {
    issue.message.contains(" is not of type ")
}

fn additional_properties_shadowed_by_nested_issue(
    issue: &DetailedValidationIssue, issues: &[DetailedValidationIssue],
) -> bool {
    let Some(unexpected_key) = first_unexpected_property_name(&issue.message) else {
        return false;
    };

    let base = if issue.path == "/" {
        String::new()
    } else {
        issue.path.clone()
    };
    let property_path = format!("{base}/{unexpected_key}");

    issues.iter().any(|other| {
        (other.path == property_path
            || other
                .path
                .strip_prefix(&property_path)
                .is_some_and(|suffix| suffix.starts_with('/')))
            && !is_additional_properties_issue(other)
    })
}

fn first_unexpected_property_name(message: &str) -> Option<&str> {
    if !message.starts_with("Additional properties are not allowed") {
        return None;
    }

    message.split('\'').nth(1).filter(|key| !key.is_empty())
}

fn is_generic_combinator_issue(issue: &DetailedValidationIssue) -> bool {
    if !(issue.schema_path.ends_with("/anyOf") || issue.schema_path.ends_with("/oneOf")) {
        return false;
    }

    issue
        .message
        .contains("is not valid under any of the given schemas")
        || issue
            .message
            .contains("is valid under more than one of the given schemas")
}

fn pointer_depth(path: &str) -> usize {
    if path == "/" {
        return 0;
    }

    path.split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

fn yaml_to_json(node: &YamlOwned) -> Value {
    match node {
        YamlOwned::Value(ScalarOwned::Null) => Value::Null,
        YamlOwned::Value(ScalarOwned::String(value)) => Value::String(value.clone()),
        YamlOwned::Value(ScalarOwned::Integer(value)) => Value::Number((*value).into()),
        YamlOwned::Value(ScalarOwned::FloatingPoint(value)) => {
            match serde_json::Number::from_f64((*value).into_inner()) {
                Some(number) => Value::Number(number),
                None => Value::Null,
            }
        }
        YamlOwned::Value(ScalarOwned::Boolean(value)) => Value::Bool(*value),
        YamlOwned::Mapping(mapping) => {
            let mut object = Map::new();
            for (key, value) in mapping {
                object.insert(yaml_key_to_string(key), yaml_to_json(value));
            }
            Value::Object(object)
        }
        YamlOwned::Sequence(sequence) => Value::Array(sequence.iter().map(yaml_to_json).collect()),
        YamlOwned::Tagged(_, value) => yaml_to_json(value),
        YamlOwned::Representation(value, _, _) => Value::String(value.clone()),
        YamlOwned::Alias(anchor) => Value::String(format!("*{anchor}")),
        YamlOwned::BadValue => Value::Null,
    }
}

fn yaml_key_to_string(node: &YamlOwned) -> String {
    match node {
        YamlOwned::Value(ScalarOwned::String(value)) => value.clone(),
        YamlOwned::Value(ScalarOwned::Integer(value)) => value.to_string(),
        YamlOwned::Value(ScalarOwned::FloatingPoint(value)) => value.to_string(),
        YamlOwned::Value(ScalarOwned::Boolean(value)) => value.to_string(),
        YamlOwned::Value(ScalarOwned::Null) => "null".into(),
        YamlOwned::Representation(value, _, _) => value.clone(),
        YamlOwned::Alias(anchor) => format!("*{anchor}"),
        YamlOwned::Tagged(_, value) => yaml_key_to_string(value),
        YamlOwned::Mapping(_) | YamlOwned::Sequence(_) => {
            let key_json = yaml_to_json(node);
            match key_json {
                Value::String(value) => value,
                _ => key_json.to_string(),
            }
        }
        YamlOwned::BadValue => "(bad value)".into(),
    }
}

fn json_pointer_or_root(pointer: String) -> String {
    if pointer.is_empty() {
        "/".into()
    } else {
        pointer
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_validate_required_property() {
        let instance = json!({"a": 1});
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["a", "b"],
            "properties": {
                "a": { "type": "integer" },
                "b": { "type": "string" }
            },
            "additionalProperties": false
        });

        let errors = validate_json_schema(&instance, &schema);
        assert!(!errors.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.message.contains("required") || error.message.contains("'b'")));
    }

    #[test]
    fn test_validate_additional_properties_false() {
        let instance = json!({"a": 1, "b": 2});
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"a": {"type": "integer"}},
            "additionalProperties": false
        });

        let errors = validate_json_schema(&instance, &schema);
        assert!(!errors.is_empty());
        assert!(errors
            .iter()
            .any(|error| error.message.contains("additional") || error.path == "/"));
    }

    #[test]
    fn test_validate_anyof() {
        let instance = json!("foo");
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "anyOf": [
                {"type": "integer"},
                {"type": "string"}
            ]
        });

        let errors = validate_json_schema(&instance, &schema);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_anyof_reports_nested_issue() {
        let instance = json!({
            "outputs": [
                {
                    "eve-log": {
                        "types": [
                            {
                                "files": {
                                    "force-hash": ["md5"],
                                    "force-magic": "no"
                                }
                            }
                        ]
                    }
                }
            ]
        });

        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "outputs": {
                    "type": "array",
                    "items": {
                        "anyOf": [
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "properties": {
                                    "fast": {
                                        "type": "object"
                                    }
                                }
                            },
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "properties": {
                                    "eve-log": {
                                        "type": "object",
                                        "additionalProperties": false,
                                        "properties": {
                                            "types": {
                                                "type": "array",
                                                "items": {
                                                    "anyOf": [
                                                        {
                                                            "type": "object",
                                                            "additionalProperties": false,
                                                            "properties": {
                                                                "files": {
                                                                    "type": "object",
                                                                    "additionalProperties": false,
                                                                    "properties": {
                                                                        "force-magic": {
                                                                            "type": "string"
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        },
                                                        {
                                                            "type": "string"
                                                        }
                                                    ]
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        });

        let errors = validate_json_schema(&instance, &schema);

        assert!(!errors.is_empty());
        assert!(errors.iter().any(|error| {
            error.path == "/outputs/0/eve-log/types/0/files"
                && error
                    .message
                    .contains("Additional properties are not allowed")
                && error.message.contains("force-hash")
        }));

        assert!(!errors.iter().any(|error| error
            .message
            .contains("not valid under any of the given schemas")));
    }

    #[test]
    fn test_validate_anyof_suppresses_shadowed_additional_props() {
        let instance = json!({
            "types": [
                {
                    "alert": null
                }
            ]
        });

        let schema: Value = serde_json::from_str(
            r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "types": {
      "type": "array",
      "items": {
        "anyOf": [
          {
            "type": "object",
            "additionalProperties": false,
            "properties": { "alert": { "type": "object" } }
          },
          {
            "type": "object",
            "additionalProperties": false,
            "properties": { "dns": { "type": "object" } }
          }
        ]
      }
    }
  }
}"#,
        )
        .expect("schema JSON should parse");

        let errors = validate_json_schema(&instance, &schema);

        assert!(errors.iter().any(|error| {
            error.path == "/types/0/alert"
                && error.message.contains("null is not of type \"object\"")
        }));
        assert!(!errors.iter().any(|error| {
            error.path == "/types/0"
                && error
                    .message
                    .starts_with("Additional properties are not allowed")
                && error.message.contains("alert")
        }));
    }

    #[test]
    fn test_validate_anyof_reports_unknown_variant_no_nested_issue() {
        let instance = json!({
            "outputs": [
                {
                    "unknown": {
                        "enabled": "yes"
                    }
                }
            ]
        });

        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "outputs": {
                    "type": "array",
                    "items": {
                        "anyOf": [
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "properties": {
                                    "fast": {
                                        "type": "object"
                                    }
                                }
                            },
                            {
                                "type": "object",
                                "additionalProperties": false,
                                "properties": {
                                    "eve-log": {
                                        "type": "object"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        });

        let errors = validate_json_schema(&instance, &schema);

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/outputs/0");
        assert!(errors[0]
            .message
            .contains("Additional properties are not allowed"));
        assert!(errors[0].message.contains("unknown"));
    }

    #[test]
    fn test_validate_keeps_unknown_key_with_nested_issue() {
        let instance = json!({
            "known": {
                "enabled": "yes"
            },
            "unknown": 1
        });

        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "known": {
                    "type": "object",
                    "properties": {
                        "enabled": {
                            "type": "boolean"
                        }
                    },
                    "additionalProperties": false
                }
            },
            "additionalProperties": false
        });

        let errors = validate_json_schema(&instance, &schema);

        assert!(errors.iter().any(|error| {
            error.path == "/"
                && error
                    .message
                    .starts_with("Additional properties are not allowed")
                && error.message.contains("unknown")
        }));
        assert!(errors
            .iter()
            .any(|error| error.path == "/known/enabled" && error.message.contains("type")));
    }

    #[test]
    fn test_config_to_json_keeps_non_scalar_mapping_keys() {
        let config = crate::parse_yaml(
            r#"? [xyzzz]
: 1
"#,
        )
        .expect("config should parse");

        let instance = config_to_json(&config);
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "additionalProperties": false
        });

        let errors = validate_json_schema(&instance, &schema);
        assert!(errors.iter().any(|error| {
            error.path == "/"
                && error
                    .message
                    .starts_with("Additional properties are not allowed")
        }));
    }

    #[test]
    fn test_validate_invalid_schema() {
        let instance = json!(1);
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": 42
        });

        let errors = validate_json_schema(&instance, &schema);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("invalid schema"));
    }
}
