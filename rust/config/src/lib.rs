// SPDX-FileCopyrightText: Copyright (C) 2023 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use serde_yaml::Value;
use std::fmt::Debug;

pub mod ffi;
pub mod loader;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    InvalidType(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("bad include: {0}")]
    BadInclude(String),
    #[error("maximum levels")]
    MaxLevels,
}

/// Merge the top level keys from source into target.
///
/// This is the same behavior as the C YAML loader which doesn't
/// attempt to make smart decisions about merging nested values.
pub fn merge(target: &mut Value, source: &Value) {
    if let serde_yaml::Value::Mapping(target) = target {
        if let serde_yaml::Value::Mapping(source) = source {
            for (key, value) in source {
                let old = target.insert(key.clone(), value.clone());
                if old.is_some() {
                    println!("key {:?} replaced", key);
                }
            }
        }
    }
}

pub fn get<S>(config: &serde_yaml::Value, key: S) -> Option<&Value>
where
    S: AsRef<str>,
{
    let mut node = config;
    let mut key = key.as_ref();

    while let Some((next, rem)) = key.split_once('.') {
        match node {
            Value::Mapping(mapping) => {
                if !mapping.contains_key(next) {
                    return None;
                }
                node = &node[next];
                key = rem;
            }
            Value::Sequence(array) => {
                if let Some((index, rem)) = key.split_once('.') {
                    if let Ok(index) = index.parse::<usize>() {
                        if let Some(entry) = array.get(index) {
                            node = entry;
                            key = rem;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    match node {
        Value::Mapping(mapping) => mapping.get(key),
        Value::Sequence(array) => {
            if let Ok(index) = key.parse::<usize>() {
                array.get(index)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn set<S, T>(config: &mut serde_yaml::Value, key: S, value: T) -> Result<(), Error>
where
    S: AsRef<str> + Debug,
    T: Into<serde_yaml::Value> + Debug,
{
    println!("set: {:?} -> {:?}", key, value);
    let mut node = config;
    let mut key = key.as_ref();

    while let Some((next, rem)) = key.split_once('.') {
        match node {
            serde_yaml::Value::Null => todo!(),
            serde_yaml::Value::Bool(_) => todo!(),
            serde_yaml::Value::Number(_) => todo!(),
            serde_yaml::Value::String(_) => todo!(),
            serde_yaml::Value::Sequence(_) => todo!(),
            serde_yaml::Value::Mapping(mapping) => {
                if !mapping.contains_key(next) {
                    node[next] = serde_yaml::Value::Null;
                }
                node = &mut node[next];
            }
            serde_yaml::Value::Tagged(_) => todo!(),
        }

        key = rem;
    }

    match node {
        serde_yaml::Value::String(_)
        | serde_yaml::Value::Number(_)
        | serde_yaml::Value::Bool(_) => {
            *node = serde_yaml::Value::Null;
        }
        _ => {}
    }

    match node {
        serde_yaml::Value::String(_)
        | serde_yaml::Value::Number(_)
        | serde_yaml::Value::Bool(_) => {
            unreachable!();
        }
        serde_yaml::Value::Null => {
            if let Ok(index) = key.parse::<usize>() {
                let mut array = vec![];
                for _i in 0..index {
                    array.push(serde_yaml::Value::Null);
                }
                array.push(value.into());
                *node = serde_yaml::Value::Sequence(array);
            } else {
                let mut mapping = serde_yaml::Mapping::new();
                mapping.insert(key.into(), value.into());
                *node = serde_yaml::Value::Mapping(mapping);
            }
        }
        serde_yaml::Value::Sequence(array) => {
            let index = key.parse::<usize>().unwrap();
            for i in 0..=index {
                if array.get(i).is_none() {
                    array.push(serde_yaml::Value::Null);
                }
            }
            array[index] = value.into();
        }
        serde_yaml::Value::Mapping(mapping) => {
            if let Ok(index) = key.parse::<usize>() {
                return Err(Error::InvalidType(format!(
                    "Can't insert array element {index} into map"
                )));
            }
            mapping.insert(key.into(), value.into());
        }
        serde_yaml::Value::Tagged(_) => todo!(),
    }

    Ok(())
}

fn yaml_type(v: &serde_yaml::Value) -> &str {
    match v {
        serde_yaml::Value::Null => "(null)",
        serde_yaml::Value::Bool(_) => "(bool)",
        serde_yaml::Value::Number(_) => "(number)",
        serde_yaml::Value::String(_) => "(string)",
        serde_yaml::Value::Sequence(_) => "(array)",
        serde_yaml::Value::Mapping(_) => "(object)",
        serde_yaml::Value::Tagged(_) => "(tagged)",
    }
}

/// TODO: Take a writer, OR return an array and let the caller write.
pub fn dump(config: &serde_yaml::Value, sep: &str, include_type: bool) {
    // Use a stack to avoid recursion.
    let mut stack: Vec<(Vec<String>, &serde_yaml::Value)> = vec![(vec![], config)];
    while let Some((prefix, node)) = stack.pop() {
        let type_string = if include_type {
            format!(" {}", yaml_type(node))
        } else {
            "".to_string()
        };
        match node {
            serde_yaml::Value::Null => {
                println!("{} = ~{}", prefix.join(sep), type_string);
            }
            serde_yaml::Value::Bool(b) => {
                println!("{} = {}{}", prefix.join(sep), b, type_string);
            }
            serde_yaml::Value::Number(n) => {
                println!("{} = {}{}", prefix.join(sep), n, type_string);
            }
            serde_yaml::Value::String(s) => {
                println!("{} = {}{}", prefix.join(sep), s, type_string);
            }
            serde_yaml::Value::Sequence(v) => {
                println!("{} = (array)", prefix.join(sep));
                for (i, v) in v.iter().enumerate() {
                    let mut prefix = prefix.clone();
                    prefix.push(i.to_string());
                    stack.push((prefix, v));
                }
            }
            serde_yaml::Value::Mapping(mapping) => {
                println!("{} = (mapping)", prefix.join(sep));
                for (k, v) in mapping {
                    let mut prefix = prefix.clone();
                    prefix.push(k.as_str().unwrap().to_string());
                    stack.push((prefix, v));
                }
            }
            serde_yaml::Value::Tagged(tagged) => {
                stack.push((prefix, &tagged.value));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_set() {
        let mut config = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());

        set(&mut config, "foo", "bar").unwrap();
        assert_eq!(&config["foo"], &serde_yaml::Value::String("bar".into()));

        set(&mut config, "foo", "foo").unwrap();
        assert_eq!(&config["foo"], &serde_yaml::Value::String("foo".into()));

        set(&mut config, "bar.foo", "bar").unwrap();
        assert_eq!(
            &config["bar"]["foo"],
            &serde_yaml::Value::String("bar".into())
        );

        set(&mut config, "bar.foo", "foo").unwrap();
        assert_eq!(
            &config["bar"]["foo"],
            &serde_yaml::Value::String("foo".into())
        );

        set(&mut config, "array.0", "zero").unwrap();
        assert!(&config["array"].is_sequence());
        set(&mut config, "array.1", "one").unwrap();
        assert_eq!(
            &config["array"].as_sequence().unwrap()[1],
            &serde_yaml::Value::from("one")
        );
        set(&mut config, "array.3", "three").unwrap();
        assert!(&config["array"].is_sequence());
        assert_eq!(
            &config["array"].as_sequence().unwrap()[3],
            &serde_yaml::Value::from("three")
        );
        assert_eq!(
            &config["array"].as_sequence().unwrap()[2],
            &serde_yaml::Value::Null
        );

        set(&mut config, "top-level", "something").unwrap();
        set(&mut config, "top-level.child", "something").unwrap();
        assert!(set(&mut config, "top-level.1", "array").is_err());
    }

    #[test]
    fn test_merge() {
        let mut target = serde_yaml::from_str(r#"{"a": 1, "b": 2, "c": 3}"#).unwrap();
        let source = serde_yaml::from_str(r#"{"b": 4, "d": 5}"#).unwrap();
        merge(&mut target, &source);
        assert_eq!(&target["a"], &serde_yaml::Value::Number(1.into()));
        assert_eq!(&target["b"], &serde_yaml::Value::Number(4.into()));
        assert_eq!(&target["c"], &serde_yaml::Value::Number(3.into()));
        assert_eq!(&target["d"], &serde_yaml::Value::Number(5.into()));
    }

    #[test]
    fn test_get() {
        let yaml = r#"
suricata-version: "7.0"
nested:
  value: foobar
  two:
    three:
      four: 4
some-bool: false
list:
  - one
  - two
objects-in-list:
  - foo: bar
nested-list:
  - aaa:
      bbb:
       - one
       - two
       - three: asdf
"#;
        let config = crate::loader::load_string(yaml, "").unwrap();
        assert_eq!(get(&config, "suricata-version").unwrap(), "7.0");
        assert_eq!(get(&config, "nested.value").unwrap(), "foobar");
        assert_eq!(get(&config, "nested.two.three.four").unwrap(), 4);
        assert_eq!(get(&config, "some-bool").unwrap(), &Value::Bool(false));
        assert_eq!(get(&config, "list.0").unwrap(), "one");
        assert_eq!(get(&config, "list.1").unwrap(), "two");
        assert_eq!(get(&config, "objects-in-list.0.foo").unwrap(), "bar");
        assert_eq!(get(&config, "nested-list.0.aaa.bbb.0").unwrap(), "one");
        assert_eq!(
            get(&config, "nested-list.0.aaa.bbb.2.three").unwrap(),
            "asdf"
        );
    }
}
