//! Pure TOML edits for users blocks and the supported `access` sections.
//!
//! `toml_edit` preserves unrelated comments, ordering and formatting. Every
//! function only mutates the requested table/entry and leaves all other keys
//! untouched.

use chrono::{DateTime, Utc};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value, value};

use crate::auth::{format_blocked_until, is_valid_username};
use crate::control_files::CandidateError;
use crate::control_protocol::{AccessChange, AccessRuleDraft, IpRuleDraft};

/// One users-file edit.
#[derive(Clone, Debug)]
pub enum UsersEdit {
    /// Append one account with an already computed PHC string.
    Add {
        username: String,
        password_hash: String,
    },
    /// Replace only one account's PHC string.
    Password {
        username: String,
        password_hash: String,
    },
    /// Set a permanent (`until = None`) or temporary block.
    Block {
        username: String,
        until: Option<DateTime<Utc>>,
    },
    /// Remove any block.
    ClearBlock { username: String },
}

/// Applies one users edit to a parsed document.
pub fn apply_users_edit(
    document: &mut DocumentMut,
    edit: &UsersEdit,
) -> Result<(), CandidateError> {
    let tables = users_tables_mut(document)?;
    match edit {
        UsersEdit::Add {
            username,
            password_hash,
        } => {
            if !is_valid_username(username) {
                return Err(CandidateError::invalid(
                    "username is invalid",
                    vec!["username".to_owned()],
                ));
            }
            if find_user(tables, username).is_some() {
                return Err(CandidateError::invalid(
                    "username already exists",
                    vec!["username".to_owned()],
                ));
            }
            let mut table = Table::new();
            table["username"] = value(username.as_str());
            table["password_hash"] = value(password_hash.as_str());
            tables.push(table);
        }
        UsersEdit::Password {
            username,
            password_hash,
        } => {
            let table = find_user(tables, username).ok_or_else(|| {
                CandidateError::invalid("user does not exist", vec!["username".to_owned()])
            })?;
            table["password_hash"] = value(password_hash.as_str());
        }
        UsersEdit::Block { username, until } => {
            let table = find_user(tables, username).ok_or_else(|| {
                CandidateError::invalid("user does not exist", vec!["username".to_owned()])
            })?;
            match until {
                Some(until) => {
                    table.remove("disabled");
                    table["blocked_until"] = value(format_blocked_until(*until));
                }
                None => {
                    table["disabled"] = value(true);
                    table.remove("blocked_until");
                }
            }
        }
        UsersEdit::ClearBlock { username } => {
            let table = find_user(tables, username).ok_or_else(|| {
                CandidateError::invalid("user does not exist", vec!["username".to_owned()])
            })?;
            table.remove("disabled");
            table.remove("blocked_until");
        }
    }
    sync_users_version(document);
    Ok(())
}

fn users_tables_mut(document: &mut DocumentMut) -> Result<&mut ArrayOfTables, CandidateError> {
    let replace = match document.get("users") {
        None => true,
        Some(Item::ArrayOfTables(_)) => false,
        Some(Item::Value(Value::Array(array))) if array.is_empty() => true,
        Some(Item::Value(Value::Array(_))) => {
            return Err(CandidateError::invalid(
                "writer supports only [[users]] tables, not an inline users array",
                vec!["users".to_owned()],
            ));
        }
        Some(_) => {
            return Err(CandidateError::invalid(
                "users must be an array of tables",
                vec!["users".to_owned()],
            ));
        }
    };
    if replace {
        document["users"] = Item::ArrayOfTables(ArrayOfTables::new());
        if let Some(mut key) = document.as_table_mut().key_mut("users") {
            key.leaf_decor_mut().set_suffix("");
        }
    }
    match document.get_mut("users") {
        Some(Item::ArrayOfTables(tables)) => Ok(tables),
        _ => Err(CandidateError::invalid(
            "cannot create the users table",
            vec!["users".to_owned()],
        )),
    }
}

fn find_user<'a>(tables: &'a mut ArrayOfTables, username: &str) -> Option<&'a mut Table> {
    tables.iter_mut().find(|table| {
        table
            .get("username")
            .and_then(Item::as_str)
            .is_some_and(|value| value == username)
    })
}

fn has_temporary_block(document: &DocumentMut) -> bool {
    document
        .get("users")
        .and_then(Item::as_array_of_tables)
        .is_some_and(|tables| {
            tables
                .iter()
                .any(|table| table.get("blocked_until").is_some())
        })
}

fn sync_users_version(document: &mut DocumentMut) {
    let version = if has_temporary_block(document) { 2 } else { 1 };
    document["version"] = value(version);
}

/// Applies one access edit to a parsed configuration document.
pub fn apply_access_edit(
    document: &mut DocumentMut,
    change: &AccessChange,
) -> Result<(), CandidateError> {
    if !document.contains_key("access") {
        document["access"] = Item::Table(Table::new());
    }
    let access = document["access"]
        .as_table_mut()
        .ok_or_else(|| CandidateError::invalid("access must be a table", vec![]))?;
    match change {
        AccessChange::SourceAdd { value: cidr, index } => {
            let array = source_array(access)?;
            let position = index.unwrap_or(array.len()).min(array.len());
            array.insert(position, cidr.as_str());
        }
        AccessChange::SourceRemove { index } => {
            let array = source_array(access)?;
            if *index >= array.len() {
                return Err(CandidateError::invalid(
                    "source index is out of range",
                    vec!["access.source_allow".to_owned()],
                ));
            }
            array.remove(*index);
        }
        AccessChange::SourceReplace { values } => {
            let array = source_array(access)?;
            array.clear();
            for value in values {
                array.push(value.as_str());
            }
        }
        AccessChange::RuleCreate { index, rule } => {
            let tables = rules_tables(access)?;
            let position = index.unwrap_or(tables.len()).min(tables.len());
            tables.insert(position, rule_table(rule)?);
        }
        AccessChange::RuleUpdate { index, rule } => {
            let tables = rules_tables(access)?;
            let table = tables.get_mut(*index).ok_or_else(|| {
                CandidateError::invalid(
                    "rule index is out of range",
                    vec![format!("access.rules[{index}]")],
                )
            })?;
            update_rule_table(table, rule)?;
        }
        AccessChange::RuleDelete { index } => {
            let tables = rules_tables(access)?;
            if *index >= tables.len() {
                return Err(CandidateError::invalid(
                    "rule index is out of range",
                    vec![format!("access.rules[{index}]")],
                ));
            }
            tables.remove(*index);
        }
        AccessChange::RuleMove { from, to } => {
            let tables = rules_tables(access)?;
            if *from >= tables.len() || *to >= tables.len() {
                return Err(CandidateError::invalid(
                    "rule move is out of range",
                    vec!["access.rules".to_owned()],
                ));
            }
            let positions = table_positions(tables);
            let table = tables.remove(*from);
            tables.insert(*to, table);
            reposition_tables(tables, &positions);
        }
        AccessChange::IpCreate { index, rule } => {
            let tables = ip_rules_tables(access)?;
            let position = index.unwrap_or(tables.len()).min(tables.len());
            tables.insert(position, ip_rule_table(rule)?);
        }
        AccessChange::IpUpdate { index, rule } => {
            let tables = ip_rules_tables(access)?;
            let table = tables.get_mut(*index).ok_or_else(|| {
                CandidateError::invalid(
                    "IP rule index is out of range",
                    vec![format!("access.ip_rules[{index}]")],
                )
            })?;
            update_ip_rule_table(table, rule)?;
        }
        AccessChange::IpDelete { index } => {
            let tables = ip_rules_tables(access)?;
            if *index >= tables.len() {
                return Err(CandidateError::invalid(
                    "IP rule index is out of range",
                    vec![format!("access.ip_rules[{index}]")],
                ));
            }
            tables.remove(*index);
        }
        AccessChange::IpMove { from, to } => {
            let tables = ip_rules_tables(access)?;
            if *from >= tables.len() || *to >= tables.len() {
                return Err(CandidateError::invalid(
                    "IP rule move is out of range",
                    vec!["access.ip_rules".to_owned()],
                ));
            }
            let positions = table_positions(tables);
            let table = tables.remove(*from);
            tables.insert(*to, table);
            reposition_tables(tables, &positions);
        }
        AccessChange::IpDefault { value: default } => {
            if default != "public_only" && default != "deny" {
                return Err(CandidateError::invalid(
                    "ip_default must be `public_only` or `deny`",
                    vec!["access.ip_default".to_owned()],
                ));
            }
            access["ip_default"] = value(default.as_str());
        }
    }
    Ok(())
}

fn table_positions(tables: &ArrayOfTables) -> Vec<isize> {
    tables
        .iter()
        .filter_map(|table| table.position())
        .collect::<Vec<_>>()
}

fn reposition_tables(tables: &mut ArrayOfTables, positions: &[isize]) {
    let mut positions = positions.to_vec();
    positions.sort_unstable();
    for (table, position) in tables.iter_mut().zip(positions) {
        table.set_position(Some(position));
    }
}

fn source_array(access: &mut Table) -> Result<&mut Array, CandidateError> {
    if !access.contains_key("source_allow") {
        access["source_allow"] = Item::Value(Value::Array(Array::new()));
    }
    access["source_allow"].as_array_mut().ok_or_else(|| {
        CandidateError::invalid(
            "access.source_allow must be an array",
            vec!["access.source_allow".to_owned()],
        )
    })
}

fn rules_tables(access: &mut Table) -> Result<&mut ArrayOfTables, CandidateError> {
    if !access.contains_key("rules") {
        access["rules"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    access["rules"].as_array_of_tables_mut().ok_or_else(|| {
        CandidateError::invalid(
            "access.rules must be an array of tables",
            vec!["access.rules".to_owned()],
        )
    })
}

fn ip_rules_tables(access: &mut Table) -> Result<&mut ArrayOfTables, CandidateError> {
    if !access.contains_key("ip_rules") {
        access["ip_rules"] = Item::ArrayOfTables(ArrayOfTables::new());
    }
    access["ip_rules"].as_array_of_tables_mut().ok_or_else(|| {
        CandidateError::invalid(
            "access.ip_rules must be an array of tables",
            vec!["access.ip_rules".to_owned()],
        )
    })
}

fn check_action(action: &str) -> Result<(), CandidateError> {
    if action == "allow" || action == "deny" {
        Ok(())
    } else {
        Err(CandidateError::invalid(
            "action must be `allow` or `deny`",
            vec!["action".to_owned()],
        ))
    }
}

fn rule_table(rule: &AccessRuleDraft) -> Result<Table, CandidateError> {
    check_action(&rule.action)?;
    let mut table = Table::new();
    table["id"] = value(rule.id.as_str());
    table["action"] = value(rule.action.as_str());
    write_selectors(&mut table, rule);
    Ok(table)
}

fn update_rule_table(table: &mut Table, rule: &AccessRuleDraft) -> Result<(), CandidateError> {
    check_action(&rule.action)?;
    table["id"] = value(rule.id.as_str());
    table["action"] = value(rule.action.as_str());
    for key in [
        "listeners",
        "sources",
        "methods",
        "ports",
        "users",
        "host_exact",
        "host_suffix",
    ] {
        table.remove(key);
    }
    write_selectors(table, rule);
    Ok(())
}

fn write_selectors(table: &mut Table, rule: &AccessRuleDraft) {
    if let Some(values) = &rule.listeners {
        table["listeners"] = string_array(values);
    }
    if let Some(values) = &rule.sources {
        table["sources"] = string_array(values);
    }
    if let Some(values) = &rule.methods {
        table["methods"] = string_array(values);
    }
    if let Some(values) = &rule.ports {
        let mut array = Array::new();
        for port in values {
            array.push(i64::from(*port));
        }
        table["ports"] = Item::Value(Value::Array(array));
    }
    if let Some(values) = &rule.users {
        table["users"] = string_array(values);
    }
    if let Some(values) = &rule.host_exact {
        table["host_exact"] = string_array(values);
    }
    if let Some(values) = &rule.host_suffix {
        table["host_suffix"] = string_array(values);
    }
}

fn string_array(values: &[String]) -> Item {
    let mut array = Array::new();
    for value in values {
        array.push(value.as_str());
    }
    Item::Value(Value::Array(array))
}

fn ip_rule_table(rule: &IpRuleDraft) -> Result<Table, CandidateError> {
    check_action(&rule.action)?;
    let mut table = Table::new();
    table["id"] = value(rule.id.as_str());
    table["action"] = value(rule.action.as_str());
    table["networks"] = string_array(&rule.networks);
    if rule.allow_special {
        table["allow_special"] = value(true);
    }
    Ok(table)
}

fn update_ip_rule_table(table: &mut Table, rule: &IpRuleDraft) -> Result<(), CandidateError> {
    check_action(&rule.action)?;
    table["id"] = value(rule.id.as_str());
    table["action"] = value(rule.action.as_str());
    table["networks"] = string_array(&rule.networks);
    if rule.allow_special {
        table["allow_special"] = value(true);
    } else {
        table.remove("allow_special");
    }
    Ok(())
}

/// Extracts a bounded preview of the changed access fragment and its nearest
/// neighbours. It never returns the whole configuration.
pub fn access_fragment(document: &DocumentMut, change: &AccessChange) -> String {
    let Some(access) = document.get("access").and_then(Item::as_table) else {
        return String::new();
    };
    let mut output = String::new();
    match change {
        AccessChange::SourceAdd { .. }
        | AccessChange::SourceRemove { .. }
        | AccessChange::SourceReplace { .. } => {
            if let Some(values) = access.get("source_allow") {
                let text = values.to_string();
                output.push_str("source_allow = ");
                output.push_str(&bounded(&text, 4096));
            }
        }
        AccessChange::RuleMove { from: _, to } => {
            let tables = access.get("rules").and_then(Item::as_array_of_tables);
            if let Some(tables) = tables {
                push_rule_fragment(&mut output, tables, *to, "access.rules");
            }
        }
        AccessChange::RuleCreate { index, .. } => {
            let tables = access.get("rules").and_then(Item::as_array_of_tables);
            if let Some(tables) = tables {
                let position = index.unwrap_or(tables.len());
                push_rule_fragment(&mut output, tables, position, "access.rules");
            }
        }
        AccessChange::RuleUpdate { index, .. } | AccessChange::RuleDelete { index, .. } => {
            let tables = access.get("rules").and_then(Item::as_array_of_tables);
            if let Some(tables) = tables {
                push_rule_fragment(&mut output, tables, *index, "access.rules");
            }
        }
        AccessChange::IpMove { from: _, to } => {
            let tables = access.get("ip_rules").and_then(Item::as_array_of_tables);
            if let Some(tables) = tables {
                push_rule_fragment(&mut output, tables, *to, "access.ip_rules");
            }
        }
        AccessChange::IpCreate { index, .. } => {
            let tables = access.get("ip_rules").and_then(Item::as_array_of_tables);
            if let Some(tables) = tables {
                let position = index.unwrap_or(tables.len());
                push_rule_fragment(&mut output, tables, position, "access.ip_rules");
            }
        }
        AccessChange::IpUpdate { index, .. } | AccessChange::IpDelete { index, .. } => {
            let tables = access.get("ip_rules").and_then(Item::as_array_of_tables);
            if let Some(tables) = tables {
                push_rule_fragment(&mut output, tables, *index, "access.ip_rules");
            }
        }
        AccessChange::IpDefault { .. } => {
            if let Some(value) = access.get("ip_default") {
                output.push_str("ip_default = ");
                output.push_str(&value.to_string());
            }
        }
    }
    bounded(&output, 12 * 1024)
}

fn push_rule_fragment(
    output: &mut String,
    tables: &toml_edit::ArrayOfTables,
    position: usize,
    header: &str,
) {
    if tables.is_empty() {
        return;
    }
    let position = position.min(tables.len().saturating_sub(1));
    let start = position.saturating_sub(1);
    let end = (position + 1).min(tables.len().saturating_sub(1));
    for index in start..=end {
        if let Some(table) = tables.get(index) {
            output.push_str("[[");
            output.push_str(header);
            output.push_str("]]\n");
            output.push_str(&bounded(&table.to_string(), 4096));
            output.push('\n');
        }
    }
}

fn bounded(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut output = value[..end].to_owned();
    output.push_str("\n…");
    output
}

/// Short human summary of one edit.
pub fn access_change_summary(change: &AccessChange) -> String {
    match change {
        AccessChange::SourceAdd { value, .. } => format!("добавить источник {value}"),
        AccessChange::SourceRemove { index } => format!("удалить источник #{index}"),
        AccessChange::SourceReplace { values } => {
            format!("заменить список источников ({} записей)", values.len())
        }
        AccessChange::RuleCreate { index, rule } => format!(
            "создать правило {} ({}) в позиции {}",
            rule.id,
            rule.action,
            index.map_or_else(|| "в конце".to_owned(), |index| index.to_string())
        ),
        AccessChange::RuleUpdate { index, rule } => {
            format!("изменить правило #{index} -> {} ({})", rule.id, rule.action)
        }
        AccessChange::RuleDelete { index } => format!("удалить правило #{index}"),
        AccessChange::RuleMove { from, to } => format!("переместить правило {from} -> {to}"),
        AccessChange::IpCreate { index, rule } => format!(
            "создать IP-правило {} ({}) в позиции {}",
            rule.id,
            rule.action,
            index.map_or_else(|| "в конце".to_owned(), |index| index.to_string())
        ),
        AccessChange::IpUpdate { index, rule } => {
            format!(
                "изменить IP-правило #{index} -> {} ({})",
                rule.id, rule.action
            )
        }
        AccessChange::IpDelete { index } => format!("удалить IP-правило #{index}"),
        AccessChange::IpMove { from, to } => format!("переместить IP-правило {from} -> {to}"),
        AccessChange::IpDefault { value } => format!("ip_default = {value}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = "# top\nversion = 1\n\n[[users]]\n# alice\nusername = \"alice\"\npassword_hash = \"a\"\n\n[[users]]\nusername = \"bob\"\npassword_hash = \"b\"\ndisabled = true\n";

    fn doc(text: &str) -> DocumentMut {
        text.parse().unwrap()
    }

    #[test]
    fn temporary_block_bumps_version_and_clear_downgrades() {
        let mut document = doc(USERS);
        apply_users_edit(
            &mut document,
            &UsersEdit::Block {
                username: "alice".to_owned(),
                until: Some("2026-11-27T18:00:00Z".parse().unwrap()),
            },
        )
        .unwrap();
        let text = document.to_string();
        assert!(text.contains("version = 2"));
        assert!(text.contains("blocked_until = \"2026-11-27T18:00:00Z\""));
        assert!(text.contains("# alice"));
        assert!(text.contains("# top"));

        let mut document = doc(&text);
        apply_users_edit(
            &mut document,
            &UsersEdit::ClearBlock {
                username: "alice".to_owned(),
            },
        )
        .unwrap();
        let text = document.to_string();
        assert!(text.contains("version = 1"));
        assert!(!text.contains("blocked_until"));
        assert!(text.contains("disabled = true"), "bob stays blocked");
    }

    #[test]
    fn add_user_accepts_an_empty_inline_users_array() {
        let mut document = doc("# keep this header\nversion = 1\nusers = []\n");
        let password = crate::auth::prepare_password("synthetic").expect("password");
        let phc = crate::auth::hash_password(&password, &[3_u8; 16]).expect("hash");
        apply_users_edit(
            &mut document,
            &UsersEdit::Add {
                username: "alice".to_owned(),
                password_hash: phc,
            },
        )
        .expect("empty users array becomes a table array");
        let text = document.to_string();
        assert!(text.contains("# keep this header"));
        assert!(text.contains("version = 1"));
        assert!(text.contains("[[users]]"));
        assert!(text.contains("username = \"alice\""));
        crate::auth::UsersSnapshot::parse(&text).expect("candidate parses");
    }

    #[test]
    fn add_user_rejects_a_non_empty_inline_users_array() {
        let mut document = doc("version = 1\nusers = [{ username = \"alice\" }]\n");
        let before = document.to_string();
        let error = apply_users_edit(
            &mut document,
            &UsersEdit::Add {
                username: "bob".to_owned(),
                password_hash: "synthetic-phc".to_owned(),
            },
        )
        .unwrap_err();
        assert!(error.message.contains("[[users]]"), "{}", error.message);
        assert_eq!(document.to_string(), before);
    }

    #[test]
    fn adding_a_duplicate_or_missing_user_is_rejected() {
        let mut document = doc(USERS);
        assert!(
            apply_users_edit(
                &mut document,
                &UsersEdit::Add {
                    username: "alice".to_owned(),
                    password_hash: "c".to_owned(),
                }
            )
            .is_err()
        );
        assert!(
            apply_users_edit(
                &mut document,
                &UsersEdit::Password {
                    username: "nobody".to_owned(),
                    password_hash: "c".to_owned(),
                }
            )
            .is_err()
        );
    }

    #[test]
    fn access_move_preserves_order_and_unrelated_comments() {
        let text = r#"# config comment
schema_version = 1

[access]
source_allow = ["127.0.0.0/8"]

[[access.rules]]
# first comment
id = "one"
action = "allow"

[[access.rules]]
id = "two"
action = "deny"

[routing]
default_egress = "system"
"#;
        let mut document = doc(text);
        apply_access_edit(&mut document, &AccessChange::RuleMove { from: 1, to: 0 }).unwrap();
        let output = document.to_string();
        let one = output.find("id = \"one\"").unwrap();
        let two = output.find("id = \"two\"").unwrap();
        assert!(two < one);
        assert!(output.contains("# first comment"));
        assert!(output.contains("[routing]"));
        assert!(output.contains("# config comment"));
    }

    #[test]
    fn malformed_access_types_return_an_error_instead_of_panicking() {
        let mut document = doc("[access]\nsource_allow = \"bad\"\nrules = 1\nip_rules = \"x\"\n");
        assert!(
            apply_access_edit(
                &mut document,
                &AccessChange::SourceAdd {
                    value: "127.0.0.0/8".to_owned(),
                    index: None,
                }
            )
            .is_err()
        );
        assert!(apply_access_edit(&mut document, &AccessChange::RuleDelete { index: 0 }).is_err());
        assert!(apply_access_edit(&mut document, &AccessChange::IpDelete { index: 0 }).is_err());
    }

    #[test]
    fn source_edit_keeps_array_entries() {
        let mut document =
            doc("schema_version = 1\n\n[access]\nsource_allow = [\"127.0.0.0/8\", \"::1/128\"]\n");
        apply_access_edit(
            &mut document,
            &AccessChange::SourceAdd {
                value: "10.0.0.0/8".to_owned(),
                index: Some(1),
            },
        )
        .unwrap();
        let output = document.to_string();
        let ten = output.find("10.0.0.0/8").unwrap();
        let local = output.find("127.0.0.0/8").unwrap();
        let v6 = output.find("::1/128").unwrap();
        assert!(local < ten && ten < v6);
    }
}
