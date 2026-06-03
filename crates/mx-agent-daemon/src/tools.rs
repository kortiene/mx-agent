//! Tool registry and built-in tool definitions.
//!
//! Named tools are the preferred security boundary over raw `exec` (see
//! `docs/architecture.md`, section 5.2): each tool declares strict input and
//! output JSON schemas so callers know exactly which arguments are accepted and
//! what shape the result takes. This module defines the [`ToolRegistry`], the
//! set of [`ToolSchema`] records an agent offers, plus the built-in tools every
//! agent ships with.
//!
//! The registry is keyed by tool name. Agents advertise their tools in
//! `com.mxagent.agent.v1` state as qualified `name@version` references (see
//! [`mx_agent_protocol::schema::AgentState::tools`]); the registry resolves
//! those references back to full [`ToolSchema`] metadata.

use std::collections::BTreeMap;

use mx_agent_protocol::schema::ToolSchema;
use serde_json::json;

/// An ordered collection of [`ToolSchema`] records keyed by tool name.
///
/// Names are unique: registering a tool with an existing name replaces the
/// previous definition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolRegistry {
    tools: BTreeMap<String, ToolSchema>,
}

impl ToolRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with the built-in tools every agent
    /// ships with (see [`builtin_tools`]).
    pub fn builtin() -> Self {
        let mut registry = Self::new();
        for tool in builtin_tools() {
            registry.register(tool);
        }
        registry
    }

    /// Register (or replace) a tool by its name.
    pub fn register(&mut self, tool: ToolSchema) {
        self.tools.insert(tool.name.clone(), tool);
    }

    /// Look up a tool by name.
    pub fn get(&self, name: &str) -> Option<&ToolSchema> {
        self.tools.get(name)
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Whether the registry has no tools.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Iterate over the registered tools in name order.
    pub fn iter(&self) -> impl Iterator<Item = &ToolSchema> {
        self.tools.values()
    }

    /// Return every tool as an owned [`ToolSchema`] in name order.
    pub fn schemas(&self) -> Vec<ToolSchema> {
        self.tools.values().cloned().collect()
    }

    /// Return the qualified `name@version` references for every tool, suitable
    /// for advertising in [`mx_agent_protocol::schema::AgentState::tools`].
    pub fn qualified_refs(&self) -> Vec<String> {
        self.tools.values().map(ToolSchema::qualified_ref).collect()
    }

    /// Resolve a `name` or `name@version` reference to a registered tool.
    ///
    /// Matching is by name only; the version suffix (if present) is ignored so
    /// that an advertised `run_tests@1.0.0` resolves to the registered
    /// `run_tests` definition.
    pub fn resolve(&self, reference: &str) -> Option<&ToolSchema> {
        let name = reference.split('@').next().unwrap_or(reference);
        self.get(name)
    }
}

/// The built-in tools every agent ships with.
///
/// Built-in tools are safe, well-known operations with strict schemas. The
/// initial set mirrors the roadmap milestone (architecture §15): a `run_tests`
/// tool plus a `lint` tool.
pub fn builtin_tools() -> Vec<ToolSchema> {
    vec![run_tests_tool(), lint_tool()]
}

/// Built-in `run_tests` tool definition (architecture §5.2).
fn run_tests_tool() -> ToolSchema {
    ToolSchema {
        name: "run_tests".to_string(),
        version: "1.0.0".to_string(),
        description: "Run project test suites".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "package": { "type": "string" },
                "name": { "type": "string" },
                "coverage": { "type": "boolean" }
            },
            "required": ["package"]
        }),
        output_schema: json!({
            "type": "object",
            "properties": {
                "exit_code": { "type": "integer" },
                "summary": { "type": "string" },
                "log_mxc": { "type": "string" }
            }
        }),
        extra: Default::default(),
    }
}

/// Built-in `lint` tool definition.
fn lint_tool() -> ToolSchema {
    ToolSchema {
        name: "lint".to_string(),
        version: "1.0.0".to_string(),
        description: "Run project linters".to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string" },
                "fix": { "type": "boolean" }
            }
        }),
        output_schema: json!({
            "type": "object",
            "properties": {
                "exit_code": { "type": "integer" },
                "summary": { "type": "string" },
                "log_mxc": { "type": "string" }
            }
        }),
        extra: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_contains_known_tools() {
        let registry = ToolRegistry::builtin();
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());
        assert!(registry.get("run_tests").is_some());
        assert!(registry.get("lint").is_some());
        assert!(registry.get("missing").is_none());
    }

    #[test]
    fn qualified_refs_are_sorted_name_at_version() {
        let registry = ToolRegistry::builtin();
        assert_eq!(
            registry.qualified_refs(),
            vec!["lint@1.0.0".to_string(), "run_tests@1.0.0".to_string()]
        );
    }

    #[test]
    fn resolve_ignores_version_suffix() {
        let registry = ToolRegistry::builtin();
        let by_ref = registry.resolve("run_tests@1.0.0").expect("resolves");
        let by_name = registry.resolve("run_tests").expect("resolves");
        assert_eq!(by_ref, by_name);
        assert_eq!(by_ref.name, "run_tests");
        assert!(registry.resolve("unknown@9.9.9").is_none());
    }

    #[test]
    fn register_replaces_by_name() {
        let mut registry = ToolRegistry::new();
        assert!(registry.is_empty());
        registry.register(run_tests_tool());
        registry.register(ToolSchema {
            description: "Run tests differently".to_string(),
            ..run_tests_tool()
        });
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.get("run_tests").unwrap().description,
            "Run tests differently"
        );
    }

    #[test]
    fn builtin_tool_schemas_serialize() {
        for tool in builtin_tools() {
            let value = serde_json::to_value(&tool).expect("serializes");
            assert_eq!(value["name"], json!(tool.name));
            assert_eq!(value["input_schema"]["type"], json!("object"));
            assert_eq!(value["output_schema"]["type"], json!("object"));
        }
    }
}
