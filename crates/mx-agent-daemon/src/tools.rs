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
    /// `run_tests` definition. This is the **discovery** path — it resolves an
    /// advertised reference to its schema for display. Version *enforcement*
    /// happens at **execution** time (`crate::tool_exec`), where a request for a
    /// version the daemon does not implement is rejected rather than silently
    /// resolved to a different implementation (issue #378).
    pub fn resolve(&self, reference: &str) -> Option<&ToolSchema> {
        let name = reference.split('@').next().unwrap_or(reference);
        self.get(name)
    }
}

/// The built-in tools every agent ships with, advertised in name order.
///
/// Built-in tools are safe, well-known operations with strict schemas. The set is
/// derived from [`crate::tool_exec::builtin_schemas`] — the single source of truth
/// that pairs each tool's advertised schema with its executor — so the registry can
/// only advertise tools the daemon can actually run (issue #378). The current set
/// mirrors the roadmap milestone (architecture §15): a `run_tests` tool and a
/// `lint` tool.
pub fn builtin_tools() -> Vec<ToolSchema> {
    crate::tool_exec::builtin_schemas()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        // Source a real base schema from the single built-in source of truth
        // rather than a now-removed private constructor (issue #378).
        let base = builtin_tools()
            .into_iter()
            .find(|t| t.name == "run_tests")
            .expect("run_tests is a built-in");
        registry.register(base.clone());
        registry.register(ToolSchema {
            description: "Run tests differently".to_string(),
            ..base
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
