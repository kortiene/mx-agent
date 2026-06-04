//! Task DAG graph analysis and rendering (architecture §9.5).
//!
//! Tasks form a directed acyclic graph through their `depends_on` edges: a task
//! depends on the tasks listed there, and is in turn a dependency of the tasks
//! that list it. This module turns a flat set of [`TaskState`] events into a
//! navigable graph — computing roots (tasks that depend on nothing present),
//! the dependency edges between them, and any dependency cycles — and renders
//! it either as the indented text tree documented in the architecture, or as a
//! JSON object for programmatic consumers.
//!
//! Cycle detection is deliberate: Matrix room state cannot enforce acyclicity,
//! so a malformed or adversarial workspace may contain a circular dependency. A
//! cycle is reported clearly rather than silently dropped or rendered as an
//! infinite tree.

use std::collections::{BTreeMap, BTreeSet};

use mx_agent_protocol::schema::TaskState;
use serde::Serialize;

/// One task in the dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphNode {
    /// Task identifier (the Matrix state key).
    pub task_id: String,
    /// Current lifecycle state, e.g. `succeeded`.
    pub state: String,
    /// Task IDs this task depends on, as recorded on the task (including any
    /// that refer to tasks not present in the room).
    pub depends_on: Vec<String>,
}

/// A dependency edge. `to` depends on `from`; equivalently, work flows from the
/// dependency (`from`) to the dependent (`to`), which is the direction the text
/// tree is drawn.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct GraphEdge {
    /// The dependency (drawn as the parent in the tree).
    pub from: String,
    /// The dependent (drawn as the child in the tree).
    pub to: String,
}

/// A fully analyzed task dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskGraph {
    /// Every task, sorted by `task_id`.
    pub nodes: Vec<GraphNode>,
    /// Dependency edges between present tasks, sorted.
    pub edges: Vec<GraphEdge>,
    /// Tasks that depend on no present task, sorted; the roots of the tree.
    pub roots: Vec<String>,
    /// Detected dependency cycles. Each entry lists the task IDs around the
    /// loop with the entry point repeated at the end, e.g.
    /// `["task-a", "task-b", "task-a"]`.
    pub cycles: Vec<Vec<String>>,
}

impl TaskGraph {
    /// Build a graph from a set of task state events.
    ///
    /// `depends_on` entries that refer to tasks not present in `tasks` are kept
    /// on the node for fidelity but ignored when computing edges, roots, and
    /// cycles — a dangling dependency cannot be drawn or traversed.
    pub fn from_tasks(tasks: &[TaskState]) -> Self {
        let present: BTreeSet<&str> = tasks.iter().map(|t| t.task_id.as_str()).collect();

        let mut nodes: Vec<GraphNode> = tasks
            .iter()
            .map(|t| GraphNode {
                task_id: t.task_id.clone(),
                state: t.state.clone(),
                depends_on: t.depends_on.clone(),
            })
            .collect();
        nodes.sort_by(|a, b| a.task_id.cmp(&b.task_id));

        let mut edges = BTreeSet::new();
        let mut roots = Vec::new();
        for task in tasks {
            let mut has_present_dep = false;
            for dep in &task.depends_on {
                if present.contains(dep.as_str()) {
                    has_present_dep = true;
                    edges.insert(GraphEdge {
                        from: dep.clone(),
                        to: task.task_id.clone(),
                    });
                }
            }
            if !has_present_dep {
                roots.push(task.task_id.clone());
            }
        }
        roots.sort();
        roots.dedup();

        let cycles = detect_cycles(tasks, &present);

        Self {
            nodes,
            edges: edges.into_iter().collect(),
            roots,
            cycles,
        }
    }

    /// Render the graph as the indented text tree from architecture §9.5,
    /// followed by one `cycle detected: ...` line per detected cycle.
    ///
    /// Each root is drawn at the left margin; its dependents are nested beneath
    /// it with a `└─ ` connector, four columns deeper per level. A task that
    /// reappears on the current path (a cycle) is not expanded again.
    pub fn render_text(&self) -> String {
        let states: BTreeMap<&str, &str> = self
            .nodes
            .iter()
            .map(|n| (n.task_id.as_str(), n.state.as_str()))
            .collect();

        // Dependents of each task, sorted, derived from the dependency edges.
        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &self.edges {
            children
                .entry(edge.from.as_str())
                .or_default()
                .push(edge.to.as_str());
        }

        let mut out = String::new();
        let mut path: Vec<&str> = Vec::new();
        for root in &self.roots {
            render_node(root, 0, &states, &children, &mut path, &mut out);
        }
        for cycle in &self.cycles {
            out.push_str(&format!("cycle detected: {}\n", cycle.join(" -> ")));
        }
        out
    }
}

/// Recursively render one node and its dependents.
fn render_node<'a>(
    id: &'a str,
    depth: usize,
    states: &BTreeMap<&'a str, &'a str>,
    children: &BTreeMap<&'a str, Vec<&'a str>>,
    path: &mut Vec<&'a str>,
    out: &mut String,
) {
    let prefix = if depth == 0 {
        String::new()
    } else {
        format!("{}└─ ", " ".repeat(4 * depth - 2))
    };
    let state = states.get(id).copied().unwrap_or("");
    out.push_str(&format!("{prefix}{id}  {state}\n"));

    // Guard against cycles: never expand a task already on the active path.
    if path.contains(&id) {
        return;
    }
    path.push(id);
    if let Some(kids) = children.get(id) {
        for child in kids {
            render_node(child, depth + 1, states, children, path, out);
        }
    }
    path.pop();
}

/// Find every dependency cycle reachable through present `depends_on` edges.
///
/// Runs an iterative depth-first search over the dependency direction (a task
/// points at the tasks it depends on). A back edge to a task currently on the
/// search stack closes a cycle, which is recorded as the stack slice from that
/// task to the current one, with the entry point repeated at the end.
fn detect_cycles(tasks: &[TaskState], present: &BTreeSet<&str>) -> Vec<Vec<String>> {
    // Dependency adjacency, sorted for deterministic traversal.
    let mut deps: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for task in tasks {
        let entry = deps.entry(task.task_id.as_str()).or_default();
        for dep in &task.depends_on {
            if present.contains(dep.as_str()) {
                entry.push(dep.as_str());
            }
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        White,
        Gray,
        Black,
    }
    let mut color: BTreeMap<&str, Color> = deps.keys().map(|&k| (k, Color::White)).collect();
    let mut cycles = Vec::new();

    // Explicit stack DFS so deep graphs cannot overflow the call stack. Each
    // frame tracks how many of a node's dependencies have been visited.
    for &start in deps.keys() {
        if color[start] != Color::White {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(start, 0)];
        color.insert(start, Color::Gray);
        while let Some(&(node, idx)) = stack.last() {
            let adj = &deps[node];
            if idx < adj.len() {
                stack.last_mut().unwrap().1 += 1;
                let next = adj[idx];
                match color[next] {
                    Color::White => {
                        color.insert(next, Color::Gray);
                        stack.push((next, 0));
                    }
                    Color::Gray => {
                        // Back edge: cycle from `next` down to `node`.
                        let pos = stack.iter().position(|&(n, _)| n == next).unwrap();
                        let mut cycle: Vec<String> =
                            stack[pos..].iter().map(|&(n, _)| n.to_string()).collect();
                        cycle.push(next.to_string());
                        cycles.push(cycle);
                    }
                    Color::Black => {}
                }
            } else {
                color.insert(node, Color::Black);
                stack.pop();
            }
        }
    }

    cycles
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, state: &str, depends_on: &[&str]) -> TaskState {
        TaskState {
            task_id: id.to_string(),
            title: format!("title {id}"),
            description: String::new(),
            state: state.to_string(),
            assigned_to: String::new(),
            created_by: "me".to_string(),
            depends_on: depends_on.iter().map(|s| s.to_string()).collect(),
            blocks: Vec::new(),
            invocation_id: None,
            created_at: "t".to_string(),
            updated_at: "t".to_string(),
            state_rev: 1,
            previous_event_id: None,
            result: None,
            extra: Default::default(),
        }
    }

    /// The four-task chain from architecture §9.5.
    fn doc_chain() -> Vec<TaskState> {
        vec![
            task("task-plan", "succeeded", &[]),
            task("task-code", "succeeded", &["task-plan"]),
            task("task-test", "failed", &["task-code"]),
            task("task-review", "blocked", &["task-test"]),
        ]
    }

    #[test]
    fn text_tree_matches_documented_example() {
        let graph = TaskGraph::from_tasks(&doc_chain());
        let expected = "\
task-plan  succeeded
  └─ task-code  succeeded
      └─ task-test  failed
          └─ task-review  blocked
";
        assert_eq!(graph.render_text(), expected);
        assert!(graph.cycles.is_empty());
    }

    #[test]
    fn roots_and_edges_follow_dependencies() {
        let graph = TaskGraph::from_tasks(&doc_chain());
        assert_eq!(graph.roots, vec!["task-plan".to_string()]);
        assert_eq!(
            graph.edges,
            vec![
                GraphEdge {
                    from: "task-code".to_string(),
                    to: "task-test".to_string()
                },
                GraphEdge {
                    from: "task-plan".to_string(),
                    to: "task-code".to_string()
                },
                GraphEdge {
                    from: "task-test".to_string(),
                    to: "task-review".to_string()
                },
            ]
        );
    }

    #[test]
    fn multiple_roots_and_branches_render_sorted() {
        // Two independent roots; `root-a` fans out to two dependents.
        let tasks = vec![
            task("root-a", "pending", &[]),
            task("root-b", "pending", &[]),
            task("leaf-y", "pending", &["root-a"]),
            task("leaf-x", "pending", &["root-a"]),
            task("leaf-z", "pending", &["root-b"]),
        ];
        let graph = TaskGraph::from_tasks(&tasks);
        assert_eq!(
            graph.roots,
            vec!["root-a".to_string(), "root-b".to_string()]
        );
        let expected = "\
root-a  pending
  └─ leaf-x  pending
  └─ leaf-y  pending
root-b  pending
  └─ leaf-z  pending
";
        assert_eq!(graph.render_text(), expected);
    }

    #[test]
    fn dangling_dependency_makes_task_a_root() {
        // `orphan` depends only on a task that is not present in the room.
        let tasks = vec![task("orphan", "pending", &["does-not-exist"])];
        let graph = TaskGraph::from_tasks(&tasks);
        assert_eq!(graph.roots, vec!["orphan".to_string()]);
        assert!(graph.edges.is_empty());
        assert!(graph.cycles.is_empty());
        assert_eq!(graph.render_text(), "orphan  pending\n");
    }

    #[test]
    fn two_node_cycle_is_reported() {
        let tasks = vec![
            task("task-a", "pending", &["task-b"]),
            task("task-b", "pending", &["task-a"]),
        ];
        let graph = TaskGraph::from_tasks(&tasks);
        assert!(graph.roots.is_empty());
        assert_eq!(graph.cycles.len(), 1);
        let cycle = &graph.cycles[0];
        // First and last entry close the loop.
        assert_eq!(cycle.first(), cycle.last());
        assert!(cycle.contains(&"task-a".to_string()));
        assert!(cycle.contains(&"task-b".to_string()));
        assert!(graph.render_text().contains("cycle detected: "));
    }

    #[test]
    fn self_dependency_is_a_cycle() {
        let tasks = vec![task("loop", "pending", &["loop"])];
        let graph = TaskGraph::from_tasks(&tasks);
        assert_eq!(
            graph.cycles,
            vec![vec!["loop".to_string(), "loop".to_string()]]
        );
    }

    #[test]
    fn cycle_with_a_tail_root_still_renders_the_root() {
        // `start` is a clean root feeding into a `a <-> b` cycle.
        let tasks = vec![
            task("start", "succeeded", &[]),
            task("a", "pending", &["start", "b"]),
            task("b", "pending", &["a"]),
        ];
        let graph = TaskGraph::from_tasks(&tasks);
        assert_eq!(graph.roots, vec!["start".to_string()]);
        assert_eq!(graph.cycles.len(), 1);
        let text = graph.render_text();
        // The reachable portion is drawn, the cycle does not loop forever, and
        // the cycle is reported.
        assert!(text.starts_with("start  succeeded\n"));
        assert!(text.contains("└─ a  pending"));
        assert!(text.contains("cycle detected: "));
    }

    #[test]
    fn empty_graph_renders_empty() {
        let graph = TaskGraph::from_tasks(&[]);
        assert!(graph.nodes.is_empty());
        assert!(graph.roots.is_empty());
        assert_eq!(graph.render_text(), "");
    }

    #[test]
    fn graph_serializes_to_json() {
        let graph = TaskGraph::from_tasks(&doc_chain());
        let value = serde_json::to_value(&graph).unwrap();
        assert!(value.get("nodes").is_some());
        assert!(value.get("edges").is_some());
        assert_eq!(value["roots"], serde_json::json!(["task-plan"]));
        assert_eq!(value["cycles"], serde_json::json!([]));
    }
}
