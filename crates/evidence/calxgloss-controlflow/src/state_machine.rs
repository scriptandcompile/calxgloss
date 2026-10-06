//! State-machine pattern detection.
//!
//! A state machine in Ghidra output looks like a switch-shaped chain on a
//! state variable (`if (state == STATE_IDLE) ... else if (state ==
//! STATE_RUN) ...`) whose case bodies assign new values to that same
//! variable (transitions). The detector requires at least `min_states` arms
//! with at least one named constant (matching the configurable name set,
//! default `STATE_*` / `IDLE` / `RUNNING`), and reports the transition
//! targets plus the idle state — a state that is compared but never entered
//! by a transition assignment, or one with an idle-like name.

use calxgloss_types::Confidence;

use crate::chain::find_chains;
use crate::types::StateMachine;

/// Detector for state-machine-shaped if/else-if chains.
#[derive(Debug, Clone)]
pub struct StateMachineDetector {
    /// Name patterns for state constants; a trailing `*` means prefix match.
    state_names: Vec<String>,
    /// Minimum number of arms for a chain to look like a state machine.
    min_states: usize,
}

impl Default for StateMachineDetector {
    fn default() -> Self {
        Self {
            state_names: vec!["STATE_*".into(), "IDLE".into(), "RUNNING".into()],
            min_states: 3,
        }
    }
}

impl StateMachineDetector {
    /// Create a detector with the default name set (`STATE_*`/`IDLE`/
    /// `RUNNING`) and minimum state count (3).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the default state-name pattern set.
    pub fn with_state_names<S: AsRef<str>>(mut self, names: &[S]) -> Self {
        self.state_names = names.iter().map(|n| n.as_ref().to_string()).collect();
        self
    }

    /// Lower or raise the arm count a chain needs to read as a state
    /// machine.
    pub fn with_min_states(mut self, min_states: usize) -> Self {
        self.min_states = min_states;
        self
    }

    fn is_named_state(&self, konst: &str) -> bool {
        self.state_names.iter().any(|pat| {
            if let Some(prefix) = pat.strip_suffix('*') {
                konst.starts_with(prefix)
            } else {
                konst.eq_ignore_ascii_case(pat)
            }
        })
    }

    /// Detect state machines in one decompiled function body.
    pub(crate) fn detect(&self, name: &str, code: &str) -> Vec<StateMachine> {
        let lines: Vec<&str> = code.lines().collect();
        find_chains(&lines)
            .into_iter()
            .filter(|chain| chain.cases.len() >= self.min_states)
            .filter_map(|chain| {
                let case_consts: Vec<&str> = chain.cases.iter().map(|c| c.konst.as_str()).collect();

                // Transitions: `var = TARGET;` inside any case (or default) body.
                let mut transitions: Vec<String> = Vec::new();
                let mut bodies: Vec<(usize, usize)> = chain.cases.iter().map(|c| c.body).collect();
                bodies.extend(chain.default_body);
                let assign_prefix = format!("{} =", chain.var);
                for (start, end) in bodies {
                    for line in &lines[start.min(lines.len())..end.min(lines.len())] {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix(assign_prefix.as_str()) {
                            let target = rest.trim().trim_end_matches(';').trim();
                            if !target.is_empty() && !transitions.iter().any(|t| t == target) {
                                transitions.push(target.to_string());
                            }
                        }
                    }
                }

                // A chain qualifies when it uses named state constants or
                // reassigns its own state variable (transitions).
                let named = chain.cases.iter().any(|c| self.is_named_state(&c.konst));
                if !named && transitions.is_empty() {
                    return None;
                }

                // Idle: a state compared by the chain that no transition
                // assignment ever enters, or — failing that — a state with an
                // idle-like name.
                let idle_state = case_consts
                    .iter()
                    .find(|c| !transitions.iter().any(|t| t.as_str() == **c))
                    .map(|c| c.to_string())
                    .or_else(|| {
                        case_consts
                            .iter()
                            .find(|c| is_idle_name(c))
                            .map(|c| c.to_string())
                    });

                let n = chain.cases.len();
                let mut evidence = format!("state variable {} with {} states", chain.var, n);
                if let Some(idle) = &idle_state {
                    evidence.push_str(&format!(" idle: {}", idle));
                }
                Some(StateMachine {
                    function: name.to_string(),
                    state_var: chain.var.clone(),
                    states: chain.cases.iter().map(|c| c.konst.clone()).collect(),
                    transitions,
                    idle_state,
                    suggestion: format!(
                        "enum State + match {} {{ /* {} states */ }}",
                        chain.var, n
                    ),
                    confidence: Confidence::new(if named { 70 } else { 60 }),
                    evidence,
                })
            })
            .collect()
    }
}

fn is_idle_name(name: &str) -> bool {
    name.to_ascii_uppercase().contains("IDLE")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SM: &str = "\
if (local_4 == STATE_IDLE) {
    local_4 = STATE_RUNNING;
}
else if (local_4 == STATE_RUNNING) {
    local_4 = STATE_DONE;
}
else if (local_4 == STATE_DONE) {
    return;
}
";

    #[test]
    fn detects_named_state_chain() {
        let findings = StateMachineDetector::default().detect("pump", SM);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.function, "pump");
        assert_eq!(f.state_var, "local_4");
        assert_eq!(f.states, ["STATE_IDLE", "STATE_RUNNING", "STATE_DONE"]);
        assert_eq!(u8::from(f.confidence), 70);
        assert_eq!(
            f.suggestion,
            "enum State + match local_4 { /* 3 states */ }"
        );
    }

    #[test]
    fn transitions_and_idle_state_are_found() {
        let f = &StateMachineDetector::default().detect("pump", SM)[0];
        assert_eq!(f.transitions, ["STATE_RUNNING", "STATE_DONE"]);
        // STATE_IDLE is compared but no transition assignment enters it.
        assert_eq!(f.idle_state.as_deref(), Some("STATE_IDLE"));
        assert!(f.evidence.contains("idle: STATE_IDLE"));
    }

    #[test]
    fn idle_state_falls_back_to_idle_like_name() {
        let code = "\
if (state == STATE_A) {
    state = STATE_B;
}
else if (state == STATE_B) {
    state = STATE_IDLE;
}
else if (state == STATE_IDLE) {
    state = STATE_A;
}
";
        // Every state is entered by some transition, so the idle state is
        // picked by its idle-like name instead.
        let f = &StateMachineDetector::default().detect("loop", code)[0];
        assert_eq!(f.idle_state.as_deref(), Some("STATE_IDLE"));
    }

    #[test]
    fn numeric_only_chain_gets_lower_confidence() {
        let code = "\
if (local_4 == 1) {
    local_4 = 2;
}
else if (local_4 == 2) {
    local_4 = 3;
}
else if (local_4 == 3) {
    local_4 = 1;
}
";
        // Numeric-only chains qualify via their transition assignments, at
        // the lower 60 confidence.
        let findings = StateMachineDetector::default().detect("pump", code);
        assert_eq!(findings.len(), 1);
        assert_eq!(u8::from(findings[0].confidence), 60);

        // Without transitions, a numeric-only chain is just a switch.
        let plain = "\
if (local_4 == 1) {
    a();
}
else if (local_4 == 2) {
    b();
}
else if (local_4 == 3) {
    c();
}
";
        assert!(
            StateMachineDetector::default()
                .detect("pump", plain)
                .is_empty()
        );
    }

    #[test]
    fn two_state_chain_is_below_threshold() {
        let code = "\
if (state == STATE_A) {
    state = STATE_B;
}
else if (state == STATE_B) {
    state = STATE_A;
}
";
        assert!(
            StateMachineDetector::default()
                .detect("toggle", code)
                .is_empty()
        );
    }

    #[test]
    fn min_states_is_configurable() {
        let code = "\
if (state == STATE_A) {
    state = STATE_B;
}
else if (state == STATE_B) {
    state = STATE_A;
}
";
        let findings = StateMachineDetector::default()
            .with_min_states(2)
            .detect("toggle", code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn name_set_is_swappable() {
        let code = "\
if (mode == MODE_ON) {
    mode = MODE_OFF;
}
else if (mode == MODE_OFF) {
    mode = MODE_ON;
}
else if (mode == MODE_SLEEP) {
    mode = MODE_OFF;
}
";
        // With the default name set these constants are unnamed: still
        // detected (via transitions) but at the lower confidence.
        let findings = StateMachineDetector::default().detect("blink", code);
        assert_eq!(findings.len(), 1);
        assert_eq!(u8::from(findings[0].confidence), 60);
        // Swapping the name set names them and lifts confidence to 70.
        let findings = StateMachineDetector::default()
            .with_state_names(&["MODE_*"])
            .detect("blink", code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].state_var, "mode");
        assert_eq!(u8::from(findings[0].confidence), 70);
    }

    #[test]
    fn plain_identifier_assignments_count_as_transitions() {
        let code = "\
if (state == STATE_A) {
    state = next_mode();
}
else if (state == STATE_B) {
    state = g_state;
}
else if (state == STATE_C) {
    state = 0;
}
";
        let f = &StateMachineDetector::default().detect("loop", code)[0];
        assert_eq!(f.transitions, ["next_mode()", "g_state", "0"]);
    }
}
