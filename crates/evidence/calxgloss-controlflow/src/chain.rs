//! Brace-depth-aware walker over Ghidra if/else-if chains.
//!
//! Ghidra renders switch-shaped code as `if (var == CONST) { ... }` followed
//! by `else if (var == CONST) { ... }` arms (each `else` on its own line).
//! This walker finds those chains — only arms sitting at the *same* brace
//! depth as the chain head count, so nested ifs inside a case body never
//! extend a chain — and records each arm's body line range so detectors can
//! inspect case bodies (state-machine transitions) after the fact.

/// One arm of an if/else-if chain, with its body's line span `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainCase {
    /// The compared constant, exactly as written (`1`, `0x10`, `STATE_IDLE`).
    pub konst: String,
    /// Lines of the arm's body (empty span when the arm has no braces).
    pub body: (usize, usize),
}

/// One if/else-if chain comparing a single variable against constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IfChain {
    /// The compared variable (`local_4`, `state`).
    pub var: String,
    /// The chain's arms, in source order.
    pub cases: Vec<ChainCase>,
    /// Whether the chain ends in a trailing `else` (a switch default).
    pub has_default: bool,
    /// Lines of the default arm's body, when present.
    pub default_body: Option<(usize, usize)>,
}

/// Net brace delta of a line, ignoring braces inside string literals.
pub(crate) fn net_braces(line: &str) -> i32 {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => depth -= 1,
            _ => {}
        }
    }
    depth
}

fn match_head(trimmed: &str) -> Option<(String, String)> {
    let rest = trimmed.strip_prefix("if")?.trim_start();
    // The head line usually opens the arm's brace: `if (x == 1) {`.
    let rest = rest.strip_suffix('{').map(str::trim_end).unwrap_or(rest);
    let inner = rest.strip_prefix('(')?.strip_suffix(')')?;
    let (var, konst) = inner.split_once("==")?;
    let var = var.trim();
    if !is_ident(var) {
        return None;
    }
    Some((var.to_string(), konst.trim().to_string()))
}

fn match_else_if(trimmed: &str) -> Option<(String, String)> {
    let rest = trimmed.strip_prefix("else")?.trim_start();
    match_head(rest)
}

fn match_else(trimmed: &str) -> bool {
    trimmed == "else" || trimmed == "else {"
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Find every if/else-if chain in `lines` comparing one variable against
/// constants. Chains may nest: a chain inside a case body is found too.
pub(crate) fn find_chains(lines: &[&str]) -> Vec<IfChain> {
    let mut chains = Vec::new();
    let mut depth = 0i32;
    // Arm lines already consumed by a chain, so the outer scan never treats
    // them as new chain heads.
    let mut arm_lines: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();
        let chain_depth = depth;
        depth += net_braces(trimmed);
        if arm_lines.contains(&i) {
            i += 1;
            continue;
        }
        // A chain head is an `if (...)` line — or an `else if (...)` line that
        // broke the previous chain by comparing a different variable.
        let head = match_head(trimmed).or_else(|| match_else_if(trimmed));
        if let Some((var, konst)) = head {
            arm_lines.push(i);
            let mut cases = vec![ChainCase {
                konst,
                body: (i + 1, i + 1),
            }];
            let mut has_default = false;
            let mut default_body = None;
            let mut j = i + 1;
            let mut d = depth;
            while j < lines.len() {
                let t = lines[j].trim();
                if d == chain_depth {
                    if let Some((v2, k2)) = match_else_if(t) {
                        if v2 == var {
                            arm_lines.push(j);
                            if let Some(last) = cases.last_mut() {
                                last.body.1 = j;
                            }
                            cases.push(ChainCase {
                                konst: k2,
                                body: (j + 1, j + 1),
                            });
                            d += net_braces(t);
                            j += 1;
                            continue;
                        }
                        break;
                    }
                    if match_else(t) {
                        has_default = true;
                        if let Some(last) = cases.last_mut() {
                            last.body.1 = j;
                        }
                        break;
                    }
                    break;
                }
                d += net_braces(t);
                j += 1;
            }
            if has_default {
                // Walk past the default body to close its span.
                let mut k = j + 1;
                let mut dd = d + net_braces(lines[j].trim());
                while k < lines.len() && dd > chain_depth {
                    dd += net_braces(lines[k].trim());
                    k += 1;
                }
                default_body = Some((j + 1, k));
            } else {
                if let Some(last) = cases.last_mut() {
                    last.body.1 = j;
                }
            }
            chains.push(IfChain {
                var,
                cases,
                has_default,
                default_body,
            });
        }
        i += 1;
    }
    chains
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(src: &str) -> Vec<&str> {
        src.lines().collect()
    }

    #[test]
    fn finds_simple_chain() {
        let lines = body(
            "\
if (local_4 == 1) {
    puts(\"one\");
}
else if (local_4 == 2) {
    puts(\"two\");
}
else {
    puts(\"other\");
}",
        );
        let chains = find_chains(&lines);
        assert_eq!(chains.len(), 1);
        let chain = &chains[0];
        assert_eq!(chain.var, "local_4");
        assert_eq!(chain.cases.len(), 2);
        assert_eq!(chain.cases[0].konst, "1");
        assert_eq!(chain.cases[1].konst, "2");
        assert!(chain.has_default);
        assert_eq!(chain.default_body, Some((7, 9)));
    }

    #[test]
    fn nested_if_does_not_extend_chain() {
        let lines = body(
            "\
if (x == 1) {
    if (y == 9) {
        f();
    }
}
else if (x == 2) {
    g();
}",
        );
        let chains = find_chains(&lines);
        // The outer chain has 2 arms; the nested if is its own (1-arm) chain.
        let outer = chains.iter().find(|c| c.var == "x").unwrap();
        assert_eq!(outer.cases.len(), 2);
        let inner = chains.iter().find(|c| c.var == "y").unwrap();
        assert_eq!(inner.cases.len(), 1);
    }

    #[test]
    fn different_variable_breaks_chain() {
        let lines = body(
            "\
if (x == 1) {
    f();
}
else if (y == 2) {
    g();
}",
        );
        let chains = find_chains(&lines);
        assert_eq!(chains.iter().filter(|c| c.var == "x").count(), 1);
        assert_eq!(chains.iter().filter(|c| c.var == "y").count(), 1);
    }

    #[test]
    fn braces_in_strings_ignored() {
        assert_eq!(net_braces("puts(\"a { b } c\");"), 0);
        assert_eq!(net_braces("puts(\"escaped \\\" brace {\");"), 0);
        assert_eq!(net_braces("if (x == 1) {"), 1);
        assert_eq!(net_braces("} else {"), 0);
    }

    #[test]
    fn case_body_spans_are_recorded() {
        let lines = body(
            "\
if (x == 1) {
    a();
    b();
}
else if (x == 2) {
    c();
}",
        );
        let chain = &find_chains(&lines)[0];
        assert_eq!(chain.cases[0].body, (1, 4));
        assert_eq!(chain.cases[1].body, (5, 7));
    }
}
