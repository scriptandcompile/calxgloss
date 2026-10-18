//! Brace-disciplined control flow graph over one decompiled body.
//!
//! The graph is crate-internal machinery, not a persisted artifact: the
//! loop detector, the branch-density detector, and the recursion deepening
//! all read the *same* per-body graph, so their nesting, density, and depth
//! claims cannot disagree with each other. Only their readings join the
//! finding union; the graph itself is never written out.
//!
//! Blocks are cut where the pseudo-C says control can part company with
//! the straight line: `if`/`else` heads, `for`/`while`/`do` heads, labels
//! (including `case`/`default` arms, though the switch's own dispatch and
//! `break` edges are not modelled — the chain detector reads switches
//! textually), `goto` statements, and `return`s. Edges are fall-through,
//! branch taken/not-taken, `goto` jumps, and loop back edges — a `goto`
//! back to an earlier block is a back edge, and the graph exposes every
//! back edge with its loop header. The line scan reuses the chain walker's
//! brace-depth discipline ([`net_braces`]) and adds the same string-literal
//! blindness, so braces, keywords, and names spelled inside string
//! literals invent no blocks and no edges. A truncated body (the decompiler
//! cutting a decompile off mid-brace) degrades to a partial graph instead
//! of panicking.
//!
//! Nesting comes out at its real depth: brace depth is recorded per block
//! and per loop header, so a loop inside a chain case body nests under that
//! chain rather than reading as a top-level loop.

use crate::chain::{net_braces, outside_strings};
use crate::types::LoopKind;

/// Identity of a basic block within one [`Cfg`].
pub(crate) type BlockId = usize;

/// How a block hands control on, decided by its last line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Terminator {
    /// Falls through to the next block in document order.
    FallThrough,
    /// Ends at an `if`/`else if` head: taken and not-taken branch edges.
    Branch,
    /// Ends at a `for`/`while`/`do` head: body edge, and an exit edge and
    /// back edge once the body's closing brace is visible.
    Loop,
    /// Ends at a `} while (...)` tail: back edge to the `do` head and an
    /// exit edge on the block the tail closes.
    DoWhileTail,
    /// Ends at a `return`: no successors.
    Return,
    /// Ends at a `goto`: one jump edge — a back edge when the label sits at
    /// or before the jumping block.
    Goto,
}

/// Why an edge exists, per the pseudo-C shape that put it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EdgeKind {
    /// Sequential flow out of a block that does not jump.
    FallThrough,
    /// The condition held: into the `if`/loop body.
    BranchTaken,
    /// The condition failed: past the `if` body, or out of the loop.
    BranchNotTaken,
    /// A forward `goto` to a later label.
    Goto,
    /// A loop's back edge: a structured loop closing on itself, or a
    /// `goto` back to an earlier label.
    BackEdge,
}

/// One directed edge between two blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Edge {
    pub from: BlockId,
    pub to: BlockId,
    pub kind: EdgeKind,
}

/// One basic block: a maximal run of lines with a single entry and the
/// single exit its [`Terminator`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Block {
    pub id: BlockId,
    /// Body line span `[start, end)`; the terminator sits on `end - 1`.
    pub start: usize,
    pub end: usize,
    /// Brace depth at the block's first line. Function-body statements sit
    /// at depth 1; a loop inside a chain case body reads deeper than the
    /// chain head, which is what makes nesting honest.
    pub depth: i32,
    pub terminator: Terminator,
}

/// One loop in the body, identified by its header block. The kind
/// vocabulary is the finding's own — the enum lives in `types` so the
/// graph's loop kinds and the finding's `kinds_seen` cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Loop {
    /// The block the back edge returns to.
    pub header: BlockId,
    pub kind: LoopKind,
    /// Brace depth of the loop head, so nesting composes with blocks.
    pub depth: i32,
}

/// The control flow graph of one decompiled body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cfg {
    blocks: Vec<Block>,
    edges: Vec<Edge>,
    loops: Vec<Loop>,
    line_block: Vec<Option<BlockId>>,
}

/// What a line is, decided on the string-blanked trim of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind<'a> {
    Other,
    /// A jump target: `ident:` alone, `default:`, or a `case ...:` arm.
    Label(&'a str),
    If,
    ElseIf,
    Else,
    For,
    While,
    Do,
    /// The `} while (...);` that closes a `do` body.
    WhileTail,
    Return,
    Goto(&'a str),
    /// A line that is just a closing brace.
    Close,
}

impl LineKind<'_> {
    /// Whether this line opens an `else`/`else if` arm — the shape a taken
    /// branch must route around rather than fall through into.
    fn is_else_like(self) -> bool {
        matches!(self, LineKind::Else | LineKind::ElseIf)
    }
}

/// `s` opens with `word` as a whole word, not as the prefix of a longer name.
fn starts_word(s: &str, word: &str) -> bool {
    s.starts_with(word)
        && s[word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
}

/// The label name when `t` is `ident:` alone (or followed by `{`).
fn label_name(t: &str) -> Option<&str> {
    let split = t.find(':')?;
    let name = &t[..split];
    let ident = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ident {
        return None;
    }
    let rest = t[split + 1..].trim();
    (rest.is_empty() || rest == "{").then_some(name)
}

/// Classify one string-blanked trimmed line. A leading `}` is peeled so
/// `} else {` and `} while (x);` read as the heads they are; a bare `}`
/// line reads as [`LineKind::Close`].
fn classify(t: &str) -> LineKind<'_> {
    if t.is_empty() {
        return LineKind::Other;
    }
    let (core, inline_close) = match t.strip_prefix('}') {
        Some(rest) => (rest.trim_start(), true),
        None => (t, false),
    };
    if core.is_empty() {
        return LineKind::Close;
    }
    if starts_word(core, "else") {
        let rest = core[4..].trim_start();
        return if starts_word(rest, "if") {
            LineKind::ElseIf
        } else {
            LineKind::Else
        };
    }
    if starts_word(core, "if") {
        return LineKind::If;
    }
    if starts_word(core, "for") {
        return LineKind::For;
    }
    if starts_word(core, "while") {
        return if inline_close && core.ends_with(';') {
            LineKind::WhileTail
        } else {
            LineKind::While
        };
    }
    if starts_word(core, "do") {
        return LineKind::Do;
    }
    if starts_word(core, "return") {
        return LineKind::Return;
    }
    if starts_word(core, "goto") {
        return LineKind::Goto(core[4..].trim_start().trim_end_matches(';').trim());
    }
    if starts_word(core, "case") && core.contains(':') {
        return LineKind::Label("");
    }
    match label_name(core) {
        Some(name) => LineKind::Label(name),
        None => LineKind::Other,
    }
}

impl Cfg {
    /// Build the graph of one decompiled body.
    ///
    /// Blocks are cut at branch heads, loop heads, labels, `goto`s, and
    /// `return`s; edges join them in document order and by the shapes those
    /// lines spell. A body truncated mid-brace still yields a graph — the
    /// edges that would need the missing closing brace are simply absent.
    pub(crate) fn build(body: &str) -> Cfg {
        let code: Vec<String> = body.lines().map(outside_strings).collect();
        let trimmed: Vec<&str> = code.iter().map(String::as_str).map(str::trim).collect();
        let n = trimmed.len();
        let kinds: Vec<LineKind> = trimmed.iter().map(|t| classify(t)).collect();

        // Brace depth around every line, on the chain walker's discipline.
        let mut depth_before = Vec::with_capacity(n);
        let mut depth_after = Vec::with_capacity(n);
        let mut depth = 0i32;
        for line in &code {
            depth_before.push(depth);
            depth += net_braces(line);
            depth_after.push(depth);
        }

        // Cut the blocks. A head/terminator line closes the block it sits at
        // the end of and opens the next; a label opens the block it starts.
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut start = 0;
        for (i, &kind) in kinds.iter().enumerate() {
            match kind {
                LineKind::Label(_) => {
                    if i > start {
                        spans.push((start, i));
                    }
                    start = i;
                }
                LineKind::If
                | LineKind::ElseIf
                | LineKind::For
                | LineKind::While
                | LineKind::Do => {
                    // The head line belongs to the block it terminates:
                    // the decision is that block's exit.
                    spans.push((start, i + 1));
                    start = i + 1;
                }
                LineKind::Else => {
                    if i > start {
                        spans.push((start, i));
                    }
                    start = i + 1;
                }
                LineKind::Return | LineKind::Goto(_) => {
                    spans.push((start, i + 1));
                    start = i + 1;
                }
                LineKind::Close | LineKind::WhileTail => {
                    if i >= start {
                        spans.push((start, i + 1));
                    }
                    start = i + 1;
                }
                LineKind::Other => {}
            }
        }
        if start < n {
            spans.push((start, n));
        }

        let mut blocks: Vec<Block> = spans
            .into_iter()
            .map(|(start, end)| Block {
                id: 0,
                start,
                end,
                depth: depth_before.get(start).copied().unwrap_or(0),
                terminator: Terminator::FallThrough,
            })
            .collect();
        for (id, block) in blocks.iter_mut().enumerate() {
            block.id = id;
        }

        let mut starts_at = vec![None; n + 1];
        let mut line_block = vec![None; n + 1];
        for block in &blocks {
            starts_at[block.start] = Some(block.id);
            line_block[block.start..block.end].fill(Some(block.id));
        }
        let starting_at = |line: usize| starts_at.get(line).copied().flatten();
        let containing = |line: usize| line_block.get(line).copied().flatten();

        // Jump targets: the block each label opens.
        let labels: Vec<(&str, BlockId)> = blocks
            .iter()
            .filter_map(|block| match kinds.get(block.start) {
                Some(LineKind::Label(name)) if !name.is_empty() => Some((*name, block.id)),
                _ => None,
            })
            .collect();

        // The line closing a body: the first line at or after `start` that
        // sits inside depth `inner` and carries a brace back out of it.
        let close_from = |start: usize, inner: i32| -> Option<usize> {
            (start..n).find(|&j| {
                depth_before[j] == inner && (depth_after[j] < inner || trimmed[j].starts_with('}'))
            })
        };
        // The line closing the body a head opens: the first line back at the
        // head's own depth that carries a closing brace. A head with no
        // brace on its line has a single-statement body instead — Ghidra
        // always braces its bodies, so the braceless form is an
        // approximation kept only so a hand-written or truncated body
        // still reads as a graph.
        let body_close = |head: usize| close_from(head + 1, depth_before[head] + 1);
        let body_end = |head: usize| -> Option<usize> {
            body_close(head)
                .or_else(|| (net_braces(&code[head]) == 0 && head + 1 < n).then_some(head + 1))
        };

        // Walk the whole `else`/`else if` chain that starts at or right
        // after `close` and answer the block just past its final arm —
        // where a branch body that skips the chain lands.
        let chain_join = |close: usize| -> Option<BlockId> {
            let mut cur = close;
            loop {
                let el = if kinds.get(cur).is_some_and(|k| k.is_else_like()) {
                    cur
                } else if kinds.get(cur + 1).is_some_and(|k| k.is_else_like()) {
                    cur + 1
                } else {
                    break;
                };
                match close_from(el + 1, depth_after[el]) {
                    Some(c2) => cur = c2,
                    None => break,
                }
            }
            starting_at(cur + 1).or_else(|| containing(cur + 1))
        };

        let mut edges: Vec<Edge> = Vec::new();
        let mut loops: Vec<Loop> = Vec::new();
        let mut claimed_tails = vec![false; n];

        for idx in 0..blocks.len() {
            let block = blocks[idx];
            let head = block.end - 1;
            match kinds[head] {
                LineKind::If | LineKind::ElseIf => {
                    blocks[idx].terminator = Terminator::Branch;
                    let taken = starting_at(head + 1).or_else(|| containing(head + 1));
                    let r = depth_before[head];
                    let not_taken = body_end(head).and_then(|c| {
                        // The matching `else` sits on the closing line
                        // (`} else {`) or on the line right after it, at
                        // this head's own depth.
                        let else_line = if kinds[c].is_else_like() {
                            Some(c)
                        } else if kinds.get(c + 1).is_some_and(|k| k.is_else_like())
                            && depth_before.get(c + 1).copied() == Some(r)
                        {
                            Some(c + 1)
                        } else {
                            None
                        };
                        match else_line {
                            Some(el) if kinds[el] == LineKind::ElseIf => containing(el),
                            Some(el) => starting_at(el + 1),
                            None => starting_at(c + 1).or_else(|| containing(c + 1)),
                        }
                    });
                    if let Some(to) = taken {
                        edges.push(Edge {
                            from: block.id,
                            to,
                            kind: EdgeKind::BranchTaken,
                        });
                    }
                    if let Some(to) = not_taken {
                        edges.push(Edge {
                            from: block.id,
                            to,
                            kind: EdgeKind::BranchNotTaken,
                        });
                    }
                }
                LineKind::For | LineKind::While => {
                    blocks[idx].terminator = Terminator::Loop;
                    let kind = if kinds[head] == LineKind::For {
                        LoopKind::For
                    } else {
                        LoopKind::While
                    };
                    loops.push(Loop {
                        header: block.id,
                        kind,
                        depth: depth_before[head],
                    });
                    if let Some(to) = starting_at(head + 1).or_else(|| containing(head + 1)) {
                        edges.push(Edge {
                            from: block.id,
                            to,
                            kind: EdgeKind::BranchTaken,
                        });
                    }
                    if let Some(c) = body_close(head) {
                        if let Some(to) = starting_at(c + 1).or_else(|| containing(c + 1)) {
                            edges.push(Edge {
                                from: block.id,
                                to,
                                kind: EdgeKind::BranchNotTaken,
                            });
                        }
                        if let Some(tail) = containing(c) {
                            edges.push(Edge {
                                from: tail,
                                to: block.id,
                                kind: EdgeKind::BackEdge,
                            });
                        }
                    }
                }
                LineKind::Do => {
                    blocks[idx].terminator = Terminator::Loop;
                    loops.push(Loop {
                        header: block.id,
                        kind: LoopKind::DoWhile,
                        depth: depth_before[head],
                    });
                    if let Some(to) = starting_at(head + 1).or_else(|| containing(head + 1)) {
                        edges.push(Edge {
                            from: block.id,
                            to,
                            kind: EdgeKind::BranchTaken,
                        });
                    }
                    let r = depth_before[head];
                    let tail = (head + 1..n).find(|&j| {
                        kinds[j] == LineKind::WhileTail
                            && depth_before[j] == r + 1
                            && !claimed_tails[j]
                    });
                    if let Some(tail_line) = tail {
                        claimed_tails[tail_line] = true;
                        if let Some(body_block) = containing(tail_line) {
                            edges.push(Edge {
                                from: body_block,
                                to: block.id,
                                kind: EdgeKind::BackEdge,
                            });
                            if let Some(to) =
                                starting_at(tail_line + 1).or_else(|| containing(tail_line + 1))
                            {
                                edges.push(Edge {
                                    from: body_block,
                                    to,
                                    kind: EdgeKind::BranchNotTaken,
                                });
                            }
                        }
                    }
                }
                LineKind::Return => {
                    blocks[idx].terminator = Terminator::Return;
                }
                LineKind::Goto(target) => {
                    blocks[idx].terminator = Terminator::Goto;
                    if let Some(&(_, to)) = labels.iter().find(|(name, _)| *name == target) {
                        if to <= block.id {
                            // Back to an earlier (or its own) block: a loop.
                            edges.push(Edge {
                                from: block.id,
                                to,
                                kind: EdgeKind::BackEdge,
                            });
                            if !loops.iter().any(|loop_| loop_.header == to) {
                                loops.push(Loop {
                                    header: to,
                                    kind: LoopKind::Goto,
                                    depth: blocks[to].depth,
                                });
                            }
                        } else {
                            edges.push(Edge {
                                from: block.id,
                                to,
                                kind: EdgeKind::Goto,
                            });
                        }
                    }
                }
                LineKind::WhileTail => {
                    if claimed_tails[head] {
                        blocks[idx].terminator = Terminator::DoWhileTail;
                    } else {
                        // A `} while` with no `do` in sight (a truncated
                        // body): just a block end like any other.
                        if let Some(next) = blocks.get(idx + 1) {
                            edges.push(Edge {
                                from: block.id,
                                to: next.id,
                                kind: EdgeKind::FallThrough,
                            });
                        }
                    }
                }
                LineKind::Else | LineKind::Close | LineKind::Label(_) | LineKind::Other => {
                    // Fall through — unless the very next line is the
                    // `else` this branch's head already routed around, in
                    // which case the flow skips the whole else chain.
                    if kinds.get(head + 1).is_some_and(|k| k.is_else_like()) {
                        if let Some(to) = chain_join(head) {
                            edges.push(Edge {
                                from: block.id,
                                to,
                                kind: EdgeKind::FallThrough,
                            });
                        }
                    } else if let Some(next) = blocks.get(idx + 1) {
                        edges.push(Edge {
                            from: block.id,
                            to: next.id,
                            kind: EdgeKind::FallThrough,
                        });
                    }
                }
            }
        }

        Cfg {
            blocks,
            edges,
            loops,
            line_block,
        }
    }

    /// Every block, in document order.
    pub(crate) fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Every edge, grouped by source block in document order.
    pub(crate) fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Every loop in the body, in the order its head line appears (goto
    /// loops land after the structured ones, in goto order).
    pub(crate) fn loops(&self) -> &[Loop] {
        &self.loops
    }

    /// The line span `[start, end)` each loop's body covers, in loop
    /// order. A structured loop runs from the line after its head
    /// through the line that closes it — the back edge's source block's
    /// last line; a `goto` loop runs from its label block's first line
    /// through the jumping block. A loop whose closing brace never
    /// arrives (a truncated body) runs to the end of the body: the
    /// brace discipline that built the graph keeps the reading honest.
    pub(crate) fn loop_body_spans(&self) -> Vec<(usize, usize)> {
        let body_end = self.line_block.len() - 1;
        self.loops
            .iter()
            .map(|loop_| {
                let head = &self.blocks[loop_.header];
                let start = if loop_.kind == LoopKind::Goto {
                    head.start
                } else {
                    head.end
                };
                let end = self
                    .back_edges()
                    .filter(|edge| edge.to == loop_.header)
                    .map(|edge| self.blocks[edge.from].end)
                    .max()
                    .unwrap_or(body_end);
                (start, end)
            })
            .collect()
    }

    /// The block the body enters through, when it has one.
    pub(crate) fn entry(&self) -> Option<BlockId> {
        self.blocks.first().map(|block| block.id)
    }

    pub(crate) fn block(&self, id: BlockId) -> Option<&Block> {
        self.blocks.get(id)
    }

    /// The block covering `line`, when the line sits inside one.
    pub(crate) fn block_at(&self, line: usize) -> Option<BlockId> {
        self.line_block.get(line).copied().flatten()
    }

    /// Where control can go from `id`.
    pub(crate) fn successors(&self, id: BlockId) -> impl Iterator<Item = BlockId> + '_ {
        self.edges
            .iter()
            .filter(move |e| e.from == id)
            .map(|e| e.to)
    }

    /// Every back edge, each pointing at its loop header.
    pub(crate) fn back_edges(&self) -> impl Iterator<Item = &Edge> + '_ {
        self.edges.iter().filter(|e| e.kind == EdgeKind::BackEdge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(src: &str) -> Cfg {
        Cfg::build(src)
    }

    fn edge(cfg: &Cfg, from: BlockId, to: BlockId) -> Option<EdgeKind> {
        cfg.edges
            .iter()
            .find(|e| e.from == from && e.to == to)
            .map(|e| e.kind)
    }

    fn spans(cfg: &Cfg) -> Vec<(usize, usize)> {
        cfg.blocks().iter().map(|b| (b.start, b.end)).collect()
    }

    #[test]
    fn blocks_split_at_if_else_heads() {
        let graph = cfg("\
if (x == 1) {
    a();
}
else {
    b();
}");
        // if head, then body, else body: three blocks.
        assert_eq!(spans(&graph), vec![(0, 1), (1, 3), (4, 6)]);
        assert_eq!(
            graph.block(0).expect("if head block").terminator,
            Terminator::Branch
        );
        assert_eq!(
            graph.block(1).expect("then body block").terminator,
            Terminator::FallThrough
        );
        assert_eq!(
            graph.block(2).expect("else body block").terminator,
            Terminator::FallThrough
        );
    }

    #[test]
    fn blocks_split_at_loop_heads_labels_gotos_and_returns() {
        let graph = cfg("\
for (i = 0; i < 10; i = i + 1) {
    f();
}
while (x) {
    g();
}
do {
    h();
} while (x);
goto LAB_join;
LAB_join:
return;");
        // for head, for body, while head, while body, do head, do body
        // (closed by its tail), goto, label + return.
        assert_eq!(
            spans(&graph),
            vec![
                (0, 1),
                (1, 3),
                (3, 4),
                (4, 6),
                (6, 7),
                (7, 9),
                (9, 10),
                (10, 12)
            ]
        );
        assert_eq!(
            graph.block(0).expect("for head block").terminator,
            Terminator::Loop
        );
        assert_eq!(
            graph.block(2).expect("while head block").terminator,
            Terminator::Loop
        );
        assert_eq!(
            graph.block(4).expect("do head block").terminator,
            Terminator::Loop
        );
        assert_eq!(
            graph.block(5).expect("do-while tail block").terminator,
            Terminator::DoWhileTail
        );
        assert_eq!(
            graph.block(6).expect("goto block").terminator,
            Terminator::Goto
        );
        assert_eq!(
            graph.block(7).expect("return block").terminator,
            Terminator::Return
        );
    }

    #[test]
    fn fall_through_edge_connects_sequential_blocks() {
        let graph = cfg("\
a();
if (x) {
    b();
}
c();");
        assert_eq!(edge(&graph, 0, 1), Some(EdgeKind::BranchTaken));
        assert_eq!(edge(&graph, 0, 2), Some(EdgeKind::BranchNotTaken));
        assert_eq!(edge(&graph, 1, 2), Some(EdgeKind::FallThrough));
    }

    #[test]
    fn branch_edges_split_taken_and_not_taken_around_else() {
        let graph = cfg("\
if (x == 1) {
    a();
}
else {
    b();
}
c();");
        // 0: if head, 1: then body, 2: else body, 3: join.
        assert_eq!(edge(&graph, 0, 1), Some(EdgeKind::BranchTaken));
        assert_eq!(edge(&graph, 0, 2), Some(EdgeKind::BranchNotTaken));
        // The then body does NOT fall through into the else body — it
        // skips the chain and lands at the join.
        assert_eq!(edge(&graph, 1, 2), None);
        assert_eq!(edge(&graph, 1, 3), Some(EdgeKind::FallThrough));
        assert_eq!(edge(&graph, 2, 3), Some(EdgeKind::FallThrough));
    }

    #[test]
    fn else_if_chain_routes_not_taken_into_next_arm() {
        let graph = cfg("\
if (x == 1) {
    a();
}
else if (x == 2) {
    b();
}
else {
    c();
}");
        // 0: if, 1: arm-1 body, 2: else-if head, 3: arm-2 body, 4: default body.
        assert_eq!(edge(&graph, 0, 1), Some(EdgeKind::BranchTaken));
        assert_eq!(edge(&graph, 0, 2), Some(EdgeKind::BranchNotTaken));
        assert_eq!(edge(&graph, 2, 3), Some(EdgeKind::BranchTaken));
        assert_eq!(edge(&graph, 2, 4), Some(EdgeKind::BranchNotTaken));
        assert_eq!(edge(&graph, 1, 2), None);
        assert_eq!(edge(&graph, 3, 4), None);
    }

    #[test]
    fn while_loop_exposes_back_edge_and_header() {
        let graph = cfg("\
while (x) {
    f();
}
g();");
        assert_eq!(edge(&graph, 0, 1), Some(EdgeKind::BranchTaken));
        assert_eq!(edge(&graph, 0, 2), Some(EdgeKind::BranchNotTaken));
        assert_eq!(edge(&graph, 1, 0), Some(EdgeKind::BackEdge));
        assert_eq!(graph.loops().len(), 1);
        assert_eq!(graph.loops()[0].header, 0);
        assert_eq!(graph.loops()[0].kind, LoopKind::While);
        assert_eq!(graph.back_edges().count(), 1);
    }

    #[test]
    fn for_and_do_while_loops_read_at_their_heads() {
        let graph = cfg("\
for (i = 0; i < 3; i = i + 1) {
    f();
}
do {
    g();
} while (x);");
        let kinds: Vec<LoopKind> = graph.loops().iter().map(|l| l.kind).collect();
        assert_eq!(kinds, vec![LoopKind::For, LoopKind::DoWhile]);
        // for: body back to head; do-while: tail block back to do head.
        assert_eq!(edge(&graph, 1, 0), Some(EdgeKind::BackEdge));
        assert_eq!(edge(&graph, 3, 2), Some(EdgeKind::BackEdge));
        // The do-while tail also exits forward.
        assert_eq!(
            graph.block(3).expect("do-while tail block").terminator,
            Terminator::DoWhileTail
        );
    }

    #[test]
    fn goto_back_to_label_yields_a_back_edge_and_a_goto_loop() {
        let graph = cfg("\
LAB_top:
    x = x + 1;
    goto LAB_top;
return;");
        // 0: label body ending in goto, 1: return.
        assert_eq!(edge(&graph, 0, 0), Some(EdgeKind::BackEdge));
        assert_eq!(
            graph.block(0).expect("goto block").terminator,
            Terminator::Goto
        );
        assert_eq!(graph.loops().len(), 1);
        assert_eq!(graph.loops()[0].header, 0);
        assert_eq!(graph.loops()[0].kind, LoopKind::Goto);
        assert_eq!(graph.back_edges().count(), 1);
    }

    #[test]
    fn forward_goto_lands_a_jump_edge() {
        let graph = cfg("\
goto LAB_join;
dead();
LAB_join:
return;");
        // 0: goto, 1: dead code, 2: label + return.
        assert_eq!(edge(&graph, 0, 2), Some(EdgeKind::Goto));
        assert_eq!(edge(&graph, 0, 1), None);
        assert_eq!(graph.loops().len(), 0);
    }

    #[test]
    fn return_ends_a_block_with_no_successors() {
        let graph = cfg("\
if (x) {
    return;
}
f();");
        // 0: if head, 1: return, 2: closing brace, 3: f().
        assert_eq!(graph.successors(1).count(), 0);
        assert_eq!(
            graph.block(1).expect("return block").terminator,
            Terminator::Return
        );
    }

    #[test]
    fn string_literals_invent_no_blocks_or_edges() {
        let graph = cfg("\
puts(\"if (x == 1) {\");
puts(\"} else {\");
puts(\"while (y) { goto LAB_100; }\");
puts(\"return\");
puts(\"LAB_100:\");");
        assert_eq!(graph.blocks().len(), 1);
        assert!(graph.edges().is_empty());
        assert!(graph.loops().is_empty());
    }

    #[test]
    fn braces_in_string_literals_do_not_move_depth() {
        let graph = cfg("\
if (x) {
    puts(\"a { b } c\");
    f();
}");
        // The puts line sits inside the if body at depth 1, not back at 0.
        let body = graph.block(1).expect("if body block");
        assert_eq!(body.depth, 1);
        assert_eq!(body.end, 4);
    }

    #[test]
    fn truncated_body_degrades_without_panicking() {
        // Unclosed if and while, a goto to a label that never arrives, and
        // a bare `goto` with no name: a partial graph, no panic.
        let graph = cfg("\
if (x) {
    while (y) {
        f();
    goto
goto LAB_gone;");
        assert!(!graph.blocks().is_empty());
        assert_eq!(graph.loops().len(), 1); // the while head still reads
        assert!(
            graph
                .edges()
                .iter()
                .all(|e| e.from < graph.blocks().len() && e.to < graph.blocks().len())
        );
    }

    #[test]
    fn nested_loop_in_chain_case_body_nests_under_the_chain() {
        let graph = cfg("\
if (local_4 == 1) {
    while (x) {
        f();
    }
}
else if (local_4 == 2) {
    g();
}");
        // The chain head sits at depth 0; the loop inside its first arm
        // reads at depth 1 — nested under the chain, not beside it.
        assert_eq!(graph.loops().len(), 1);
        let loop_ = &graph.loops()[0];
        assert_eq!(loop_.kind, LoopKind::While);
        assert_eq!(loop_.depth, 1);
        let chain_head = graph.block_at(0).expect("chain head at line 0");
        assert_eq!(graph.block(chain_head).expect("chain head block").depth, 0);
        assert_eq!(
            graph.block(loop_.header).expect("loop header block").depth,
            1
        );
        // The chain's arms still route around each other.
        let else_if_head = graph.block_at(5).expect("else-if head at line 5");
        assert_eq!(
            edge(&graph, chain_head, else_if_head),
            Some(EdgeKind::BranchNotTaken)
        );
    }

    #[test]
    fn loop_nested_inside_a_loop_reads_at_real_depth() {
        let graph = cfg("\
for (i = 0; i < 3; i = i + 1) {
    while (x) {
        f();
    }
}");
        // Outer for at depth 0, inner while at depth 1: the inner loop
        // nests under the outer, and each keeps its own back edge.
        assert_eq!(graph.loops().len(), 2);
        assert_eq!(graph.loops()[0].kind, LoopKind::For);
        assert_eq!(graph.loops()[0].depth, 0);
        assert_eq!(graph.loops()[1].kind, LoopKind::While);
        assert_eq!(graph.loops()[1].depth, 1);
        // 0: for head, 1: while head, 2: f body + while close, 3: for close.
        let inner_header = graph.loops()[1].header;
        let outer_header = graph.loops()[0].header;
        assert_eq!(
            edge(&graph, inner_header, inner_header + 1),
            Some(EdgeKind::BranchTaken)
        );
        assert_eq!(
            edge(&graph, inner_header + 1, inner_header),
            Some(EdgeKind::BackEdge)
        );
        assert_eq!(
            edge(&graph, outer_header + 3, outer_header),
            Some(EdgeKind::BackEdge)
        );
        assert_eq!(graph.back_edges().count(), 2);
    }

    #[test]
    fn case_labels_split_the_switch_body_into_blocks() {
        let graph = cfg("\
switch (x) {
    case 1:
        f();
        break;
    case 2:
        g();
        break;
}");
        // The switch head line, then one block per case arm: case labels
        // cut blocks like any other label. The switch's own dispatch and
        // `break` edges are not modelled — the chain detector reads
        // switches textually, and the follow-up tickets only need the
        // loops and branches around them.
        assert_eq!(spans(&graph), vec![(0, 1), (1, 4), (4, 8)]);
        assert_eq!(edge(&graph, 0, 1), Some(EdgeKind::FallThrough));
        assert_eq!(edge(&graph, 1, 2), Some(EdgeKind::FallThrough));
        assert!(graph.loops().is_empty());
    }

    #[test]
    fn inline_else_brace_style_splits_like_ghidras() {
        let graph = cfg("\
if (x) {
    a();
} else {
    b();
}
c();");
        // 0: if head, 1: then body, 2: else body, 3: join.
        assert_eq!(edge(&graph, 0, 1), Some(EdgeKind::BranchTaken));
        assert_eq!(edge(&graph, 0, 2), Some(EdgeKind::BranchNotTaken));
        assert_eq!(edge(&graph, 1, 2), None);
        assert_eq!(edge(&graph, 1, 3), Some(EdgeKind::FallThrough));
        assert_eq!(edge(&graph, 2, 3), Some(EdgeKind::FallThrough));
    }

    #[test]
    fn nested_if_else_does_not_steal_the_outer_elses_join() {
        let graph = cfg("\
if (a) {
    if (b) {
        x();
    }
}
else {
    y();
}");
        // The inner if's not-taken lands on the block closing the outer
        // body, not inside the outer else.
        let inner_head = graph.block_at(1).expect("inner if head at line 1");
        let inner_body = graph.block_at(2).expect("inner body at line 2");
        let outer_else = graph.block_at(6).expect("outer else body at line 6");
        assert_ne!(
            graph
                .edges()
                .iter()
                .find(|e| e.from == inner_head && e.kind == EdgeKind::BranchNotTaken)
                .map(|e| e.to),
            Some(outer_else)
        );
        // The inner body falls out, not into the outer else.
        assert_eq!(edge(&graph, inner_body, outer_else), None);
    }

    #[test]
    fn block_at_maps_every_body_line_to_its_block() {
        let graph = cfg("\
a();
if (x) {
    b();
}
return;");
        assert_eq!(graph.block_at(0), graph.entry());
        assert_eq!(graph.block_at(1), graph.entry());
        assert_eq!(graph.block_at(2), Some(1));
        assert_eq!(graph.block_at(4), Some(2));
        assert_eq!(graph.block_at(99), None);
    }

    #[test]
    fn loop_body_spans_cover_the_lines_each_loop_wraps() {
        let graph = cfg("\
for (i = 0; i < 10; i = i + 1) {
    f();
}
while (x) {
    g();
    h();
}
do {
    k();
} while (x);
goto LAB_join;
LAB_join:
m();
goto LAB_join;
return;");
        // for body (f + close), while body (g, h + close), do body
        // (k + tail), and the goto loop from its label block through
        // the jumping block — each loop's body lines, in loop order.
        assert_eq!(
            graph.loop_body_spans(),
            vec![(1, 3), (4, 7), (8, 10), (11, 14)],
        );
    }

    #[test]
    fn a_truncated_loop_body_span_runs_to_the_end_of_the_body() {
        let graph = cfg("while (x) {\n    f();\n");
        // No closing brace means no back edge, but the visible body
        // lines still read as the loop's — a call inside them is
        // nested however truncated the decompile was.
        assert_eq!(
            graph.loop_body_spans(),
            vec![(1, 2)],
            "the span runs to the end of the truncated body",
        );
    }

    #[test]
    fn cfg_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Cfg>();
        assert_send_sync::<Block>();
        assert_send_sync::<Edge>();
        assert_send_sync::<Loop>();
    }
}
