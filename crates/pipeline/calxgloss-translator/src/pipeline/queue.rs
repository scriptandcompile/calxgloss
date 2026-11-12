//! The run's queue has one shape for both queue sources: an ordered
//! list of planned units, each carrying its name and its planned
//! disposition — translate, Stub, or skip (issue #488, part of #486).
//! Each entry point builds its queue through an adapter, ahead of the
//! batch's opening steps. The explicit-list adapter plans every scoped
//! function to translate. The call-graph adapter orders the graph,
//! plans entry-point roots as Stub, and plans runtime-library
//! functions as skip. The batch pass reads each unit's disposition and
//! never asks which adapter built the queue.

use super::*;

/// What the batch plans to do with one queued unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PlannedDisposition {
    /// Translate the unit on the same retry path the batches use today.
    Translate,
    /// Record a Stub — an entry-point root holds no logic to translate.
    Stub,
    /// Record the unit as skipped — a runtime-library function is never
    /// attempted.
    Skip,
}

/// One entry in the run's queue: the unit's name and its planned
/// disposition.
pub(super) struct PlannedUnit {
    pub(super) name: String,
    pub(super) disposition: PlannedDisposition,
}

impl TranslationPipeline {
    /// The explicit-list adapter (issue #488): the run's queue for a
    /// caller-supplied function list.
    ///
    /// Operator scope applies first: skipped functions never enter the
    /// queue, and priority functions move to the front (W2.5). Every
    /// scoped function then enters planned to translate.
    pub(super) fn explicit_queue(&self, binary: &str, functions: &[String]) -> Vec<PlannedUnit> {
        let scoped = self.apply_function_scope(binary, functions.to_vec(), |f| f.as_str());
        scoped
            .into_iter()
            .map(|name| PlannedUnit {
                name,
                disposition: PlannedDisposition::Translate,
            })
            .collect()
    }

    /// The call-graph adapter (issue #488): the run's queue for a call
    /// graph.
    ///
    /// The order comes from the call-graph orderer, extended by the
    /// saved shared-globals index when that document exists for the
    /// binary (issue #256). The adapter reads the artifact and never
    /// runs a scan. The queue stands before this batch's scan phase, so
    /// the order reads the index as it was saved before the batch: a
    /// binary's first-ever call-graph batch orders without
    /// state-sharing edges, and later batches pick the document up.
    ///
    /// Operator scope applies as in the explicit-list adapter (W2.5).
    /// Each unit then gets its planned disposition: an entry-point root
    /// is planned Stub, a runtime-library function planned skip, every
    /// other unit planned to translate.
    pub(super) fn callgraph_queue(
        &self,
        graph: &calxgloss_callgraph::CallGraph,
    ) -> Result<Vec<PlannedUnit>> {
        let orderer = calxgloss_callgraph::TranslationOrderer::new()
            .with_state_sharing(self.state_sharing_edges(&graph.binary));
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;
        let plan: Vec<_> = plan.into_iter().collect();
        let scoped = self.apply_function_scope(&graph.binary, plan, |p| p.name.as_str());
        Ok(scoped
            .into_iter()
            .map(|plan_func| PlannedUnit {
                name: plan_func.name,
                // The orderer gives a Skip node Root priority, so the
                // category check comes first — exactly the precedence
                // the nested check in the old batch body had.
                disposition: if matches!(plan_func.category, NodeCategory::Skip) {
                    PlannedDisposition::Skip
                } else if matches!(
                    plan_func.priority,
                    calxgloss_callgraph::TranslationPriority::Root
                ) {
                    PlannedDisposition::Stub
                } else {
                    PlannedDisposition::Translate
                },
            })
            .collect())
    }
}
