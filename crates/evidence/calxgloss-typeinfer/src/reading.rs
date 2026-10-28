//! The detector-internal accumulator shared by the detectors.
//!
//! Every detector walks a decompiled body and collects one [`Reading`]
//! per parameter usage it finds. It then resolves those readings down to
//! one per parameter and assembles the [`InferredParamType`] records.
//! This accumulator is internal to the crate: the persisted contract is
//! the record, not the accumulator. The shape lives here once instead of
//! inside each detector.

use crate::types::{InferenceMethod, InferenceScope, InferredParamType};

/// One detector's reading of one parameter, before record assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reading {
    /// The parameter the reading is about.
    pub(crate) param_index: usize,
    /// The evidence family behind the reading. A detector that reads one
    /// parameter through several families keys its per-family keeping on
    /// this field.
    pub(crate) method: InferenceMethod,
    /// The narrowed type text the evidence suggests.
    pub(crate) inferred_type: &'static str,
    /// How strongly the evidence supports the reading, on the detector's
    /// plain `u8` scale.
    pub(crate) confidence: u8,
    /// The source line the evidence comes from.
    pub(crate) evidence: String,
}

impl Reading {
    /// Resolve readings down to one per parameter: the reading with the
    /// highest confidence score wins and the rest are dropped. A tie
    /// keeps the reading the body showed first.
    pub(crate) fn resolve(readings: Vec<Self>) -> Vec<Self> {
        let mut winners: Vec<Self> = Vec::new();
        for reading in readings {
            match winners
                .iter_mut()
                .find(|w| w.param_index == reading.param_index)
            {
                Some(winner) if reading.confidence > winner.confidence => *winner = reading,
                Some(_) => {}
                None => winners.push(reading),
            }
        }
        winners
    }

    /// Assemble the reading into its record: the type text becomes owned,
    /// the score crosses onto the shared 0–100 evidence-confidence scale,
    /// and `scope` says how far the reading reaches beyond the function
    /// it was made in.
    pub(crate) fn into_record(
        self,
        function: String,
        param_name: String,
        scope: InferenceScope,
    ) -> InferredParamType {
        InferredParamType {
            function,
            param_index: self.param_index,
            param_name: Some(param_name),
            inferred_type: self.inferred_type.to_string(),
            method: self.method,
            scope,
            confidence: self.confidence.into(),
            evidence: self.evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InferenceMethod::*;

    fn reading(param_index: usize, method: InferenceMethod, confidence: u8) -> Reading {
        Reading {
            param_index,
            method,
            inferred_type: "char *",
            confidence,
            evidence: "strlen(param_1);".to_string(),
        }
    }

    #[test]
    fn the_highest_confidence_reading_wins() {
        let winners = Reading::resolve(vec![
            reading(0, StringFunction, 70),
            reading(0, PointerArithmetic, 65),
            reading(0, KnownSignature, 75),
        ]);
        assert_eq!(winners, vec![reading(0, KnownSignature, 75)]);
    }

    #[test]
    fn a_tie_keeps_the_first_reading() {
        let winners = Reading::resolve(vec![
            reading(0, StringFunction, 70),
            reading(0, KnownSignature, 70),
        ]);
        assert_eq!(winners, vec![reading(0, StringFunction, 70)]);
    }

    #[test]
    fn different_parameters_each_keep_their_own() {
        let winners = Reading::resolve(vec![
            reading(0, StringFunction, 70),
            reading(1, PointerArithmetic, 65),
        ]);
        assert_eq!(winners.len(), 2);
        assert_eq!(winners[0].param_index, 0);
        assert_eq!(winners[1].param_index, 1);
    }
}
