//! What a statement rested on (SPEC.md §5.6).
//!
//! A signature answers two questions and not a third. It says who made a
//! statement, and it says the words have not changed. It says nothing about
//! whether the things underneath are still what they were, so a deliverable
//! keeps verifying after its inputs have moved and a receipt keeps verifying
//! after the schedule it was priced against has been rewritten. Both are clean
//! signatures over statements that stopped being true.
//!
//! `rests_on` closes that by declaring the bytes a statement was computed
//! from. There is no second signature and no combined root to compute: the
//! member lives inside the statement, so the envelope signature (§4.5, §5.3)
//! already covers it. The declaration IS the mechanism.
//!
//! THE POINT OF THIS MODULE IS THE FOUR-WAY VERDICT, not the validation. A
//! reader needs to tell apart "I looked and it moved", "I could not look", and
//! "nothing was declared", because collapsing any of them into a boolean ends
//! with somebody either relying on a stale statement or accusing an honest
//! one. [`Freshness::Stale`] in particular is NOT a signature failure and NOT
//! evidence of bad faith: the statement was true when made and its signature
//! is still good. What it means is that it is no longer a safe basis for a
//! decision, which is a matter for whoever is deciding, so nothing here
//! returns an error for it.
//!
//! AGREEMENTS ARE EXCLUDED, which is why `countersigned` is a parameter rather
//! than something a caller is trusted to remember. A document two parties
//! signed means what it meant when they signed it; an undertaking that
//! silently voided when one side touched a file would be one neither party
//! could rely on, and either could escape by touching it. Pass `true` and the
//! answer is [`Freshness::NotApplicable`] without a single byte resolved.
//!
//! Mirrors `sdk-typescript/src/rests-on.ts`; shapes and verdicts pinned by
//! `conformance/rests-on.json`.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, MeshError, Result};

/// A verifier may have to fetch every entry, so an unbounded list is a way to
/// spend a stranger's bandwidth. Far above any honest statement.
pub const MAX_RESTS_ON: usize = 64;

/// `sha256:<64 lowercase hex>`, the §7.5.1 spelling.
///
/// Case-sensitive on purpose: the declared string sits inside the signed
/// bytes, so normalising before comparing would make two different signed
/// statements equal. Hand-rolled rather than a regex because the crate carries
/// no regex dependency and this is cheaper than acquiring one.
pub fn is_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One thing a statement rested on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestsOnEntry {
    /// REQUIRED. `sha256:<64 lowercase hex>` over the bytes depended on.
    pub digest: String,
    /// What makes the entry CHECKABLE: a verifier resolves it to get the
    /// bytes. Absent is legal and weaker, the same trade §7.5.1 makes the
    /// other way round for a ref with no digest.
    ///
    /// `ref` is a Rust keyword, so the field is `ref_` and serde carries the
    /// wire name. The rename is at the boundary rather than in the data: the
    /// wire spelling is the specification's and must not drift to suit one
    /// language's grammar.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub ref_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What this input was to the statement ("input", "rate-schedule"). Open
    /// vocabulary, for the reader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// The verdict.
///
/// [`Freshness::Undeclared`] is not a milder `Fresh` and [`Freshness::Unchecked`]
/// is not a milder `Stale`. They are different facts and callers are expected
/// to branch on all four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Every declared entry was observed and every digest matched.
    Fresh,
    /// At least one entry was observed with a DIFFERENT digest. The statement
    /// was true when made and is no longer a safe basis for a decision.
    Stale,
    /// Nothing was seen to change, and at least one entry could not be
    /// obtained. Absent evidence is not agreement.
    Unchecked,
    /// The statement declared nothing about what it rested on. Reads as
    /// unverifiable, never as "it rested on nothing" and never as fresh.
    Undeclared,
    /// A countersigned agreement, which §5.6 excludes from this rule entirely.
    NotApplicable,
}

/// One entry whose bytes have moved, with what the verifier saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub entry: RestsOnEntry,
    pub observed: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessResult {
    pub state: Freshness,
    /// Non-empty exactly when the state is [`Freshness::Stale`].
    pub changed: Vec<Changed>,
    /// Entries the verifier could not obtain, or obtained unintelligibly.
    pub unreachable: Vec<RestsOnEntry>,
}

impl FreshnessResult {
    fn bare(state: Freshness) -> Self {
        Self { state, changed: Vec::new(), unreachable: Vec::new() }
    }

    /// One line a person can read, for a log or a panel. Names which input
    /// moved, because "stale" without the name sends somebody looking through
    /// all of them.
    pub fn describe(&self) -> String {
        match self.state {
            Freshness::Fresh => "every input it rested on is unchanged".to_string(),
            Freshness::Stale => {
                let names: Vec<String> = self
                    .changed
                    .iter()
                    .map(|c| {
                        c.entry
                            .name
                            .clone()
                            .or_else(|| c.entry.ref_.clone())
                            .unwrap_or_else(|| c.entry.digest.chars().take(16).collect())
                    })
                    .collect();
                format!("no longer current: {} changed since this was signed", names.join(", "))
            }
            Freshness::Unchecked => format!(
                "signature is good; {} of the inputs it rested on could not be read, so freshness is unknown",
                self.unreachable.len()
            ),
            Freshness::Undeclared => {
                "says nothing about what it rested on, so freshness cannot be checked".to_string()
            }
            Freshness::NotApplicable => {
                "a countersigned agreement, which does not go stale when its inputs change".to_string()
            }
        }
    }
}

/// Validate a `rests_on` list, naming the single fault.
///
/// Returning an error is right here and wrong for the verdict: a malformed
/// list is the producer's own programming error, caught at the site that
/// builds it, while a stale verdict is a fact about the world that the caller
/// has to weigh.
pub fn validate_rests_on(entries: &[RestsOnEntry]) -> Result<()> {
    if entries.is_empty() {
        // Omitting the member already means "declares nothing". Two spellings
        // of one state is how two implementations come to disagree about which
        // is which, so the empty list is refused rather than quietly folded in.
        return Err(MeshError::code(
            ErrorCode::InputInvalid,
            "rests_on must not be empty (§5.6): omit the member instead, which is what declaring nothing means",
        ));
    }
    if entries.len() > MAX_RESTS_ON {
        return Err(MeshError::code(
            ErrorCode::InputInvalid,
            format!("rests_on carries at most {MAX_RESTS_ON} entries (§5.6), got {}", entries.len()),
        ));
    }
    let mut seen_refs: Vec<&str> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if !is_digest(&e.digest) {
            return Err(MeshError::code(
                ErrorCode::InputInvalid,
                format!("rests_on[{i}].digest must be sha256:<64 lowercase hex> (§5.6)"),
            ));
        }
        if let Some(r) = &e.ref_ {
            if r.is_empty() {
                return Err(MeshError::code(
                    ErrorCode::InputInvalid,
                    format!("rests_on[{i}].ref must be a non-empty opaque URI when present (§7.5.1)"),
                ));
            }
            if seen_refs.contains(&r.as_str()) {
                // One reference cannot have rested on two different sets of
                // bytes. The statement contradicts itself and no verdict over
                // it would mean anything.
                return Err(MeshError::code(
                    ErrorCode::InputInvalid,
                    format!("rests_on names {r} twice with different digests (§5.6)"),
                ));
            }
            seen_refs.push(r);
        }
    }
    Ok(())
}

/// Is what this statement rested on still what it rested on?
///
/// `declared` is the statement's own `rests_on`, or `None` when it has none.
/// `observe` answers with the digest of each input as it is today, or `None`
/// when the verifier cannot obtain it. An entry with no `ref` is never
/// observable and is always counted unreachable: there is nothing to resolve.
///
/// Never fails on the answer. A verdict is an input to somebody's decision,
/// and a function that errored on `stale` would be making that decision for
/// them.
pub fn check_freshness<F>(
    declared: Option<&[RestsOnEntry]>,
    mut observe: F,
    countersigned: bool,
) -> FreshnessResult
where
    F: FnMut(&RestsOnEntry) -> Option<String>,
{
    // Checked FIRST, and before anything is resolved. §5.6 excludes agreements
    // from this rule, so a verifier that fetched the inputs anyway would be
    // spending requests to compute a verdict it must then discard.
    if countersigned {
        return FreshnessResult::bare(Freshness::NotApplicable);
    }
    let entries = match declared {
        Some(e) if !e.is_empty() => e,
        _ => return FreshnessResult::bare(Freshness::Undeclared),
    };

    let mut changed = Vec::new();
    let mut unreachable = Vec::new();
    for entry in entries {
        if entry.ref_.is_none() {
            unreachable.push(entry.clone());
            continue;
        }
        match observe(entry) {
            // Unreachable, never stale. An unparseable observation is this
            // verifier's fault or its store's, and calling the statement stale
            // on the strength of it would accuse the producer of something the
            // evidence does not show.
            Some(seen) if is_digest(&seen) => {
                if seen != entry.digest {
                    changed.push(Changed { entry: entry.clone(), observed: seen });
                }
            }
            _ => unreachable.push(entry.clone()),
        }
    }

    // Stale beats unchecked. One input positively known to have moved is a
    // fact, and it is not weakened by a second input this verifier happened
    // not to reach — an implementation that reported `Unchecked` here would
    // let a producer hide a known change behind an unreachable neighbour.
    let state = if !changed.is_empty() {
        Freshness::Stale
    } else if !unreachable.is_empty() {
        Freshness::Unchecked
    } else {
        Freshness::Fresh
    };
    FreshnessResult { state, changed, unreachable }
}
