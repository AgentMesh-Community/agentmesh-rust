//! Refusing a revoked sender (SPEC §5.3): "Receivers MUST refuse a message
//! signed by a revoked agent key."
//!
//! An envelope signature proves which key signed it, not that the key is still
//! its owner's. When an owner reports a key leaked, the registry marks it
//! revoked, and from then on it answers a `get` for that key with
//! `UNAUTHORIZED`, `details.reason: agent_key_revoked`. This asks that
//! question about each sender before its message is handled, with a short
//! memo. It is the Rust port of the TypeScript SDK's `revoked-senders.ts`.
//!
//! FAIL SAFE, in both directions:
//!
//! - a check that cannot answer (registry down, slow, no responders) does not
//!   block anyone: a known-good contact keeps working through a registry
//!   outage;
//! - a key already seen revoked stays refused for the life of the process,
//!   whatever the registry says or fails to say later, because revocation is
//!   permanent.
//!
//! "Not revoked" answers are kept for [`RevokedSenders::OK_MS`], so a
//! revocation reaches a receiver that already knows the sender within that.
//! Failed lookups are kept for [`RevokedSenders::FAILED_MS`] so an outage does
//! not add a timeout to every message. A paused sender (the kill switch,
//! §4.12) is remembered for `OK_MS` only, because a pause is lifted.
//!
//! Concurrent checks for one key share one lookup.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::{BoxFuture, FutureExt, Shared};

/// What one registry lookup said about a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationAnswer {
    /// The registry answered `UNAUTHORIZED` / `agent_key_revoked`.
    Revoked { revoked_at: Option<String>, replaced_by: Option<String> },
    /// The registry answered, and the key is not revoked. `paused` is the
    /// kill switch: the agent's manifest says `status: "paused"`.
    NotRevoked { paused: bool, since: Option<String> },
    /// No verified answer: an error, a timeout, no responders.
    Unknown,
}

/// Why a sender is refused: its key is revoked, or (with `paused`) the agent
/// is paused by the kill switch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevokedSender {
    pub revoked_at: Option<String>,
    pub replaced_by: Option<String>,
    /// The sender is PAUSED, not revoked. A pause is lifted, so it is
    /// remembered for [`RevokedSenders::OK_MS`] only.
    pub paused: bool,
    /// When the pause began (`status_since`), for a paused sender.
    pub since: Option<String>,
}

type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
type Pending = Shared<BoxFuture<'static, Option<RevokedSender>>>;

#[derive(Default)]
struct State {
    revoked: HashMap<String, RevokedSender>,
    not_revoked: HashMap<String, i64>,
    paused: HashMap<String, (Option<String>, i64)>,
    in_flight: HashMap<String, Pending>,
}

/// The memo the receive path consults before a request is handled.
#[derive(Clone)]
pub struct RevokedSenders {
    state: Arc<Mutex<State>>,
    now: Clock,
}

impl Default for RevokedSenders {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RevokedSenders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.state.lock().unwrap();
        f.debug_struct("RevokedSenders")
            .field("revoked", &s.revoked.len())
            .field("not_revoked", &s.not_revoked.len())
            .field("paused", &s.paused.len())
            .finish()
    }
}

impl RevokedSenders {
    /// How long a "not revoked" answer (and a pause) is kept, in ms.
    pub const OK_MS: i64 = 60_000;
    /// How long a lookup that could not answer is kept, in ms.
    pub const FAILED_MS: i64 = 15_000;
    /// How long one lookup may take before it counts as no answer.
    pub const LOOKUP_TIMEOUT: Duration = Duration::from_millis(2_000);
    /// The most entries a short-lived map holds before it is cleared.
    const MAX: usize = 5_000;

    /// A memo on the wall clock.
    pub fn new() -> Self {
        Self::with_clock(Arc::new(crate::inbound::now_ms))
    }

    /// A memo on a caller's clock (ms since the epoch), for tests.
    pub fn with_clock(now: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        RevokedSenders { state: Arc::new(Mutex::new(State::default())), now }
    }

    /// The refusal for `key`, or `None` when it is not known to be revoked or
    /// paused. `lookup` asks the registry; it runs only when the memo has no
    /// current answer and no lookup for `key` is already in flight, and it is
    /// cut off after [`LOOKUP_TIMEOUT`](Self::LOOKUP_TIMEOUT).
    pub async fn check<F, Fut>(&self, key: &str, lookup: F) -> Option<RevokedSender>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = RevocationAnswer> + Send + 'static,
    {
        let pending = {
            let mut s = self.state.lock().unwrap();
            if let Some(known) = s.revoked.get(key) {
                return Some(known.clone());
            }
            let now = (self.now)();
            if let Some((since, until)) = s.paused.get(key) {
                if *until > now {
                    return Some(RevokedSender { paused: true, since: since.clone(), ..Default::default() });
                }
            }
            if let Some(until) = s.not_revoked.get(key) {
                if *until > now {
                    return None;
                }
            }
            if let Some(p) = s.in_flight.get(key) {
                p.clone()
            } else {
                let p = self.ask(key.to_string(), lookup(key.to_string())).boxed().shared();
                s.in_flight.insert(key.to_string(), p.clone());
                p
            }
        };
        pending.await
    }

    /// Record a revocation learned some other way (an answer to a request, a
    /// refusal the host saw).
    pub fn remember(&self, key: &str, r: RevokedSender) {
        let mut s = self.state.lock().unwrap();
        s.revoked.insert(key.to_string(), r);
        s.not_revoked.remove(key);
    }

    fn ask(
        &self,
        key: String,
        lookup: impl Future<Output = RevocationAnswer> + Send + 'static,
    ) -> impl Future<Output = Option<RevokedSender>> + Send + 'static {
        let state = self.state.clone();
        let now = self.now.clone();
        async move {
            let answer = tokio::time::timeout(Self::LOOKUP_TIMEOUT, lookup)
                .await
                .unwrap_or(RevocationAnswer::Unknown);
            let mut s = state.lock().unwrap();
            s.in_flight.remove(&key);
            match answer {
                RevocationAnswer::Revoked { revoked_at, replaced_by } => {
                    let r = RevokedSender { revoked_at, replaced_by, ..Default::default() };
                    s.revoked.insert(key.clone(), r.clone());
                    s.not_revoked.remove(&key);
                    Some(r)
                }
                RevocationAnswer::NotRevoked { paused: true, since } => {
                    if s.paused.len() > Self::MAX {
                        s.paused.clear();
                    }
                    s.paused.insert(key.clone(), (since.clone(), now() + Self::OK_MS));
                    s.not_revoked.remove(&key);
                    Some(RevokedSender { paused: true, since, ..Default::default() })
                }
                other => {
                    s.paused.remove(&key);
                    if s.not_revoked.len() > Self::MAX {
                        s.not_revoked.clear();
                    }
                    let ttl = if other == RevocationAnswer::Unknown { Self::FAILED_MS } else { Self::OK_MS };
                    s.not_revoked.insert(key, now() + ttl);
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

    fn clock() -> (Arc<AtomicI64>, Arc<dyn Fn() -> i64 + Send + Sync>) {
        let t = Arc::new(AtomicI64::new(0));
        let c = t.clone();
        (t, Arc::new(move || c.load(Ordering::SeqCst)))
    }

    #[tokio::test]
    async fn re_asks_about_a_good_key_once_the_short_memo_runs_out() {
        let (t, now) = clock();
        let revoked = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let r = RevokedSenders::with_clock(now);
        let ask = || {
            let revoked = revoked.clone();
            let calls = calls.clone();
            move |_k: String| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if revoked.load(Ordering::SeqCst) {
                    RevocationAnswer::Revoked { revoked_at: None, replaced_by: None }
                } else {
                    RevocationAnswer::NotRevoked { paused: false, since: None }
                }
            }
        };
        assert_eq!(r.check("UK", ask()).await, None);
        revoked.store(true, Ordering::SeqCst);
        assert_eq!(r.check("UK", ask()).await, None);
        t.fetch_add(RevokedSenders::OK_MS + 1, Ordering::SeqCst);
        assert!(r.check("UK", ask()).await.is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn refuses_a_paused_sender_and_lets_it_back_in_after_the_resume() {
        let (t, now) = clock();
        let paused = Arc::new(AtomicBool::new(true));
        let r = RevokedSenders::with_clock(now);
        let ask = || {
            let paused = paused.clone();
            move |_k: String| async move {
                if paused.load(Ordering::SeqCst) {
                    RevocationAnswer::NotRevoked {
                        paused: true,
                        since: Some("2026-09-27T10:00:00.000Z".into()),
                    }
                } else {
                    RevocationAnswer::NotRevoked { paused: false, since: None }
                }
            }
        };
        assert_eq!(
            r.check("UP", ask()).await,
            Some(RevokedSender {
                paused: true,
                since: Some("2026-09-27T10:00:00.000Z".into()),
                ..Default::default()
            })
        );
        paused.store(false, Ordering::SeqCst);
        // Still remembered as paused inside the memo, then asked again.
        assert!(r.check("UP", ask()).await.is_some_and(|s| s.paused));
        t.fetch_add(RevokedSenders::OK_MS + 1, Ordering::SeqCst);
        assert_eq!(r.check("UP", ask()).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn treats_a_lookup_that_never_answers_as_unknown_after_its_timeout() {
        let r = RevokedSenders::new();
        let out = r.check("UK", |_k| futures::future::pending::<RevocationAnswer>()).await;
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn keeps_a_revocation_for_the_life_of_the_process() {
        let (t, now) = clock();
        let r = RevokedSenders::with_clock(now);
        let got = r
            .check("UB", |_k| async {
                RevocationAnswer::Revoked {
                    revoked_at: Some("2026-09-27T00:00:00.000Z".into()),
                    replaced_by: Some("UNEWKEY".into()),
                }
            })
            .await
            .expect("revoked");
        assert_eq!(got.replaced_by.as_deref(), Some("UNEWKEY"));
        t.fetch_add(RevokedSenders::OK_MS * 100, Ordering::SeqCst);
        let again = r.check("UB", |_k| async { RevocationAnswer::Unknown }).await;
        assert_eq!(again, Some(got));
    }

    #[tokio::test]
    async fn a_failed_lookup_lets_the_sender_through_and_is_kept_briefly() {
        let (t, now) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let r = RevokedSenders::with_clock(now);
        let ask = || {
            let calls = calls.clone();
            move |_k: String| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                RevocationAnswer::Unknown
            }
        };
        assert_eq!(r.check("UD", ask()).await, None);
        assert_eq!(r.check("UD", ask()).await, None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        t.fetch_add(RevokedSenders::FAILED_MS + 1, Ordering::SeqCst);
        assert_eq!(r.check("UD", ask()).await, None);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_checks_for_one_key_share_one_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let r = RevokedSenders::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let rx = Arc::new(Mutex::new(Some(rx)));
        let ask = || {
            let calls = calls.clone();
            let rx = rx.clone();
            move |_k: String| {
                calls.fetch_add(1, Ordering::SeqCst);
                let rx = rx.lock().unwrap().take();
                async move {
                    if let Some(rx) = rx {
                        let _ = rx.await;
                    }
                    RevocationAnswer::Revoked { revoked_at: None, replaced_by: None }
                }
            }
        };
        let a = r.check("US", ask());
        let b = r.check("US", ask());
        let release = async {
            tokio::task::yield_now().await;
            let _ = tx.send(());
        };
        let (a, b, _) = tokio::join!(a, b, release);
        assert!(a.is_some() && b.is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
