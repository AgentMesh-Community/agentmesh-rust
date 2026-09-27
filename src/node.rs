//! Mesh **Node** host (§2, §4): one host, one transport connection, one
//! credential — hosting N agents, each with its own keypair, vouched for by
//! this node (§4.4).
//!
//! This is the 0.2 model: agents do NOT hold transport credentials or open
//! connections. The node connects once, then `add_agent()` creates cheap
//! keypair-only agent identities that all share the connection (the
//! `async_nats::Client` handle is a cheap clone over one connection). One node
//! heartbeat covers every hosted agent (§9.6).
//!
//! For the degenerate single-agent case (node key = agent key), the standalone
//! `AgentMesh::connect` remains the shortcut.

use nkeys::KeyPair;
use serde_json::json;

use crate::client::AgentMesh;
use crate::codec;
use crate::credential::{
    CredentialRenewal, CredentialRenewer, CredentialRenewerOptions, CredentialStatus, RenewalAgent,
    RenewalRoster,
};
use crate::envelope::{Envelope, PrimitiveType};
use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::{keypair_from_seed, sign_envelope};
use crate::manifest::{Availability, NodeDeclaredProfile};
use crate::subjects;

/// Options for connecting a node to the mesh.
#[derive(Default)]
pub struct NodeConnectOptions {
    /// Node NKey seed. The node's public key is the node ID. If absent, a
    /// fresh node key is generated (dev/self-contained use).
    pub node_seed: Option<String>,
    /// JWT for an authenticated connection. The NODE holds the transport
    /// credential (§4.2/§18.2): the server nonce is signed with the node key.
    /// Without a JWT the connection is anonymous (dev servers only).
    pub jwt: Option<String>,
    /// The node's self-declared profile (§9.7), attached to every hosted
    /// agent's registration by default.
    pub profile: Option<NodeDeclaredProfile>,
    /// How often each hosted agent re-runs its §16.4 mailbox drain. Node-level
    /// because the cadence is a property of the host, and every agent on this
    /// connection shares one reconnect stream. Default 60s
    /// ([`DEFAULT_MAILBOX_DRAIN_INTERVAL`](crate::DEFAULT_MAILBOX_DRAIN_INTERVAL)).
    pub mailbox_drain_interval: Option<std::time::Duration>,
    /// Lifetime (ms) of the vouches this node signs (§4.4), and the basis of
    /// the renewal cadence: the node re-vouches each hosted agent at two
    /// thirds of this. Default
    /// [`DEFAULT_VOUCH_TTL_MS`](crate::vouch::DEFAULT_VOUCH_TTL_MS) (30 days)
    /// for registrations that declare an `availability_class`,
    /// [`EPHEMERAL_VOUCH_TTL_MS`](crate::vouch::EPHEMERAL_VOUCH_TTL_MS) (72h)
    /// otherwise (§9.2). An explicit value always wins over that split.
    pub vouch_ttl_ms: Option<i64>,
    /// Keep the NODE credential alive (§4.8).
    ///
    /// The node's credential is a lease with a finite expiry, and this is the
    /// thing that renews it — at two thirds of its own lifetime, the same
    /// schedule the vouches this node signs already use, through
    /// `POST {api_base}/v1/node-credential`.
    ///
    /// The roster is read at each renewal from the agents currently hosted, so
    /// an agent added later is covered by the next credential without any
    /// bookkeeping here. Nothing reconnects: the fresh credential matters at the
    /// next connect, and `on_renewed` is where a host writes it down.
    ///
    /// Unset means the node does nothing about its credential, which is right
    /// for a dev node with a generated key and wrong for anything durable.
    /// Ignored when no `jwt` and no `node_seed` are set — there is then no
    /// credential, and no key to prove possession of.
    pub credential_renewal: Option<CredentialRenewal>,
}

/// Options for [`MeshNode::add_agent_with`].
#[derive(Default)]
pub struct AddAgentOptions {
    /// The agent's Ed25519 signing seed; its public key is the agent ID. `None`
    /// mints a fresh one (the agent is then unreachable across restarts).
    pub agent_seed: Option<String>,
    /// The agent's X25519 encryption secret (base64url), as produced by
    /// [`create_encryption_identity`](crate::create_encryption_identity).
    /// Per-agent — see [`MeshNode::add_agent_with`].
    pub encryption_seed: Option<String>,
}

/// A mesh node hosting N agents over one shared connection.
pub struct MeshNode {
    client: async_nats::Client,
    node_seed: String,
    node_id: String,
    /// The mesh URL this node dialled, handed to each hosted agent.
    ///
    /// Needed for ONE thing: the `acl` grade's room-scoped second connection
    /// (EXT-5 §7.2). Room traffic at that grade rides `mesh.aclroom.<id>.>`,
    /// which the broker permits only on the short-lived credential the rooms
    /// service mints per member per room — so it cannot ride the node's own
    /// connection, whatever that connection is allowed to do. A hosted agent
    /// used to carry no URL at all and was refused with "acl rooms require a
    /// standalone agent", which locked every Gateway-hosted agent out of the one
    /// grade whose membership is actually enforced.
    ///
    /// Empty for [`MeshNode::with_client`]: an embedder-supplied connection
    /// carries no URL to redial, so that path keeps the old refusal.
    url: String,
    profile: Option<NodeDeclaredProfile>,
    /// The reconnect channel this node's connection feeds (§16.4). Shared with
    /// every hosted agent, so one reconnect re-drains every mailbox on the host.
    drain_trigger: crate::client::DrainTrigger,
    /// The §16.4 re-drain cadence handed to each hosted agent.
    mailbox_drain_interval: Option<std::time::Duration>,
    /// Availability advertised in the heartbeat (§9.6). Node-level: covers every
    /// hosted agent. Defaults to Online; the host can override it (e.g. Busy).
    availability: std::sync::Mutex<Availability>,
    heartbeat_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Every agent this node created, for the §4.4 renewal loop. Behind an
    /// `Arc` because the loop task holds the LIST, never the node — so a
    /// dropped node cannot be kept alive by its own loop. Closed agents are
    /// pruned on each renewal pass.
    agents: std::sync::Arc<std::sync::Mutex<Vec<AgentMesh>>>,
    /// One renewal loop for every agent this node vouches for (§4.4) — hosted
    /// agents do not run their own. Started with the first `add_agent`,
    /// aborted on `close`.
    vouch_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Lifetime to mint each vouch with, and the renewal-loop cadence basis.
    vouch_ttl_ms: i64,
    /// Whether `vouch_ttl_ms` was set explicitly (hosted agents then inherit
    /// it, overriding the §9.2 declared-vs-ephemeral split).
    vouch_ttl_explicit: bool,
    /// The §4.8 credential lease loop, or `None` when the embedder configured no
    /// `credential_renewal`. One per node, because there is one credential.
    cred_renewer: Option<std::sync::Arc<CredentialRenewer>>,
}

impl MeshNode {
    /// Connect to the mesh as a node. The connection is authenticated with the
    /// NODE credential (jwt + node_seed); hosted agents share it.
    pub async fn connect(url: &str, opts: NodeConnectOptions) -> Result<MeshNode> {
        let node_kp = match &opts.node_seed {
            Some(s) => keypair_from_seed(s)?,
            None => KeyPair::new_user(),
        };
        let node_seed = node_kp.seed().map_err(|e| MeshError::Nkey(e.to_string()))?;
        let node_id = node_kp.public_key();
        // Retained for §4.8: the credential the renewer keeps alive is the one
        // this connection opened with, and `connect_client` consumes it.
        let jwt_in_hand = opts.jwt.clone();
        let (client, drain_trigger) = crate::client::connect_client(url, opts.jwt, &node_seed).await?;
        let agents = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // Armed before the node exists so the loop holds the agent LIST, never
        // the node — a dropped node is not kept alive by its own credential
        // loop, exactly as with the vouch loop below.
        let cred_renewer = match (opts.credential_renewal, jwt_in_hand) {
            (Some(cfg), Some(jwt)) => Some(start_credential_renewal(
                cfg,
                jwt,
                &node_seed,
                std::sync::Arc::clone(&agents),
            )),
            _ => None,
        };
        Ok(MeshNode { client, node_seed, node_id, url: url.to_string(), profile: Some(crate::manifest::with_detected_device(opts.profile)), drain_trigger, mailbox_drain_interval: opts.mailbox_drain_interval, availability: std::sync::Mutex::new(Availability::Online), heartbeat_task: std::sync::Mutex::new(None), agents, vouch_task: std::sync::Mutex::new(None), vouch_ttl_ms: opts.vouch_ttl_ms.unwrap_or(crate::vouch::DEFAULT_VOUCH_TTL_MS), vouch_ttl_explicit: opts.vouch_ttl_ms.is_some(), cred_renewer })
    }

    /// Construct a node over an existing connection (tests, embedders).
    ///
    /// Note what an embedder-supplied client cannot carry: async-nats reports
    /// reconnects through a callback installed at connect time, so a client this
    /// node did not open has no reconnect stream to share. Hosted agents therefore
    /// re-drain their §16.4 mailbox on the periodic pass only — correct, just less
    /// prompt after a gap.
    pub fn with_client(client: async_nats::Client, opts: NodeConnectOptions) -> Result<MeshNode> {
        let node_kp = match opts.node_seed {
            Some(s) => keypair_from_seed(&s)?,
            None => KeyPair::new_user(),
        };
        let node_seed = node_kp.seed().map_err(|e| MeshError::Nkey(e.to_string()))?;
        let node_id = node_kp.public_key();
        let (drain_trigger, _) = tokio::sync::broadcast::channel::<()>(1);
        let agents = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        // An embedder-supplied connection carries no JWT this node can see, so
        // §4.8 renewal needs one named explicitly — and the credential is still
        // worth keeping alive, since it is what the NEXT connect will use.
        let cred_renewer = match (opts.credential_renewal, opts.jwt) {
            (Some(cfg), Some(jwt)) => Some(start_credential_renewal(
                cfg,
                jwt,
                &node_seed,
                std::sync::Arc::clone(&agents),
            )),
            _ => None,
        };
        Ok(MeshNode { client, node_seed, node_id, url: String::new(), profile: Some(crate::manifest::with_detected_device(opts.profile)), drain_trigger, mailbox_drain_interval: opts.mailbox_drain_interval, availability: std::sync::Mutex::new(Availability::Online), heartbeat_task: std::sync::Mutex::new(None), agents, vouch_task: std::sync::Mutex::new(None), vouch_ttl_ms: opts.vouch_ttl_ms.unwrap_or(crate::vouch::DEFAULT_VOUCH_TTL_MS), vouch_ttl_explicit: opts.vouch_ttl_ms.is_some(), cred_renewer })
    }

    /// The node ID (the node key's public key).
    pub fn id(&self) -> &str {
        &self.node_id
    }

    /// The node's declared profile (§9.7), if any.
    pub fn profile(&self) -> Option<&NodeDeclaredProfile> {
        self.profile.as_ref()
    }

    /// Create an agent hosted by this node: its own keypair (public key = agent
    /// ID), sharing this node's connection, vouched by this node at register
    /// (§4.4). The node's declared profile attaches to its registration by
    /// default (§9.7).
    pub fn add_agent(&self, agent_seed: Option<String>) -> Result<AgentMesh> {
        self.add_agent_with(AddAgentOptions { agent_seed, ..Default::default() })
    }

    /// Create a hosted agent with options — today, the one thing
    /// [`add_agent`](Self::add_agent) cannot express: a per-agent X25519
    /// encryption identity.
    ///
    /// Give an agent an `encryption_seed` and its `register` declares the
    /// matching `encryption_key` (§4.3) bound to its id by a §8.3 key claim,
    /// which is what lets peers seal to it — EXT-7 pairwise payloads and the
    /// EXT-5 `sealed` room grade both. Without one the agent is reachable in
    /// cleartext only, and peers correctly decline to seal rather than
    /// encrypting to a key nobody published.
    ///
    /// The seed is **per agent**, never shared across agents on one node: the
    /// key claim binds it to a single agent id, and reusing one seed would
    /// publish claims that contradict each other. Mint one with
    /// [`create_encryption_identity`](crate::create_encryption_identity) and
    /// persist it beside the agent's signing seed.
    pub fn add_agent_with(&self, opts: AddAgentOptions) -> Result<AgentMesh> {
        let agent = AgentMesh::hosted_by(
            self.client.clone(),
            self.node_seed.clone(),
            self.node_id.clone(),
            self.url.clone(),
            opts.agent_seed,
            self.profile.clone(),
            self.drain_trigger.clone(),
            self.mailbox_drain_interval,
            opts.encryption_seed,
            // Hosted agents inherit the node's vouch TTL only when it was set
            // explicitly; otherwise each registration's §9.2 split applies.
            if self.vouch_ttl_explicit { Some(self.vouch_ttl_ms) } else { None },
        )?;
        // §4.4: the vouch a hosted agent registers with is signed by THIS
        // node's key, so its renewal is this node's job — one loop, N agents.
        self.agents.lock().unwrap().push(agent.clone());
        self.start_vouch_renewal();
        Ok(agent)
    }

    // ─── Vouch renewal (§4.4): one node, one loop, N re-vouched agents ──
    //
    // The vouch a hosted agent registers with is signed by THIS node's key and
    // expires like any other; the registry refuses an expired attestation
    // (§9.7) and its reaper reclaims a lapsed registration. A node that stays
    // up watches its agents drop out of discovery one by one unless it
    // re-vouches them. Each renewal is a plain re-registration: the node
    // supplies the vouch, the agent supplies its signature, exactly as at
    // first registration — and a hosted agent runs no loop of its own.

    /// Re-vouch every hosted agent whose vouch has reached its renewal
    /// deadline, judged against the wall clock. Returns how many were renewed.
    /// See [`renew_vouches_at`](Self::renew_vouches_at).
    pub async fn renew_vouches(&self) -> usize {
        self.renew_vouches_at(crate::inbound::now_ms()).await
    }

    /// Re-vouch every hosted agent whose vouch has reached its renewal
    /// deadline as of `now_ms` (ms epoch). An agent that never registered, or
    /// whose deadline is not yet due, is skipped; a failed renewal surfaces on
    /// that agent's own security-warning sink
    /// ([`AgentMesh::on_security_warning`](crate::AgentMesh::on_security_warning))
    /// and is retried on the next pass. Returns how many were renewed.
    pub async fn renew_vouches_at(&self, now_ms: i64) -> usize {
        renew_all(&self.agents, now_ms).await
    }

    /// Start the node's single renewal loop, once. The task holds the agent
    /// LIST, never the node, so a dropped node is not kept alive by its own
    /// loop; `close` aborts it so the timer never outlives the registrations
    /// it maintains.
    fn start_vouch_renewal(&self) {
        let mut task = self.vouch_task.lock().unwrap();
        if task.is_some() {
            return;
        }
        let agents = std::sync::Arc::clone(&self.agents);
        let interval = crate::vouch::vouch_check_interval(self.vouch_ttl_ms);
        *task = Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Each tick compares the wall clock against every agent's stored
            // deadline, so a suspended host renews on the first tick after
            // wake — late ticks must not burst-replay on top of that.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                renew_all(&agents, crate::inbound::now_ms()).await;
            }
        }));
    }

    /// Stop the node's renewal loop.
    fn stop_vouch_renewal(&self) {
        if let Some(handle) = self.vouch_task.lock().unwrap().take() {
            handle.abort();
        }
    }

    // ─── Credential renewal (§4.8): one node, one credential, one loop ──
    //
    // Renewal is HTTPS and not a mesh call for one reason: it stays available
    // exactly when the credential does not. A node that was switched off
    // through its whole renewal window comes back with a dead credential,
    // renews over HTTPS, and connects — no operator, no re-bootstrap, no lost
    // identity.

    /// When this node's credential expires, when it is next due for renewal,
    /// whether it has already lapsed, and why the last attempt failed (§4.8).
    ///
    /// All-`None`/`false` when no
    /// [`credential_renewal`](NodeConnectOptions::credential_renewal) was
    /// configured — "nothing here is watching", not a clean bill of health. An
    /// `expires_at` of `None` on a configured node means the credential carries
    /// no expiry at all, which is the pre-§4.8 shape.
    pub fn credential(&self) -> CredentialStatus {
        self.credential_at(crate::inbound::now_ms())
    }

    /// [`credential`](Self::credential) judged against `now_ms` (ms epoch) —
    /// only `expired` depends on it.
    pub fn credential_at(&self, now_ms: i64) -> CredentialStatus {
        match &self.cred_renewer {
            Some(renewer) => renewer.status(now_ms),
            None => crate::credential::unwatched_credential_status(),
        }
    }

    /// Renew the node credential now, regardless of schedule.
    ///
    /// Errors when no `credential_renewal` was configured, and when the mesh
    /// refuses — a refusal IS the revocation mechanism (§4.8), so treat it as a
    /// real answer rather than a transient fault.
    pub async fn renew_credential(&self) -> Result<()> {
        let Some(renewer) = self.cred_renewer.as_ref() else {
            return Err(MeshError::code(
                ErrorCode::Internal,
                "renew_credential(): this node was connected without credential_renewal",
            ));
        };
        renewer.renew().await.map(|_| ())
    }

    /// Renew the credential if its deadline has passed as of `now_ms`. Never
    /// errors; exposed so a supervisor can drive the check on its own clock.
    pub async fn renew_credential_if_due(&self, now_ms: i64) -> bool {
        match self.cred_renewer.as_ref() {
            Some(renewer) => renewer.renew_if_due(now_ms).await,
            None => false,
        }
    }

    /// Send a single node heartbeat (§9.6): one heartbeat covers all hosted
    /// agents. Signed by the node key, from the node ID.
    pub async fn send_heartbeat(&self) -> Result<()> {
        let node_kp = keypair_from_seed(&self.node_seed)?;
        let mut env = Envelope::new(PrimitiveType::Emit, &self.node_id);
        let availability = *self.availability.lock().unwrap();
        env.payload = Some(json!({ "node": self.node_id, "availability": availability }));
        sign_envelope(&mut env, &node_kp)?;
        let _ = self
            .client
            .publish(subjects::heartbeat(&self.node_id), codec::encode(&env)?.into())
            .await;
        Ok(())
    }

    /// Start the periodic node heartbeat (§9.6). One heartbeat from the node
    /// covers every hosted agent — hosted agents do not heartbeat individually.
    /// Requires an Arc'd node because the loop holds a reference across ticks.
    pub fn start_heartbeat(self: &std::sync::Arc<Self>) {
        self.stop_heartbeat();
        let me = std::sync::Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(crate::client::HEARTBEAT_INTERVAL);
            loop {
                ticker.tick().await;
                if me.send_heartbeat().await.is_err() {
                    break;
                }
            }
        });
        *self.heartbeat_task.lock().unwrap() = Some(handle);
    }

    /// Stop the periodic node heartbeat.
    pub fn stop_heartbeat(&self) {
        if let Some(handle) = self.heartbeat_task.lock().unwrap().take() {
            handle.abort();
        }
    }

    /// The availability currently advertised in the heartbeat.
    pub fn availability(&self) -> Availability {
        *self.availability.lock().unwrap()
    }

    /// Override the availability advertised in the heartbeat (§9.6) and emit one
    /// immediately so the change propagates without waiting for the next tick.
    /// Node-level: applies to every hosted agent. `Offline` is a liveness fact
    /// (missed heartbeats), not a state to advertise while connected — callers
    /// should use `Online`/`Busy`/`Degraded` here.
    pub async fn set_availability(&self, availability: Availability) {
        *self.availability.lock().unwrap() = availability;
        let _ = self.send_heartbeat().await;
    }

    /// Drain and close the node's connection. Hosted agents lose transport.
    pub async fn close(&self) {
        self.stop_heartbeat();
        // §4.4: the renewal loop never outlives the registrations it maintains.
        self.stop_vouch_renewal();
        // §4.8: nor does the credential loop outlive the connection it keeps
        // usable.
        if let Some(renewer) = &self.cred_renewer {
            renewer.stop();
        }
        self.agents.lock().unwrap().clear();
        let _ = self.client.drain().await;
    }
}

/// Arm the §4.8 credential loop for a node, and renew immediately if the
/// credential is already past its deadline — the case that matters, a node
/// returning from a long sleep. (The loop's first tick fires at once and does
/// exactly that, so there is no separate startup call.)
///
/// A free function, like [`renew_all`], so it can be built BEFORE the node
/// exists and capture only the agent list: the loop must never be what keeps a
/// dropped node alive.
///
/// The roster is read at each renewal, so an agent added after this node
/// connected is covered by the next credential without anything re-registering
/// it here — and each agent consents with a detached signature by its own key,
/// so the node never needs to hold an agent seed. Closed agents are dropped
/// from the roster: an agent that detached is not one this node still hosts.
fn start_credential_renewal(
    cfg: CredentialRenewal,
    jwt: String,
    node_seed: &str,
    agents: std::sync::Arc<std::sync::Mutex<Vec<AgentMesh>>>,
) -> std::sync::Arc<CredentialRenewer> {
    let on_warning = cfg.on_warning.clone();
    let renewer = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: cfg.api_base,
        jwt,
        node_seed: cfg.credential_seed.unwrap_or_else(|| node_seed.to_string()),
        agents: RenewalRoster::dynamic(move || {
            agents
                .lock()
                .unwrap()
                .iter()
                .filter(|a| !a.is_closed())
                .map(|a| {
                    let agent = a.clone();
                    RenewalAgent::with_signer(a.id().to_string(), move |m| agent.sign_detached(m))
                })
                .collect()
        }),
        transport: cfg.transport,
        on_renewed: cfg.on_renewed,
        on_warning,
    });
    renewer.start();
    renewer
}

/// One §4.4 renewal pass over a node's hosted agents. Closed agents are pruned
/// first — an agent that detached (its own `close`) is not this loop's to
/// renew — then every remaining agent gets a `renew_vouch_if_due_at` judgement
/// against the same instant. A free function so the loop task can share it
/// with [`MeshNode::renew_vouches`] while holding only the agent list.
async fn renew_all(agents: &std::sync::Mutex<Vec<AgentMesh>>, now_ms: i64) -> usize {
    let snapshot: Vec<AgentMesh> = {
        let mut list = agents.lock().unwrap();
        list.retain(|a| !a.is_closed());
        list.clone()
    };
    let mut renewed = 0;
    for agent in snapshot {
        if agent.renew_vouch_if_due_at(now_ms).await {
            renewed += 1;
        }
    }
    renewed
}
