//! Agent manifest + node vouching types (AgentMesh 0.2 §4.4, §8).

use serde::{Deserialize, Serialize};

/// A node's signed attestation that it hosts an agent (§4.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAttestation {
    pub node: String,
    pub agent: String,
    pub issued_at: String,
    pub expires_at: String,
    pub sig: String,
}

/// The node's self-declared profile attributes (§9.7). Attested attributes
/// (`trust_tier`, `role`) are set by the operator and are deliberately not
/// expressible here — a node cannot claim a standing it was not granted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeDeclaredProfile {
    /// Expected uptime pattern: "always_on" | "intermittent" | "on_demand".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_class: Option<String>,
    /// "direct" | "leaf" (outbound-only, e.g. behind a firewall).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<String>,
    /// Declared limits, distinct from live heartbeat load (§10.9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<serde_json::Value>,
    /// EXT-1 device profile (mesh://extensions/device-profile/v1). Advisory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_class: Option<String>,
}

/// EXT-1 `client` self-identification. Keep in sync with Cargo.toml.
pub const SDK_CLIENT: &str = concat!("sdk-rust/", env!("CARGO_PKG_VERSION"));

/// Detect the EXT-1 device attributes this runtime can know on its own
/// (platform + client). Merged UNDER caller-declared keys: the caller wins.
pub fn with_detected_device(profile: Option<NodeDeclaredProfile>) -> NodeDeclaredProfile {
    let mut p = profile.unwrap_or_default();
    if p.client.is_none() {
        p.client = Some(SDK_CLIENT.to_string());
    }
    if p.platform.is_none() {
        // std::env::consts::OS: "linux" | "macos" | "windows" | "android" | "ios" | …
        p.platform = match std::env::consts::OS {
            "macos" => Some("darwin".to_string()),
            "windows" => Some("win32".to_string()),
            os @ ("linux" | "android" | "ios") => Some(os.to_string()),
            _ => None,
        };
    }
    p
}

/// The hosting-node reference carried in an agent's manifest (§8.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRef {
    pub id: String,
    pub attestation: AgentAttestation,
    /// The node's self-declared profile (§9.7), carried with the vouch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<NodeDeclaredProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offering {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Media types this offering accepts as input (§8.1). Absent means
    /// undeclared, which excludes nothing — the §6.4b pre-flight only refuses
    /// against a declared list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,
    /// Media types this offering can produce (§8.1). Absent means undeclared;
    /// same pre-flight rule as `input_modes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    /// The engagement contract (§8.5.1): what must be in hand before work can
    /// start. Deliberately loose — the discovery-time reader is usually a
    /// model deciding whom to hire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<Vec<NeedEntry>>,
    /// The engagement contract (§8.5.1): what the caller gets, and how.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivers: Option<Delivers>,
    /// The offered reporting level (§8.5.2): self-declared, an advertisement
    /// and never a clause. See [`OfferingReporting`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporting: Option<OfferingReporting>,
}

/// The offered reporting level on an offering (§8.5.2): the level its
/// provider offers to bind in an engagement formed over it, in the Agent SoW
/// §5.12 vocabulary — `records_only`, `on_change` or `check_ins`
/// ([`crate::sow::SOW_REPORTING_LEVELS`]), ordinal, compared meets-or-exceeds.
///
/// An ADVERTISEMENT, not a clause: what binds is the reporting clause inside
/// the signed engagement document. Self-declared — nothing verifies it, and a
/// consumer that renders it must present it as the provider's own claim.
///
/// `every` takes §5.12's restricted duration grammar (`P1W`, `P3D`, `PT12H`;
/// [`crate::sow::reporting_every_ms`]). It must accompany `check_ins` and
/// must not appear below it. The registry validates on the way in and drops
/// an unreadable declaration at registration rather than serving it; the
/// storefront materialization it feeds is platform-side, so this crate's job
/// is only to let a Rust agent DECLARE the field on its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferingReporting {
    /// One of the closed §5.12 set. A `String` like this file's other
    /// vocabulary fields, so an unrecognised value on a foreign manifest
    /// does not fail the whole deserialization.
    pub level: String,
    /// The offered cadence — required with `check_ins`, refused below it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every: Option<String>,
}

/// One entry of an offering's `needs` (§8.5.1). Exactly one of `resource` /
/// `file` / `credential` / `text` is expected: a shared resource (§7.5.5) the
/// caller must provide, material to attach (§7.5.3), a sign-in to a
/// third-party service, or prose for anything else.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NeedEntry {
    /// A shared-resource kind (`git`, …) the caller must provide (§7.5.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// With `resource`: `read` or `read-write` — what the offering will do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// A MIME type the caller should attach (§7.5.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// A tool or MCP server the CALLER must connect and authorize before this
    /// offering can do anything.
    ///
    /// Distinct from `resource`, which is a thing the caller hands over, and
    /// from `credential`, which is a sign-in the agent will ask for. This one
    /// is capability the agent does not have until you wire it up, and its
    /// count is what tells a buyer whether hiring this agent is a call or a
    /// project. The tool's NAME as a person would say it, never an endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// With `tool`: how it connects, when that is worth saying. `mcp` is the
    /// expected spelling for an MCP server; anything else is free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// A named third-party service the agent will ask the caller to sign in to
    /// — a product the caller licenses, a government or bank site they have an
    /// account on. The service's NAME ("Colorado DMV"), not a URL.
    ///
    /// The kind that has to be declared. To the person being asked, a third
    /// party requesting a government or bank sign-in is indistinguishable from
    /// a phishing attempt, so saying it up front is the only way the honest
    /// case can look honest. Nothing here carries the credential itself: a
    /// caller who agrees sends it sealed (§4.3) or through the service's own
    /// authorization flow. Renderers should give it more room than the rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// With `credential`: what the sign-in will be used for, in plain
    /// language. The narrowest true answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Anything that fits neither, in plain language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One external service an agent says it integrates with (§8.8).
///
/// A claim about an INTEGRATION and never about affiliation or endorsement.
/// "Works with the Colorado DMV" is the true thing a third-party wrapper needs
/// to be able to say; presenting AS the Colorado DMV is impersonation, and this
/// field makes it no less so. The field exists precisely so the honest
/// statement does not have to be made by borrowing somebody's identity.
///
/// Nothing verifies any of it — `domain` is a string the registrant typed, not
/// a proven binding — so a consumer must not render an entry as verified or as
/// endorsement, and must not read an absent entry as "no such integration".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorksWith {
    /// The external service's name.
    pub service: String,
    /// That service's domain, so a reader knows which "Acme" is meant. Checked
    /// by nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// What the integration does, in plain language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The promises half of the card-level data-use declaration (§8.10), in the
/// Agent SoW §5.11 vocabulary. Only `true` is ever meaningful: a promise left
/// out is a promise not made — `false` is not a value, it is spelled by
/// omission. `Option<bool>` rather than a unit marker so a foreign manifest
/// spelling a promise wrongly still deserializes; the registry is what drops
/// an unreadable declaration, whole, on the way in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDataUsePromises {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_training: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_third_party_sharing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_human_reading: Option<bool>,
}

/// The retention ceiling the operator is prepared to bind (§8.10), in whole
/// days.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDataUseRetention {
    pub max_days: u64,
}

/// The card-level data-use declaration (§8.10): what happens to content a
/// buyer hands this agent — training, retention, human access, and the
/// services content passes through. The pre-admission shadow of the Agent SoW
/// confidentiality clause (§5.11): the clause's shape minus grades (everything
/// here is self-declared) and minus transport, which is §8.9's own field.
///
/// SELF-DECLARED, never rendered as verified or enforced. ABSENT means the
/// agent has not said, with no default in either direction. ONE declaration
/// per agent, at card level. An EMPTY `processors` list is itself a statement
/// — content leaves the operator for nowhere — while an omitted one states
/// nothing.
///
/// This crate's job is only to let a Rust agent DECLARE the field: the
/// registry validates on the way in and drops an unreadable declaration WHOLE
/// (a partially readable privacy claim misleads more than none at all), and
/// the storefront surface it feeds is platform-side.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDataUse {
    /// The promises made, each spelled the literal `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promises: Option<AgentDataUsePromises>,
    /// The retention ceiling, in whole days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<AgentDataUseRetention>,
    /// The services content passes through so the work can happen, in §5.11's
    /// entry shape. `Some(vec![])` is meaningful and serializes as `[]`:
    /// empty states "nowhere", omission states nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processors: Option<Vec<crate::sow::SowProcessor>>,
    /// The jurisdictions content may touch (§8.10) — where it is processed
    /// and stored — as lowercase ISO 3166-1 alpha-2 country codes. A SET
    /// declaration, subset-tested against a buyer's allowed list; declare
    /// only what the pipeline contractually commits to, because an absent
    /// `processed_in` fails any jurisdiction requirement — the correct fate
    /// for "we don't know where it runs" when the buyer asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processed_in: Option<Vec<String>>,
}

/// The attestation pointer of a §8.11 compliance entry: who said so — an
/// auditor's name, a URL a reader can follow, an expiry after which the claim
/// is stale on its face. The operator's OWN pointer: nothing in the protocol
/// fetches the URL, verifies the auditor, or checks the expiry against
/// anything but the calendar, and no consumer may render it as verification
/// the platform performed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentComplianceAttestation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// One compliance posture the operator claims (§8.11): "are you SOC 2, do
/// you operate under GDPR" — advertised where a buyer in a regulated
/// industry can read it before anything forms.
///
/// SELF-DECLARED, including the attestation pointer. ABSENT means the
/// operator has not said, and a stated requirement treats silence as not
/// meeting it. The `standard` vocabulary is open (`soc2`, `iso27001`,
/// `gdpr`, `hipaa`, `pci-dss` are the expected spellings of the usual
/// suspects) and comparison is exact token equality. The registry validates
/// on the way in and drops an unreadable `compliance` member WHOLE (§8.11);
/// this crate's job is only to let a Rust agent declare it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentComplianceEntry {
    /// The claimed standard, as a lowercase token. Compared by exact equality.
    pub standard: String,
    /// What the claim covers, in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Who said so — the operator's own pointer, never platform verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AgentComplianceAttestation>,
}

/// Who the agent was built to serve (§8.12).
///
/// Two fields, not one, and the second is the one nobody thinks to declare. A
/// gradebook agent is `for` teachers and touches nobody else; a tutoring agent
/// is bought by a school, directed by a teacher, and TOUCHES a child. The same
/// split runs through clinician and patient, recruiter and applicant, advisor
/// and retail investor, and in every pair the second population is the one
/// with obligations attached and the one that is never the buyer.
///
/// Free text rather than a vocabulary: the audiences worth naming are
/// open-ended and the reader is usually a model. Card-level for the same
/// reason `data_use` is — an agent serving two audiences is two products.
/// `touches` accepts the literal `none`, a real answer distinct from silence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAudience {
    /// Who hires and directs it: "teachers", "accountants", "support leads".
    #[serde(rename = "for", default, skip_serializing_if = "Option::is_none")]
    pub for_audience: Option<String>,
    /// Who is on the receiving end without being the buyer, or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touches: Option<String>,
}

/// Where the agent's answers are valid (§8.12).
///
/// Every agent has a boundary of competence and almost no listing states it. A
/// property valuation agent holding data for one postcode will answer about
/// any postcode, and the narrowness is not the danger: narrowness plus a
/// confident answer outside it is.
///
/// NOT `data_use.processed_in` (§8.10), which says where content is handled.
/// That is a privacy fact about bytes; this is a competence fact about
/// answers. Self-declared, and absence is not a claim of universal coverage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCoverage {
    /// Places its answers hold, as the operator would name them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geography: Option<Vec<String>>,
    /// Legal jurisdictions its answers are correct under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<Vec<String>>,
    /// Languages it works in, as BCP 47 tags where possible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Vec<String>>,
    /// Anything the three above cannot carry, in plain language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One company standing behind this agent, besides whoever published it
/// (§8.12).
///
/// A single provider field is a fiction for most enterprise agents. An agent
/// built on a vendor's platform, configured by an agency and run inside a
/// customer has three companies attached to three different scopes, and the
/// reader's real question is "who do I call when it misbehaves". One name
/// cannot answer that.
///
/// The PUBLISHER is not in this list — exactly one party stands behind a
/// listing and is named elsewhere, which keeps accountability singular while
/// letting the picture be honest. `role` is `platform`, `implementer`,
/// `operator` or `data_source`, as a string for the usual round-trip reason.
///
/// Naming a company here is a statement about construction, NOT a claim of
/// partnership, sponsorship or endorsement, and nothing verifies it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentParty {
    pub name: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// What they are on the hook for, in plain language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One thing the agent does that changes something (§8.12).
///
/// `approval` is the member that matters. An agent that can close a ticket and
/// an agent that can close a ticket only after somebody says yes are different
/// purchases, and a listing has had no way to tell them apart. ABSENT does NOT
/// mean unattended: the safe reading of silence is the pessimistic one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAction {
    /// What it does, as a person would say it.
    pub action: String,
    /// True when this action waits for a human or a policy check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// What the agent does with what it can reach (§8.12).
///
/// NOT the Agent Mandate, and the difference is who writes the document and
/// when. A mandate (agentmandate.net) is signed by the BUYER's organization at
/// hire time and names the powers, ceiling and expiry of one deployment. This
/// is written by the PUBLISHER before any buyer exists and says what the agent
/// will do if you let it. A listing cannot point at a mandate, because at
/// listing time there is none. Declaring an action here grants nothing.
///
/// `mode` is `"read"` (changes nothing) or `"act"` (changes something), as a
/// string for the same round-trip reason as `sealing`. An `act` with no named
/// actions is legal and deliberately unsatisfying: it says the agent does
/// something without saying what.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentActs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<AgentAction>>,
}

/// Where the agent came from (§8.12): four questions with small closed
/// vocabularies, from which the archetype labels people recognise
/// ("marketplace agent", "studio agent") are DERIVED.
///
/// Coordinates rather than a label on purpose. Archetype names are pinned to
/// vendor product tiers renamed on somebody else's release schedule, and a
/// label stored as truth goes stale while the facts underneath stay correct.
///
/// Values are the spec's tokens: `written_by` is developer,
/// buyer_or_implementer or vendor; `run_by` is builder, vendor_platform,
/// managed_runtime or not_running; `open_to` is builder, team, company or
/// anyone; `acquired_by` is clone, subscription, channel or call. Carried as
/// strings so an unknown token round-trips rather than failing a deserialize.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentOrigin {
    /// Whether the behaviour was written as code, configured on the buyer's
    /// side (by the buyer or an agency acting for them), or shipped prebuilt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_by: Option<String>,
    /// Whose infrastructure it executes on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_by: Option<String>,
    /// Who is permitted to call it. NOT the same question as who it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_to: Option<String>,
    /// How a buyer obtains it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acquired_by: Option<String>,
}

/// What the caller gets (§8.5.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Delivers {
    /// Prose or a MIME type: the form of the finished deliverable.
    #[serde(rename = "final", default, skip_serializing_if = "Option::is_none")]
    pub final_form: Option<String>,
    /// Whether checkpoint deliverables arrive as task updates along the way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interim: Option<bool>,
    /// Whether the deliverable lands in a caller-provided resource (§7.5.5)
    /// rather than travelling back through the mesh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_resource: Option<bool>,
}

/// One live object both parties knowingly operate on (§7.5.5) — a git
/// repository two agents are coding in together. Files (inline or by ref)
/// hand the receiver its own copy; a resource points both parties at the same
/// live thing. Carries NONE of a ref's fields: no digest, size, media type or
/// expiry — no snapshot-shaped claim can honestly be made about a place, and
/// the mesh stores nothing for it. Never fetch/clone/probe implicitly; never
/// a credential in cleartext (§4.3 sealing, or the resource's own auth
/// domain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    /// Where the resource lives. Never resolved through a mesh store.
    pub uri: String,
    /// What sort of thing this is. `git` is reserved; otherwise open
    /// vocabulary — treat unrecognised kinds as opaque.
    pub kind: String,
    /// `read` or `read-write`: what the sender intends the receiver to do.
    pub access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Working conventions ("branch, then PR") — part of the agreement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The manifest's declared per-message inbound limits (§8.1) — what senders
/// pre-flight against (§6.4b).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Overrides the §22.5 default (65,536 UTF-16 code units) for this agent.
    /// Absent means the protocol default applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inbound_chars: Option<u64>,
}

/// The manifest's `endpoints` block (§8.1, §14.4): the agent's endpoint
/// subjects, **verbatim**, for callers to use without constructing them. At
/// minimum `inbox`. OPTIONAL on registration and registry-populated, so a
/// manifest that predates the field never lacks it once stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Endpoints {
    /// The subject direct requests go to. What [`Manifest::resolved_inbox`]
    /// returns first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox: Option<String>,
    /// Endpoint names this SDK does not model, carried verbatim (§14.4: the
    /// carried values, not the naming convention, are the contract).
    #[serde(flatten)]
    pub other: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The public block (§8.7): the storefront — the ONLY manifest content served
/// pre-admission. Operator-declared, served verbatim; nothing generates it at
/// request time.
///
/// This SDK models the one field it writes — `skus`, the §19.1 price
/// advertisement `register` derives from the declared SKUs — and carries every
/// other storefront field verbatim (§14.4's convention: the carried values are
/// the contract), so a manifest written by the TS SDK round-trips untouched.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublicBlock {
    /// Commercial terms advertised to strangers (§19.1): each entry a SKU id,
    /// its price, and its digest — price as pre-admission data, so a buyer
    /// compares terms before knocking and an `AGREEMENT_REQUIRED` refusal
    /// (§19.5) points at terms the storefront already showed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skus: Option<Vec<crate::sku::PublicSku>>,
    /// Storefront fields this SDK does not model (`description`, `offerings`,
    /// `example_queries`, `links`, …), carried verbatim.
    #[serde(flatten)]
    pub other: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The manifest's trust block (§8.3).
///
/// `signature` is NOT a signature over the manifest. It is the agent's signed
/// claim binding its `id` to the `encryption_key` it published, made at
/// `issued_at`. That narrow binding is the one thing a reader must be able to
/// authenticate before sealing anything to the key (§7.3); the registry rewrites
/// `owner`/`visibility`/`sandbox` server-side after the agent signs, so a
/// whole-manifest signature could never verify for the party reading it back.
///
/// Wire-compatible with the TS SDK's `Trust`, field for field — the field NAMES
/// are pinned by `conformance/manifest-signing.json` alongside the bytes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Trust {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// When the key claim was made (RFC 3339). Inside the signed bytes, so a
    /// verifier can rebuild them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<String>,
    /// base64url Ed25519 signature over the §8.3 key claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Agent manifest (§8). 0.2: durable description only — no liveness fields
/// (those live in presence, §9.6) and no `network`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub protocol_version: String,
    /// The agent's X25519 encryption public key (core §4.3): lets others seal
    /// content to this agent (e.g. a sealed-room key). Absent = cleartext only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    /// Whether callers should seal what they send this agent, and whether an
    /// unsealed request gets read at all (§8.9): `"required"` | `"preferred"`.
    ///
    /// ABSENT is the third state and the load-bearing one. It means the agent
    /// has not said, it is what every manifest written before this field
    /// existed says, and it must keep meaning cleartext — so nothing infers a
    /// posture from a published `encryption_key`. An agent may hold a key only
    /// for sealed rooms, with a request handler that has never seen a
    /// `SealedPayload`.
    ///
    /// A string rather than an enum, like `visibility` and `interaction`: a
    /// value this SDK does not recognise must round-trip rather than fail a
    /// deserialize, and an unrecognised posture is read as "has not said".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealing: Option<String>,
    /// What happens to content a buyer hands this agent (§8.10). Card-level,
    /// one declaration per agent; pre-admission data that travels with the
    /// storefront the way `sealing` does. Self-declared; absent means the
    /// agent has not said, and nothing may be inferred from silence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_use: Option<AgentDataUse>,
    /// The compliance postures the operator claims (§8.11). Card-level,
    /// pre-admission, self-declared including each entry's attestation
    /// pointer; absent means the operator has not said, and a stated
    /// requirement treats silence as not meeting it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<Vec<AgentComplianceEntry>>,
    /// Who this agent was built to serve, and who it touches without being the
    /// buyer (§8.12). Card-level, pre-admission, self-declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<AgentAudience>,
    /// Where this agent's answers are valid (§8.12). NOT
    /// `data_use.processed_in`, which is about where bytes are handled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<AgentCoverage>,
    /// What it does when asked outside `coverage` (§8.12): `"declines"` |
    /// `"answers"`.
    ///
    /// ABSENT is the third state and means the operator has not said. A
    /// consumer MUST NOT read silence as `declines`; that turns missing
    /// information into a safety promise nobody made. A string rather than an
    /// enum for the same round-trip reason as `sealing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<String>,
    /// Whose interest it acts in (§8.12): `"hirer"` | `"owner"` | `"neutral"`.
    ///
    /// A supplier's quoting agent answers accurately and still optimises for
    /// its owner's margin; in a list of results that looks identical to an
    /// agent you hired, and the distinction is not derivable from anything
    /// else on the card. Absent means unstated, and `hirer` must not be
    /// assumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serves: Option<String>,
    /// What it does with what it can reach (§8.12): read-only, or acting with
    /// each action named and flagged for approval. NOT a mandate — this
    /// informs the decision to hire, a mandate constrains the thing once
    /// hired, and declaring an action here grants nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acts: Option<AgentActs>,
    /// The other companies standing behind this agent (§8.12). NOT the
    /// publisher, who is exactly one party named elsewhere. Unverified, and
    /// never endorsement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parties: Option<Vec<AgentParty>>,
    /// Where it came from, as four coordinates rather than an archetype label
    /// (§8.12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<AgentOrigin>,
    pub endpoint: String,
    /// The agent's endpoint subjects, verbatim (§8.1, §14.4). OPTIONAL on the
    /// wire; this SDK's `register` populates it so resolution is always
    /// available even before a registry stamps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Endpoints>,
    /// Declared per-message inbound limits senders pre-flight against
    /// (§8.1, §6.4b). Absent means the protocol defaults apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
    pub node: NodeRef,
    pub capabilities: Vec<String>,
    /// Deprecation window (§8.5): manifests stored before the rename say
    /// `skills`; read as the same list. Serialization emits only `offerings`.
    #[serde(alias = "skills")]
    pub offerings: Vec<Offering>,
    /// Event subjects this agent publishes (§8.2) — notably its declared
    /// feeds (§6.6a), each as its full `mesh.feed.{id}.{topic}` subject,
    /// which is what makes a feed discoverable through the registry like any
    /// other manifest fact. Set by `register` from
    /// [`crate::client::AgentMesh::declare_feed`]; absent means nothing
    /// declared, which excludes nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emits: Option<Vec<String>>,
    /// Event subjects this agent subscribes to (§8.2) — `emits`'s twin,
    /// carried for wire parity with the TypeScript manifest. This SDK does
    /// not derive it; declaration-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<Vec<String>>,
    /// External services this agent integrates with (§8.8). Pre-admission
    /// data: it travels with the storefront, because a claim nobody can read
    /// before knocking is not a claim. An integration claim ONLY — never
    /// affiliation, never endorsement, and never verified by anyone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub works_with: Option<Vec<WorksWith>>,
    /// The §8.7 public block, with §19.1's price advertisement: when SKUs are
    /// declared, `register` fills `public.skus` with each one's id, price, and
    /// digest (an explicit `public.skus` wins — advertising less than you sell
    /// is a choice the spec protects).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<PublicBlock>,
    /// Declared commercial terms (§19.1). Absent or empty means every offering
    /// is free — paid is the declared exception.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skus: Option<Vec<crate::sku::Sku>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    /// The §8.3 key claim, set by `register` and checked by anyone about to seal
    /// to `encryption_key`. Optional on the wire: a manifest registered by an
    /// older SDK has none, and the correct response to that is to refuse to seal
    /// (see `AgentMesh::encryption_key_for`), not to seal anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<Trust>,
    /// Discovery visibility (§9.x): "public" (default) | "unlisted" | "private".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// How inbound requests are handled, so a caller knows what reaching this
    /// agent MEANS before it sends anything (§8.2): `"service"` (no person in the
    /// loop — sending disturbs nobody) or `"interactive"` (delivered into a live
    /// session somebody is using, so sending may interrupt them and an answer
    /// waits on their attention).
    ///
    /// **Absent means unknown**, which a careful caller reads as `interactive` —
    /// the cautious assumption (§8.3a). So absent is not a synonym for `service`
    /// and this field is never defaulted or invented, here or by the registry.
    ///
    /// Deliberately NOT covered by the §8.3 key claim: §8.3a is explicit that it
    /// is not a security boundary. An agent that misdeclares itself inconveniences
    /// callers rather than gaining anything, a signature cannot tell an honest
    /// declaration from a lie (the agent signs whatever it says), and the field
    /// already fails safe. Compare `encryption_key`, which has no safe default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction: Option<String>,
    /// The product answering here — the assistant or framework the agent runs
    /// inside ("claude-code", "openclaw", "hermes", "letta"), as its operator
    /// names it. Self-declared like every storefront fact, though join paths
    /// usually prefill it (an MCP client introduces itself; the adapter knows
    /// what it wraps). Absent means the operator has not said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    /// The harness's version, from the same source as `harness`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_version: Option<String>,
    /// The model behind the agent, at whatever precision the operator stands
    /// behind — a family ("claude") or an exact name ("claude-opus-5"). The
    /// operator's word, and it drifts: models change more often than cards,
    /// so readers weigh it against the registration's age.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Controlling operator/org key; defaults to the node id (set by the registry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Live availability, stamped by the registry on DISCOVER results only
    /// (§9.3 presence join). Never stored; absent on registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
    /// Owner attestation, present when `owner` differs from the node (§9.x).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_attestation: Option<AgentAttestation>,
}

impl Manifest {
    /// The subject a caller addresses this agent's requests to, resolved per
    /// §14.4: the `endpoints.inbox` carried value wins when present, then the
    /// legacy `endpoint` field; `None` when the manifest carries neither (an
    /// SDK — the convention's one legitimate constructor — may then fall back
    /// to constructing).
    pub fn resolved_inbox(&self) -> Option<&str> {
        if let Some(inbox) = self.endpoints.as_ref().and_then(|e| e.inbox.as_deref()) {
            if !inbox.is_empty() {
                return Some(inbox);
            }
        }
        if self.endpoint.is_empty() { None } else { Some(&self.endpoint) }
    }

    /// The declared §22.5 sender-text cap (§8.1 `limits.max_inbound_chars`),
    /// or `None` when undeclared — in which case the §22.5 default governs the
    /// §6.4b pre-flight.
    pub fn declared_max_inbound_chars(&self) -> Option<u64> {
        self.limits.as_ref().and_then(|l| l.max_inbound_chars)
    }

    /// The offering definition for `offering_id`, if this manifest declares it.
    pub fn offering(&self, offering_id: &str) -> Option<&Offering> {
        self.offerings.iter().find(|s| s.id == offering_id)
    }
}

/// Presence status vocabulary (§9.6). Not part of the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Availability {
    Online,
    Busy,
    Degraded,
    Offline,
}
