//! Interpretation uses public structured mail APIs; raw bytes remain authoritative.
use email_address::EmailAddress;
use mail_parser::{Address, HeaderName, HeaderValue, MessageParser};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_AUTHORS: &[&str] = &[
    "torvalds@klaava.helsinki.fi",
    "torvalds@transmeta.com",
    "torvalds@osdl.org",
    "torvalds@linux-foundation.org",
    "torvalds@linuxfoundation.org",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub spelling: String,
    pub local: String,
    pub domain: String,
}
impl Mailbox {
    pub fn parse(value: &str) -> Result<Self, AddressError> {
        let address: EmailAddress = value.parse().map_err(AddressError)?;
        Ok(Self {
            spelling: value.into(),
            local: address.local_part().into(),
            domain: address.domain().to_ascii_lowercase(),
        })
    }
    fn matches(&self, other: &Self) -> bool {
        self.local == other.local && self.domain == other.domain
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AddressError(email_address::Error);

#[derive(Debug, thiserror::Error)]
pub enum AuthorError {
    #[error("empty author policy")]
    Empty,
    #[error(transparent)]
    Address(#[from] AddressError),
}

pub fn authors(values: &[String]) -> Result<Vec<Mailbox>, AuthorError> {
    if values.is_empty() {
        return Err(AuthorError::Empty);
    }
    values
        .iter()
        .map(|value| Mailbox::parse(value).map_err(AuthorError::from))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Invalid,
    AmbiguousFrom,
    Context,
    UnlinkedAuthor,
    AmbiguousReply,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdField {
    pub values: Vec<String>,
    pub usable: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Direct,
    References,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub basis: Basis,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub class: Class,
    pub headers: serde_json::Value,
    pub text: Vec<String>,
    pub html: Vec<String>,
    pub from: Option<Mailbox>,
    pub message_ids: Vec<IdField>,
    pub primary_id: Option<String>,
    pub in_reply_to: Vec<IdField>,
    pub references: Vec<IdField>,
    pub parent: Option<Candidate>,
    pub ambiguities: Vec<String>,
}
fn ids(header: &mail_parser::Header<'_>, raw: &[u8]) -> IdField {
    let values: Vec<String> = header
        .value
        .as_text_list()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect();
    // mail-parser also returns Text for broken-client, bracket-less input.
    // Validate the original field with a public Message-ID grammar, not mailbox
    // rules: ID domains can be dot-atoms or literals that are not DNS/IP names.
    // Keep the original parser values even when the grammars disagree.
    let usable = std::str::from_utf8(&raw[header.offset_start..header.offset_end])
        .ok()
        .and_then(|field| {
            // Delivered LF mail is accepted by mail-parser. The validation
            // library expects CRLF folds; this copy never replaces source data.
            let field = field.trim().replace("\r\n", "\n").replace('\n', "\r\n");
            <email_format::rfc5322::headers::InReplyTo as email_format::TryFrom<&str>>::try_from(
                field.as_str(),
            )
            .ok()
        })
        .is_some_and(|parsed| {
            !values.is_empty()
                && parsed
                    .0
                    .iter()
                    .map(|id| format!("{}@{}", id.id_left, id.id_right))
                    .eq(values.iter().cloned())
        });
    IdField { values, usable }
}
fn single(fields: &[IdField]) -> Option<&str> {
    match fields {
        [
            IdField {
                values,
                usable: true,
            },
        ] if values.len() == 1 => Some(&values[0]),
        _ => None,
    }
}
fn reference_tail(fields: &[IdField]) -> Option<&str> {
    match fields {
        [
            IdField {
                values,
                usable: true,
            },
        ] => values.last().map(String::as_str),
        _ => None,
    }
}

pub fn interpret(raw: &[u8], policy: &[Mailbox]) -> Metadata {
    let mut out = Metadata {
        class: Class::Invalid,
        headers: serde_json::Value::Array(vec![]),
        text: vec![],
        html: vec![],
        from: None,
        message_ids: vec![],
        primary_id: None,
        in_reply_to: vec![],
        references: vec![],
        parent: None,
        ambiguities: vec![],
    };
    let Some(message) = MessageParser::default().parse(raw) else {
        return out;
    };
    out.headers = match serde_json::to_value(message.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            out.headers = serde_json::Value::Null;
            out.ambiguities.push("header_serialization_failed".into());
            return out;
        }
    };
    if !message
        .headers()
        .iter()
        .any(|header| !matches!(header.name, HeaderName::Other(_)))
    {
        return out;
    }
    out.text = (0..message.text_body.len())
        .filter_map(|index| message.body_text(index).map(|text| text.into_owned()))
        .collect();
    out.html = (0..message.html_body.len())
        .filter_map(|index| message.body_html(index).map(|text| text.into_owned()))
        .collect();
    let from: Vec<_> = message.header_values(HeaderName::From).collect();
    if let [HeaderValue::Address(Address::List(list))] = from.as_slice()
        && let [address] = list.as_slice()
        && let Some(address) = &address.address
    {
        out.from = Mailbox::parse(address).ok();
    }
    for header in message.headers() {
        let fields = match header.name {
            HeaderName::MessageId => &mut out.message_ids,
            HeaderName::InReplyTo => &mut out.in_reply_to,
            HeaderName::References => &mut out.references,
            _ => continue,
        };
        fields.push(ids(header, raw));
    }
    out.primary_id = single(&out.message_ids).map(str::to_owned);
    if !out.message_ids.is_empty() && out.primary_id.is_none() {
        out.ambiguities.push("message_id".into());
    }
    if out.from.is_none() {
        out.ambiguities.push("from".into());
    }
    let tail = reference_tail(&out.references);
    let direct = single(&out.in_reply_to);
    out.parent = if out.in_reply_to.is_empty() {
        tail.map(|id| Candidate {
            id: id.into(),
            basis: Basis::References,
        })
    } else if let Some(id) = direct {
        if out.references.is_empty() || tail == Some(id) {
            Some(Candidate {
                id: id.into(),
                basis: Basis::Direct,
            })
        } else {
            None
        }
    } else {
        None
    };
    let no_reply = out.in_reply_to.is_empty() && out.references.is_empty();
    if !no_reply && out.parent.is_none() {
        out.ambiguities.push("reply".into());
    }
    out.class = match &out.from {
        None => Class::AmbiguousFrom,
        Some(address) if !policy.iter().any(|selected| selected.matches(address)) => Class::Context,
        Some(_) if no_reply => Class::UnlinkedAuthor,
        Some(_) if out.parent.is_some() => Class::Response,
        Some(_) => Class::AmbiguousReply,
    };
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Links {
    pub message_ids: BTreeMap<String, Vec<String>>,
    pub relationships: BTreeMap<String, Relationship>,
    /// Every artifact belongs to exactly one thread. A thread is keyed by the
    /// smallest digest among its members.
    pub threads: BTreeMap<String, Thread>,
}
impl Links {
    /// Adds the entries of `changes`, which replace the entries under their
    /// keys. Added artifacts only ever merge threads, so a thread replaces
    /// every thread keyed by one of its members.
    pub fn fold(&mut self, changes: Links) {
        self.message_ids.extend(changes.message_ids);
        self.relationships.extend(changes.relationships);
        for (key, thread) in changes.threads {
            for member in &thread.members {
                let _merged_into_thread = self.threads.remove(member);
            }
            self.threads.extend([(key, thread)]);
        }
    }
    pub fn changes(&self, recomputed: Links) -> Links {
        fn changed<V: PartialEq>(
            current: &BTreeMap<String, V>,
            recomputed: BTreeMap<String, V>,
        ) -> BTreeMap<String, V> {
            recomputed
                .into_iter()
                .filter(|(key, value)| current.get(key) != Some(value))
                .collect()
        }
        Links {
            message_ids: changed(&self.message_ids, recomputed.message_ids),
            relationships: changed(&self.relationships, recomputed.relationships),
            threads: changed(&self.threads, recomputed.threads),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relationship {
    pub candidate: Candidate,
    pub targets: Vec<String>,
    pub ancestors: BTreeSet<String>,
    pub missing: BTreeSet<String>,
    pub cycles: BTreeSet<String>,
}
/// Artifacts connected through Message-IDs, directly or through other members.
/// An artifact is joined to its Message-ID and to every ID in its In-Reply-To and
/// References fields, whether or not the corpus has a message with that ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    /// Members without a resolved parent. A root with a parent candidate follows
    /// a message that is missing. A thread in which every member has a resolved
    /// parent, as in a cycle, has no root.
    pub roots: BTreeSet<String>,
    pub members: BTreeSet<String>,
}
/// Computes the links of `messages`, pairs of digest and metadata. Every
/// thread is computed from its own members only, so the links of a set of
/// whole threads equal the corpus-wide entries for those threads.
pub fn links<'a>(messages: impl IntoIterator<Item = (&'a String, &'a Metadata)>) -> Links {
    let messages: BTreeMap<&String, &Metadata> = messages.into_iter().collect();
    let mut out = Links::default();
    for (digest, message) in &messages {
        if let Some(id) = &message.primary_id {
            out.message_ids
                .entry(id.clone())
                .or_default()
                .push((*digest).clone());
        }
    }
    for (digest, message) in &messages {
        let Some(candidate) = &message.parent else {
            continue;
        };
        let targets = out
            .message_ids
            .get(&candidate.id)
            .cloned()
            .unwrap_or_default();
        let mut relation = Relationship {
            candidate: candidate.clone(),
            targets,
            ancestors: BTreeSet::new(),
            missing: BTreeSet::new(),
            cycles: BTreeSet::new(),
        };
        // Explicit DFS colors distinguish cycles from converging variant branches.
        let mut active = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut stack = vec![((*digest).clone(), false)];
        while let Some((current, exit)) = stack.pop() {
            if exit {
                active.remove(&current);
                continue;
            }
            if active.contains(&current) {
                relation.cycles.insert(current);
                continue;
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            active.insert(current.clone());
            stack.push((current.clone(), true));
            if let Some(parent) = &messages[&current].parent {
                match out.message_ids.get(&parent.id) {
                    None => {
                        relation.missing.insert(parent.id.clone());
                    }
                    Some(targets) => {
                        for target in targets.iter().rev() {
                            relation.ancestors.insert(target.clone());
                            stack.push((target.clone(), false));
                        }
                    }
                }
            }
        }
        out.relationships.extend([((*digest).clone(), relation)]);
    }
    out.threads = threads(&messages, &out.relationships);
    out
}
fn threads(
    messages: &BTreeMap<&String, &Metadata>,
    relationships: &BTreeMap<String, Relationship>,
) -> BTreeMap<String, Thread> {
    let mentions: Mentions = messages
        .iter()
        .map(|(digest, message)| (*digest, *message))
        .collect();
    let mut assigned = BTreeSet::new();
    let mut threads = BTreeMap::new();
    // Visiting the artifacts in ascending digest order makes each new thread
    // begin at its smallest member, which is its key.
    for start in messages.keys().copied() {
        if assigned.contains(start) {
            continue;
        }
        let members = mentions.thread_members([start]);
        let roots = members
            .iter()
            .filter(|member| {
                relationships
                    .get(**member)
                    .is_none_or(|relation| relation.targets.is_empty())
            })
            .map(|member| (*member).clone())
            .collect();
        let thread = Thread {
            roots,
            members: members.iter().map(|member| (*member).clone()).collect(),
        };
        assigned.extend(members);
        threads.extend([(start.clone(), thread)]);
    }
    threads
}
fn thread_ids(message: &Metadata) -> impl Iterator<Item = &String> {
    message
        .primary_id
        .iter()
        .chain(message.in_reply_to.iter().flat_map(|field| &field.values))
        .chain(message.references.iter().flat_map(|field| &field.values))
}
#[derive(Debug, Default)]
pub struct Mentions {
    ids: BTreeMap<String, Vec<String>>,
    artifacts: BTreeMap<String, Vec<String>>,
}
impl Mentions {
    pub fn add(&mut self, digest: &str, message: &Metadata) {
        let ids: Vec<String> = thread_ids(message).cloned().collect();
        for id in &ids {
            self.artifacts
                .entry(id.clone())
                .or_default()
                .push(digest.to_owned());
        }
        self.ids.extend([(digest.to_owned(), ids)]);
    }
    pub fn thread_members<'a>(
        &'a self,
        start: impl IntoIterator<Item = &'a String>,
    ) -> BTreeSet<&'a String> {
        let mut members = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut stack: Vec<_> = start.into_iter().collect();
        while let Some(digest) = stack.pop() {
            if !members.insert(digest) {
                continue;
            }
            for id in self.ids.get(digest).into_iter().flatten() {
                if visited.insert(id) {
                    stack.extend(self.artifacts.get(id).into_iter().flatten());
                }
            }
        }
        members
    }
}
impl<'a> FromIterator<(&'a String, &'a Metadata)> for Mentions {
    fn from_iter<I: IntoIterator<Item = (&'a String, &'a Metadata)>>(messages: I) -> Self {
        let mut mentions = Self::default();
        for (digest, message) in messages {
            mentions.add(digest, message);
        }
        mentions
    }
}
