//! Control-plane requests.
//!
//! One line of JSON is one [`Request`]. The enum is internally tagged by an
//! `op` field, so a request reads as `{"op":"rule-add", ...}` — self-describing
//! on purpose: the control plane is low-frequency operator traffic and being
//! human-debuggable is a feature.
//!
//! There is deliberately no "modify rule" operation: a modification is a
//! remove followed by an add, which keeps the rule keyspace unambiguous.

use serde::{Deserialize, Serialize};

use crate::listener::Listener;
use crate::policy::{
    AuthMode, HostDirectIo, NamespaceName, NamespaceSpec, OwnershipSpec, PermissionMode, Rule,
    XattrRule,
};
use crate::response::{ControlError, ErrorCode};

macro_rules! requests {
    (
        $(
            $(#[$attribute:meta])*
            $variant:ident $fields:tt => $operation:literal
        ),+ $(,)?
    ) => {
        /// Every operation name the server understands, in declaration order.
        ///
        /// The list lets parsing distinguish an unknown operation from invalid
        /// arguments for a known one.
        pub const OPERATIONS: &[&str] = &[$($operation),+];

        /// One control-plane operation.
        ///
        /// Mutating variants carry policy in its [source form](crate::policy):
        /// the server resolves sentinels and relative targets exactly as a load
        /// does, and persists what it was given.
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "op", deny_unknown_fields)]
        pub enum Request {
            $(
                $(#[$attribute])*
                #[serde(rename = $operation)]
                $variant $fields,
            )+
        }

        impl Request {
            /// The operation name this request serializes with.
            #[must_use]
            pub fn operation(&self) -> &'static str {
                match self {
                    $(Self::$variant { .. } => $operation,)+
                }
            }
        }
    };
}

requests! {
    /// Server version, state file and control socket.
    ServerInfo {} => "server-info",
    /// Every namespace the server serves.
    NamespaceList {} => "namespace-list",
    /// One namespace in source form.
    NamespaceShow {
        /// The namespace to show.
        name: NamespaceName,
    } => "namespace-show",
    /// Creates a namespace.
    NamespaceCreate {
        /// The namespace to create, whole.
        namespace: NamespaceSpec,
    } => "namespace-create",
    /// Deletes a namespace. Sessions already resolved against it keep their
    /// snapshot; new handshakes fail.
    NamespaceDelete {
        /// The namespace to delete.
        name: NamespaceName,
    } => "namespace-delete",
    /// Adds one rule to a namespace.
    RuleAdd {
        /// The namespace to add to.
        namespace: NamespaceName,
        /// The rule.
        rule: Rule,
    } => "rule-add",
    /// Removes the rule keyed by a path and, for a pattern rule, a match.
    RuleRemove {
        /// The namespace to remove from.
        namespace: NamespaceName,
        /// The rule path, exactly as `rule-add` stated it.
        path: String,
        /// The match, for a pattern rule — a rule is keyed by the pair, so
        /// removal names both. Absent removes the rule that has no match.
        #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
        r#match: Option<String>,
    } => "rule-remove",
    /// Adds one extended-attribute rule to a namespace.
    XattrAdd {
        /// The namespace to add to.
        namespace: NamespaceName,
        /// The rule.
        rule: XattrRule,
    } => "xattr-add",
    /// Removes the extended-attribute rule keyed by a match.
    XattrRemove {
        /// The namespace to remove from.
        namespace: NamespaceName,
        /// The match, exactly as `xattr-add` stated it — an xattr rule is keyed
        /// by its match alone.
        #[serde(rename = "match")]
        r#match: String,
    } => "xattr-remove",
    /// Replaces a namespace's ownership policy.
    OwnershipSet {
        /// The namespace to change.
        namespace: NamespaceName,
        /// The new ownership policy, whole.
        ownership: OwnershipSpec,
    } => "ownership-set",
    /// Sets a namespace's permission mode.
    PermissionSet {
        /// The namespace to change.
        namespace: NamespaceName,
        /// The new permission mode.
        mode: PermissionMode,
    } => "permission-set",
    /// Sets a namespace's host-side direct-I/O posture.
    ///
    /// Live at the next open, like every other policy change: descriptions
    /// already open keep the posture they were opened under.
    DirectIoSet {
        /// The namespace to change.
        namespace: NamespaceName,
        /// The new posture.
        posture: HostDirectIo,
    } => "direct-io-set",
    /// Turns a namespace's privileged mode bits (setuid, setgid) on or off.
    ///
    /// Off, presentation masks them — recorded and host-real alike — and a
    /// chmod attempting to set them is refused; recorded truth is kept, not
    /// discarded, so turning the switch back on presents it again.
    PrivilegedBitsSet {
        /// The namespace to change.
        namespace: NamespaceName,
        /// Whether the namespace records and presents privileged bits.
        enabled: bool,
    } => "privileged-bits-set",
    /// Sets a namespace's auth mode.
    AuthSet {
        /// The namespace to change.
        namespace: NamespaceName,
        /// The new auth mode.
        mode: AuthMode,
    } => "auth-set",
    /// Lists the data-plane sessions the server is serving.
    SessionList {} => "session-list",
    /// Binds one data-plane listener and serves it, now and after a restart.
    ///
    /// The reply names the endpoint it actually bound, which is the only
    /// spelling a guest can connect to and the name `listener-remove` takes.
    ListenerAdd {
        /// The listener, in the same source form the state file holds.
        listener: Listener,
    } => "listener-add",
    /// Closes one data-plane listener, now and after a restart.
    ///
    /// Sessions already accepted on it keep serving and end by the ordinary
    /// connection-death rules: removal is not an eviction.
    ListenerRemove {
        /// The endpoint as bound, exactly as `server-info` lists it.
        endpoint: String,
    } => "listener-remove",
}

/// Parses one request line, classifying every way it can fail.
///
/// The three failure classes are distinguished because they mean different
/// things to an operator: the line was not JSON at all, the operation does not
/// exist (likely a version skew), or the arguments were wrong. All three are
/// answered with a structured error and the connection lives on.
///
/// # Errors
///
/// Returns a [`ControlError`] carrying [`ErrorCode::MalformedRequest`],
/// [`ErrorCode::UnknownOperation`] or [`ErrorCode::InvalidRequest`].
pub fn parse_request(line: &[u8]) -> Result<Request, ControlError> {
    let value: serde_json::Value = serde_json::from_slice(line)
        .map_err(|error| ControlError::new(ErrorCode::MalformedRequest, error.to_string()))?;
    if let Some(operation) = value.get("op").and_then(serde_json::Value::as_str)
        && !OPERATIONS.contains(&operation)
    {
        return Err(ControlError::new(
            ErrorCode::UnknownOperation,
            format!("unknown operation {operation:?}"),
        ));
    }
    serde_json::from_value(value)
        .map_err(|error| ControlError::new(ErrorCode::InvalidRequest, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{IdSentinel, ShareMode};

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    #[test]
    fn requests_are_tagged_by_operation() {
        let cases = [
            (Request::ServerInfo {}, r#"{"op":"server-info"}"#),
            (Request::NamespaceList {}, r#"{"op":"namespace-list"}"#),
            (
                Request::NamespaceShow { name: name("p") },
                r#"{"op":"namespace-show","name":"p"}"#,
            ),
            (
                Request::NamespaceDelete { name: name("p") },
                r#"{"op":"namespace-delete","name":"p"}"#,
            ),
            (
                Request::RuleAdd {
                    namespace: name("p"),
                    rule: Rule::new("/a", ShareMode::Rw).with_target("a"),
                },
                r#"{"op":"rule-add","namespace":"p","rule":{"path":"/a","mode":"rw","target":"a"}}"#,
            ),
            (
                Request::RuleRemove {
                    namespace: name("p"),
                    path: "/a".to_owned(),
                    r#match: None,
                },
                r#"{"op":"rule-remove","namespace":"p","path":"/a"}"#,
            ),
            (
                Request::RuleAdd {
                    namespace: name("p"),
                    rule: Rule::new("/a", ShareMode::Rw).with_match("x-*"),
                },
                r#"{"op":"rule-add","namespace":"p","rule":{"path":"/a","mode":"rw","match":"x-*"}}"#,
            ),
            (
                Request::RuleRemove {
                    namespace: name("p"),
                    path: "/a".to_owned(),
                    r#match: Some("x-*".to_owned()),
                },
                r#"{"op":"rule-remove","namespace":"p","path":"/a","match":"x-*"}"#,
            ),
            (
                Request::XattrAdd {
                    namespace: name("p"),
                    rule: XattrRule::new("user.*").with_write(crate::policy::XattrVerdict::Deny),
                },
                r#"{"op":"xattr-add","namespace":"p","rule":{"match":"user.*","write":"deny"}}"#,
            ),
            (
                Request::XattrRemove {
                    namespace: name("p"),
                    r#match: "user.*".to_owned(),
                },
                r#"{"op":"xattr-remove","namespace":"p","match":"user.*"}"#,
            ),
            (
                Request::PermissionSet {
                    namespace: name("p"),
                    mode: PermissionMode::Passthrough,
                },
                r#"{"op":"permission-set","namespace":"p","mode":"passthrough"}"#,
            ),
            (
                Request::DirectIoSet {
                    namespace: name("p"),
                    posture: HostDirectIo::Passthrough,
                },
                r#"{"op":"direct-io-set","namespace":"p","posture":"passthrough"}"#,
            ),
            (
                Request::PrivilegedBitsSet {
                    namespace: name("p"),
                    enabled: false,
                },
                r#"{"op":"privileged-bits-set","namespace":"p","enabled":false}"#,
            ),
            (
                Request::AuthSet {
                    namespace: name("p"),
                    mode: AuthMode::None,
                },
                r#"{"op":"auth-set","namespace":"p","mode":"none"}"#,
            ),
            (Request::SessionList {}, r#"{"op":"session-list"}"#),
            (
                Request::ListenerAdd {
                    listener: Listener::Tcp {
                        addr: "127.0.0.1:9000".parse().expect("valid address"),
                    },
                },
                r#"{"op":"listener-add","listener":{"transport":"tcp","addr":"127.0.0.1:9000"}}"#,
            ),
            (
                Request::ListenerRemove {
                    endpoint: "127.0.0.1:9000".to_owned(),
                },
                r#"{"op":"listener-remove","endpoint":"127.0.0.1:9000"}"#,
            ),
        ];
        for (request, encoded) in cases {
            assert_eq!(
                serde_json::to_string(&request).expect("serializable"),
                encoded
            );
            assert_eq!(
                parse_request(encoded.as_bytes()).expect("parses"),
                request,
                "round trip of {encoded}"
            );
            assert!(OPERATIONS.contains(&request.operation()));
        }
    }

    #[test]
    fn mutating_requests_carry_the_source_form() {
        let encoded = r#"{"op":"ownership-set","namespace":"p","ownership":{"mode":"map","unmapped":"hide","squash_uid":65534,"squash_gid":65534,"uid_map":[{"host":"uid","guest":0}],"gid_map":[{"host":"gid","guest":0}]}}"#;
        let request = parse_request(encoded.as_bytes()).expect("parses");
        let Request::OwnershipSet { ownership, .. } = &request else {
            panic!("expected ownership-set, got {request:?}");
        };
        let OwnershipSpec::Map { uid_map, .. } = ownership else {
            panic!("expected map ownership");
        };
        // The sentinel survives the wire unresolved.
        assert_eq!(uid_map[0].host, IdSentinel::Uid.into());
        assert_eq!(
            serde_json::to_string(&request).expect("serializable"),
            encoded
        );
    }

    #[test]
    fn every_operation_name_is_reachable_from_a_request() {
        let requests = [
            Request::ServerInfo {},
            Request::NamespaceList {},
            Request::NamespaceShow { name: name("p") },
            Request::NamespaceCreate {
                namespace: NamespaceSpec::new(name("p")),
            },
            Request::NamespaceDelete { name: name("p") },
            Request::RuleAdd {
                namespace: name("p"),
                rule: Rule::new("/a", ShareMode::Hidden),
            },
            Request::RuleRemove {
                namespace: name("p"),
                path: "/a".to_owned(),
                r#match: None,
            },
            Request::XattrAdd {
                namespace: name("p"),
                rule: XattrRule::new("*"),
            },
            Request::XattrRemove {
                namespace: name("p"),
                r#match: "*".to_owned(),
            },
            Request::OwnershipSet {
                namespace: name("p"),
                ownership: OwnershipSpec::default(),
            },
            Request::PermissionSet {
                namespace: name("p"),
                mode: PermissionMode::Passthrough,
            },
            Request::DirectIoSet {
                namespace: name("p"),
                posture: HostDirectIo::Cached,
            },
            Request::PrivilegedBitsSet {
                namespace: name("p"),
                enabled: true,
            },
            Request::AuthSet {
                namespace: name("p"),
                mode: AuthMode::None,
            },
            Request::SessionList {},
            Request::ListenerAdd {
                listener: Listener::vsock(1024),
            },
            Request::ListenerRemove {
                endpoint: "any:1024".to_owned(),
            },
        ];
        let names: Vec<&str> = requests.iter().map(Request::operation).collect();
        assert_eq!(names, OPERATIONS);
    }

    #[test]
    fn parse_failures_are_classified() {
        let malformed = parse_request(b"not json").expect_err("malformed");
        assert_eq!(malformed.code, ErrorCode::MalformedRequest);

        let unknown = parse_request(br#"{"op":"do-the-thing"}"#).expect_err("unknown operation");
        assert_eq!(unknown.code, ErrorCode::UnknownOperation);
        assert!(unknown.message.contains("do-the-thing"), "{unknown}");

        let invalid = parse_request(br#"{"op":"namespace-show"}"#).expect_err("missing field");
        assert_eq!(invalid.code, ErrorCode::InvalidRequest);

        let untagged = parse_request(br#"{"name":"p"}"#).expect_err("no operation");
        assert_eq!(untagged.code, ErrorCode::InvalidRequest);

        let bad_name = parse_request(br#"{"op":"namespace-show","name":"a/b"}"#)
            .expect_err("invalid namespace name");
        assert_eq!(bad_name.code, ErrorCode::InvalidRequest);

        let extra =
            parse_request(br#"{"op":"namespace-list","surplus":1}"#).expect_err("unknown field");
        assert_eq!(extra.code, ErrorCode::InvalidRequest);
    }
}
