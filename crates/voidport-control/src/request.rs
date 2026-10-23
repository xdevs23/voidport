//! One line of JSON is one [`Request`], tagged by an `op` field. A modification
//! of a rule is a remove followed by an add.

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
        /// Lets parsing tell an unknown operation from invalid arguments for a
        /// known one.
        pub const OPERATIONS: &[&str] = &[$($operation),+];

        /// Mutating variants carry policy in its [source form](crate::policy).
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
    ServerInfo {} => "server-info",
    NamespaceList {} => "namespace-list",
    NamespaceShow {
        name: NamespaceName,
    } => "namespace-show",
    NamespaceCreate {
        namespace: NamespaceSpec,
    } => "namespace-create",
    /// Deletes a namespace. Sessions already resolved against it keep their
    /// snapshot; new handshakes fail.
    NamespaceDelete {
        name: NamespaceName,
    } => "namespace-delete",
    RuleAdd {
        namespace: NamespaceName,
        rule: Rule,
    } => "rule-add",
    RuleRemove {
        namespace: NamespaceName,
        path: String,
        /// A rule is keyed by the pair of path and match. Absent removes the
        /// rule that has no match.
        #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
        r#match: Option<String>,
    } => "rule-remove",
    XattrAdd {
        namespace: NamespaceName,
        rule: XattrRule,
    } => "xattr-add",
    XattrRemove {
        namespace: NamespaceName,
        #[serde(rename = "match")]
        r#match: String,
    } => "xattr-remove",
    OwnershipSet {
        namespace: NamespaceName,
        ownership: OwnershipSpec,
    } => "ownership-set",
    PermissionSet {
        namespace: NamespaceName,
        mode: PermissionMode,
    } => "permission-set",
    /// Live at the next open: descriptions already open still have the posture
    /// they were opened with.
    DirectIoSet {
        namespace: NamespaceName,
        posture: HostDirectIo,
    } => "direct-io-set",
    /// Off, presentation masks them and a chmod attempting to set them is
    /// refused. The recorded bits are kept, so turning the switch back on
    /// presents them again.
    PrivilegedBitsSet {
        namespace: NamespaceName,
        enabled: bool,
    } => "privileged-bits-set",
    AuthSet {
        namespace: NamespaceName,
        mode: AuthMode,
    } => "auth-set",
    SessionList {} => "session-list",
    /// The reply shows the endpoint it actually bound, which is the name
    /// `listener-remove` takes.
    ListenerAdd {
        listener: Listener,
    } => "listener-add",
    /// Sessions already accepted on it keep serving and end by the ordinary
    /// connection-death rules.
    ListenerRemove {
        endpoint: String,
    } => "listener-remove",
    /// Resolves one path under the rules of a namespace. Changes nothing.
    Resolve {
        namespace: NamespaceName,
        path: String,
    } => "resolve",
}

/// Parses one request line. The three failure classes (not JSON, unknown
/// operation, wrong arguments) are answered with a structured error and the
/// connection lives on.
///
/// # Errors
///
/// A [`ControlError`] with [`ErrorCode::MalformedRequest`],
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
            (
                Request::Resolve {
                    namespace: name("p"),
                    path: "/a/b".to_owned(),
                },
                r#"{"op":"resolve","namespace":"p","path":"/a/b"}"#,
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
            Request::Resolve {
                namespace: name("p"),
                path: "/".to_owned(),
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
