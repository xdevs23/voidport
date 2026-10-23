use std::collections::BTreeMap;
use voidport_lkml::{
    mail::{self, Basis, Class},
    storage::digest,
};

fn policy() -> Vec<mail::Mailbox> {
    mail::authors(
        &mail::DEFAULT_AUTHORS
            .iter()
            .map(|a| (*a).into())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
fn parse(headers: &str) -> mail::Metadata {
    mail::interpret(format!("{headers}\r\nSubject: example\r\n\r\nFrom literal\r\n>From literal\r\n>>From literal\r\n").as_bytes(), &policy())
}

#[test]
fn sender_policy_and_exact_classes() {
    for author in mail::DEFAULT_AUTHORS {
        assert_eq!(
            parse(&format!("From: {author}")).class,
            Class::UnlinkedAuthor
        );
    }
    for (from, expected) in [
        ("From: torvalds@OSDL.ORG", Class::UnlinkedAuthor),
        ("From: Torvalds@osdl.org", Class::Context),
        (
            "From: Linus Torvalds <other@example.invalid>",
            Class::Context,
        ),
        ("From: Linus Torvalds", Class::AmbiguousFrom),
        ("From: torvalds@osdl.org.attacker.invalid", Class::Context),
        (
            "From: torvalds@osdl.org\r\nFrom: torvalds@osdl.org",
            Class::AmbiguousFrom,
        ),
        (
            "From: torvalds@osdl.org, other@example.invalid",
            Class::AmbiguousFrom,
        ),
        ("Date: Tue, 1 Jan 2019 00:00:00 +0000", Class::AmbiguousFrom),
    ] {
        assert_eq!(parse(from).class, expected, "{from}");
    }
    assert_eq!(parse("").class, Class::Invalid);
    let custom = mail::authors(&["custom@example.invalid".into()]).unwrap();
    for (source, spelling, local, class) in [
        (
            "custom@EXAMPLE.INVALID",
            "custom@EXAMPLE.INVALID",
            "custom",
            Class::UnlinkedAuthor,
        ),
        (
            "Custom <custom@EXAMPLE.INVALID>",
            "custom@EXAMPLE.INVALID",
            "custom",
            Class::UnlinkedAuthor,
        ),
        (
            "Custom <Custom@EXAMPLE.INVALID>",
            "Custom@EXAMPLE.INVALID",
            "Custom",
            Class::Context,
        ),
    ] {
        let metadata = mail::interpret(format!("From: {source}\r\n\r\nbody").as_bytes(), &custom);
        assert_eq!(metadata.class, class);
        let from = metadata.from.unwrap();
        assert_eq!(from.spelling, spelling);
        assert_eq!(from.local, local);
        assert_eq!(from.domain, "example.invalid");
    }
    assert!(mail::Mailbox::parse("display name only").is_err());
    assert_eq!(
        parse("From: torvalds@osdl.org\r\nIn-Reply-To: <parent@example.invalid>").class,
        Class::Response
    );
    assert_eq!(
        parse("From: torvalds@osdl.org\r\nIn-Reply-To: broken").class,
        Class::AmbiguousReply
    );
    assert_eq!(
        mail::interpret(b"<html>denied</html>", &policy()).class,
        Class::Invalid
    );
    assert_eq!(
        mail::interpret(b"\xff\0garbage", &policy()).class,
        Class::Invalid
    );
}

#[test]
fn every_occurrence_is_inspected_and_reply_absence_is_not_malformed() {
    let duplicate = parse(
        "From: torvalds@osdl.org\r\nMessage-ID: <first@example.invalid>\r\nMessage-ID: <second@example.invalid>",
    );
    assert_eq!(duplicate.message_ids.len(), 2);
    assert_eq!(duplicate.message_ids[0].values, ["first@example.invalid"]);
    assert_eq!(duplicate.message_ids[1].values, ["second@example.invalid"]);
    assert_eq!(duplicate.primary_id, None);
    assert!(duplicate.ambiguities.contains(&"message_id".into()));
    assert!(parse("From: torvalds@osdl.org").message_ids.is_empty());
    for fields in [
        "In-Reply-To: broken",
        "In-Reply-To: <p@example.invalid> <q@example.invalid>",
        "In-Reply-To: <p@example.invalid>\r\nIn-Reply-To: <p@example.invalid>",
        "References: broken",
        "References: <p@example.invalid>\r\nReferences: <p@example.invalid>",
        "In-Reply-To: <p@example.invalid>\r\nReferences: <q@example.invalid>",
        "In-Reply-To: broken\r\nReferences: <p@example.invalid>",
        "In-Reply-To: <p@example.invalid>\r\nReferences: broken",
    ] {
        let value = parse(&format!("From: torvalds@osdl.org\r\n{fields}"));
        assert_eq!(value.class, Class::AmbiguousReply, "{fields}");
        assert!(value.parent.is_none(), "{fields}");
    }
    let references = parse(
        "From: torvalds@osdl.org\r\nReferences: <root@example.invalid>\r\n <parent@example.invalid>",
    );
    assert_eq!(
        references.references[0].values,
        ["root@example.invalid", "parent@example.invalid"]
    );
    assert_eq!(references.parent.unwrap().basis, Basis::References);
    let direct = parse(
        "From: torvalds@osdl.org\r\nIn-Reply-To: <parent@example.invalid>\r\nReferences: <root@example.invalid> <parent@example.invalid>",
    );
    assert_eq!(direct.parent.unwrap().basis, Basis::Direct);
}

#[test]
fn id_usability_keeps_original_values_without_minting_malformed_links() {
    for (token, expected) in [
        ("broken", vec!["broken"]),
        ("parent@example.invalid", vec!["parent@example.invalid"]),
        ("<parent@example.invalid", vec![]),
        (
            "<parent@example.invalid> broken",
            vec!["parent@example.invalid"],
        ),
    ] {
        let parsed = parse(&format!(
            "From: torvalds@osdl.org\r\nMessage-ID: {token}\r\nIn-Reply-To: {token}\r\nReferences: {token}"
        ));
        assert_eq!(parsed.class, Class::AmbiguousReply, "{token}");
        assert!(parsed.primary_id.is_none());
        assert!(parsed.parent.is_none());
        for field in [
            &parsed.message_ids[0],
            &parsed.in_reply_to[0],
            &parsed.references[0],
        ] {
            assert!(!field.usable, "{token}");
            assert_eq!(field.values, expected, "{token}");
        }
        if token == "broken" {
            assert_eq!(parsed.message_ids[0].values, ["broken"]);
            assert_eq!(parsed.in_reply_to[0].values, ["broken"]);
            assert_eq!(parsed.references[0].values, ["broken"]);
        }
        let index = mail::links(&BTreeMap::from([("artifact".into(), parsed)]));
        assert!(index.message_ids.is_empty());
        assert!(index.relationships.is_empty());
    }
    // Message-ID is not an email mailbox: no DNS label or local-part length cap.
    for id in [
        "parent@example.invalid".to_string(),
        "parent@under_score.!right".to_string(),
        "parent@[literal-not-an-ip]".to_string(),
        format!("{}@example.invalid", "x".repeat(80)),
    ] {
        for newline in ["\r\n", "\n"] {
            let bytes = format!(
                "From: torvalds@osdl.org{newline}Message-ID: <{id}>{newline}References: <root@example.invalid>{newline} <{id}>{newline}{newline}body"
            );
            let parsed = mail::interpret(bytes.as_bytes(), &policy());
            assert_eq!(parsed.primary_id.as_deref(), Some(id.as_str()));
            assert!(parsed.message_ids[0].usable);
            assert!(parsed.references[0].usable);
            assert_eq!(parsed.references[0].values, ["root@example.invalid", &id]);
            assert_eq!(
                parsed.parent,
                Some(mail::Candidate {
                    id: id.clone(),
                    basis: Basis::References
                })
            );
            assert_eq!(parsed.class, Class::Response);
        }
    }
}

#[test]
fn variants_later_parents_and_cycles_have_finite_exact_links() {
    let child = parse(
        "From: torvalds@osdl.org\r\nMessage-ID: <child@example.invalid>\r\nIn-Reply-To: <parent@example.invalid>",
    );
    let mut messages = BTreeMap::from([("child".into(), child)]);
    let missing = mail::links(&messages);
    assert!(missing.relationships["child"].targets.is_empty());
    assert_eq!(
        missing.relationships["child"]
            .missing
            .iter()
            .collect::<Vec<_>>(),
        [&"parent@example.invalid".to_string()]
    );
    let parent = parse(
        "From: other@example.invalid\r\nMessage-ID: <parent@example.invalid>\r\nIn-Reply-To: <child@example.invalid>",
    );
    messages.insert("parent-a".into(), parent.clone());
    messages.insert("parent-b".into(), parent);
    let resolved = mail::links(&messages);
    assert_eq!(
        resolved.message_ids["parent@example.invalid"],
        ["parent-a", "parent-b"]
    );
    assert_eq!(
        resolved.relationships["child"].targets,
        ["parent-a", "parent-b"]
    );
    assert_eq!(resolved.relationships["child"].ancestors.len(), 3);
    assert_eq!(
        resolved.relationships["child"]
            .cycles
            .iter()
            .collect::<Vec<_>>(),
        [&"child".to_string()]
    );
    assert!(resolved.relationships["child"].missing.is_empty());
}

fn thread_messages() -> BTreeMap<String, mail::Metadata> {
    let message = |headers: &str| parse(&format!("From: torvalds@osdl.org\r\n{headers}"));
    let root = message("Message-ID: <root@example.invalid>");
    let copy = message("Message-ID: <copy@example.invalid>");
    BTreeMap::from([
        ("a-root".into(), root.clone()),
        (
            "b-reply".into(),
            message("Message-ID: <reply@example.invalid>\r\nIn-Reply-To: <root@example.invalid>"),
        ),
        (
            "c-nested".into(),
            message(
                "Message-ID: <nested@example.invalid>\r\nReferences: <root@example.invalid> <reply@example.invalid>",
            ),
        ),
        ("d-variant".into(), root),
        (
            "e-orphan".into(),
            message("Message-ID: <orphan@example.invalid>\r\nIn-Reply-To: <gone@example.invalid>"),
        ),
        (
            "f-single".into(),
            message("Message-ID: <single@example.invalid>"),
        ),
        (
            "g-cycle".into(),
            message("Message-ID: <g@example.invalid>\r\nIn-Reply-To: <h@example.invalid>"),
        ),
        (
            "h-cycle".into(),
            message("Message-ID: <h@example.invalid>\r\nIn-Reply-To: <g@example.invalid>"),
        ),
        (
            "i-start".into(),
            message("Message-ID: <start@example.invalid>"),
        ),
        (
            "j-gap".into(),
            message(
                "Message-ID: <gap@example.invalid>\r\nIn-Reply-To: <middle@example.invalid>\r\nReferences: <start@example.invalid> <middle@example.invalid>",
            ),
        ),
        (
            "k-sibling".into(),
            message("Message-ID: <k@example.invalid>\r\nIn-Reply-To: <absent@example.invalid>"),
        ),
        (
            "l-sibling".into(),
            message("Message-ID: <l@example.invalid>\r\nIn-Reply-To: <absent@example.invalid>"),
        ),
        ("m-copy".into(), copy.clone()),
        ("n-copy".into(), copy),
        (
            "o-present".into(),
            message("Message-ID: <o@example.invalid>"),
        ),
        (
            "p-two-ids".into(),
            message(
                "Message-ID: <p@example.invalid>\r\nIn-Reply-To: <o@example.invalid> <q@example.invalid>",
            ),
        ),
    ])
}

#[test]
fn threads_join_artifacts_through_message_ids() {
    let thread = |roots: &[&str], members: &[&str]| mail::Thread {
        roots: roots.iter().map(|digest| (*digest).into()).collect(),
        members: members.iter().map(|digest| (*digest).into()).collect(),
    };
    let threads = mail::links(&thread_messages()).threads;
    assert!(
        threads
            .iter()
            .all(|(key, thread)| thread.members.first() == Some(key))
    );
    assert_eq!(
        threads.into_values().collect::<Vec<_>>(),
        [
            thread(
                &["a-root", "d-variant"],
                &["a-root", "b-reply", "c-nested", "d-variant"]
            ),
            thread(&["e-orphan"], &["e-orphan"]),
            thread(&["f-single"], &["f-single"]),
            thread(&[], &["g-cycle", "h-cycle"]),
            thread(&["i-start", "j-gap"], &["i-start", "j-gap"]),
            thread(&["k-sibling", "l-sibling"], &["k-sibling", "l-sibling"]),
            thread(&["m-copy", "n-copy"], &["m-copy", "n-copy"]),
            thread(&["o-present", "p-two-ids"], &["o-present", "p-two-ids"]),
        ]
    );
}

#[test]
fn changes_of_the_joined_threads_fold_into_the_links_of_the_whole() {
    let messages = thread_messages();
    let mut added = BTreeMap::new();
    let mut mentions = mail::Mentions::default();
    let mut links = mail::Links::default();
    for (digest, message) in messages.iter().rev() {
        added.extend([(digest.clone(), message.clone())]);
        mentions.add(digest, message);
        let members = mentions.thread_members([digest]);
        let recomputed = mail::links(members.into_iter().map(|member| (member, &added[member])));
        links.fold(links.changes(recomputed));
        assert_eq!(links, mail::links(&added), "after {digest}");
    }
}

#[test]
fn multipart_is_one_message_and_body_fidelity_is_not_mbox_conversion() {
    let raw = b"From: torvalds@osdl.org\r\nMessage-ID: <mime@example.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nFrom literal\r\n>From literal\r\n>>From literal\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>body</p>\r\n--x--\r\n";
    let parsed = mail::interpret(raw, &policy());
    assert_eq!(parsed.class, Class::UnlinkedAuthor);
    assert_eq!(parsed.text.len(), 1);
    assert_eq!(parsed.html.len(), 1);
    assert!(parsed.text[0].contains("From literal\r\n>From literal\r\n>>From literal"));
    assert_eq!(parsed.primary_id.as_deref(), Some("mime@example.invalid"));
    assert_eq!(
        digest(raw),
        "4009a53359cbdcfa2bb4e82c32893339347c796789a9bc2eb11592217dc449ca"
    );
}
