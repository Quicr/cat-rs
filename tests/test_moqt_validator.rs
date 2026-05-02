// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_impl::moqt::{MoqtAuthRequest, MoqtScopeBuilder, MoqtValidator, roles};
use cat_impl::*;
use chrono::{Duration, Utc};

#[test]
fn test_moqt_validator_spec_example_exact_match() {
    // Example from spec: Allow with an exact match "example.com/bob"
    let scope = MoqtScopeBuilder::new()
        .actions(&[
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .namespace_exact(b"example.com")
        .track_exact(b"/bob")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://spec-example.com")
        .moqt_scope(scope)
        .build();

    let validator = MoqtValidator::new();

    // Should permit exact match
    let request = MoqtAuthRequest::simple(MoqtAction::PublishNamespace, b"example.com", b"/bob");
    assert!(validator.authorize(&token, &request).authorized);

    // Should prohibit - various mismatches
    let test_cases = vec![
        (b"example.com".to_vec(), b"".to_vec()),
        (b"example.com".to_vec(), b"/bob/123".to_vec()),
        (b"example.com".to_vec(), b"/alice".to_vec()),
        (b"example.com".to_vec(), b"/bob/logs".to_vec()),
        (b"alternate/example.com".to_vec(), b"/bob".to_vec()),
    ];

    for (ns, track) in test_cases {
        let request = MoqtAuthRequest::simple(MoqtAction::PublishNamespace, &ns, &track);
        assert!(
            !validator.authorize(&token, &request).authorized,
            "Should deny ns={:?} track={:?}",
            String::from_utf8_lossy(&ns),
            String::from_utf8_lossy(&track)
        );
    }
}

#[test]
fn test_moqt_validator_spec_example_prefix_match() {
    // Example from spec: Allow with a prefix match "example.com/bob*"
    let scope = MoqtScopeBuilder::new()
        .actions(&[
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .namespace_exact(b"example.com")
        .track_prefix(b"/bob")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://spec-example.com")
        .moqt_scope(scope)
        .build();

    let validator = MoqtValidator::new();

    // Should permit - various prefix matches
    let permit_cases: Vec<(&[u8], &[u8])> = vec![
        (b"example.com", b"/bob"),
        (b"example.com", b"/bob/123"),
        (b"example.com", b"/bob/logs"),
        (b"example.com", b"/bobby"),
    ];

    for (ns, track) in permit_cases {
        let request = MoqtAuthRequest::simple(MoqtAction::PublishNamespace, ns, track);
        assert!(
            validator.authorize(&token, &request).authorized,
            "Should permit ns={:?} track={:?}",
            String::from_utf8_lossy(ns),
            String::from_utf8_lossy(track)
        );
    }

    // Should prohibit
    let deny_cases: Vec<(&[u8], &[u8])> =
        vec![(b"example.com", b"/alice"), (b"other.com", b"/bob")];

    for (ns, track) in deny_cases {
        let request = MoqtAuthRequest::simple(MoqtAction::PublishNamespace, ns, track);
        assert!(
            !validator.authorize(&token, &request).authorized,
            "Should deny ns={:?} track={:?}",
            String::from_utf8_lossy(ns),
            String::from_utf8_lossy(track)
        );
    }
}

#[test]
fn test_moqt_validator_multiple_scopes() {
    // Create multiple scopes with different permissions
    let pub_scope = roles::publisher(b"cdn.example.com", b"/live/");
    let sub_scope = roles::subscriber(b"cdn.example.com", b"/vod/");

    let token = CatTokenBuilder::new()
        .issuer("https://multi-scope.com")
        .audience(vec!["relay".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .moqt_scopes(vec![pub_scope, sub_scope])
        .build();

    let validator = MoqtValidator::new();

    // Publisher can publish to /live/
    let request =
        MoqtAuthRequest::simple(MoqtAction::Publish, b"cdn.example.com", b"/live/stream1");
    let result = validator.authorize(&token, &request);
    assert!(result.authorized);
    assert_eq!(result.matched_scope_index, Some(0));

    // Publisher cannot publish to /vod/
    let request = MoqtAuthRequest::simple(MoqtAction::Publish, b"cdn.example.com", b"/vod/movie1");
    assert!(!validator.authorize(&token, &request).authorized);

    // Subscriber can fetch from /vod/
    let request = MoqtAuthRequest::simple(MoqtAction::Fetch, b"cdn.example.com", b"/vod/movie1");
    let result = validator.authorize(&token, &request);
    assert!(result.authorized);
    assert_eq!(result.matched_scope_index, Some(1));

    // Subscriber cannot fetch from /live/
    let request = MoqtAuthRequest::simple(MoqtAction::Fetch, b"cdn.example.com", b"/live/stream1");
    assert!(!validator.authorize(&token, &request).authorized);
}

#[test]
fn test_moqt_validator_revalidation_required() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(300.0) // 5 minute revalidation
        .build();

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::simple(MoqtAction::Publish, b"example.com", b"/stream");
    let result = validator.authorize(&token, &request);

    assert!(result.authorized);
    assert!(result.requires_revalidation);
    assert_eq!(result.revalidation_interval, Some(300.0));
}

#[test]
fn test_moqt_validator_revalidation_zero() {
    // When moqt-reval is 0, token must not be revalidated
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(0.0)
        .build();

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::simple(MoqtAction::Publish, b"example.com", b"/stream");
    let result = validator.authorize(&token, &request);

    assert!(result.authorized);
    assert!(!result.requires_revalidation); // 0 means no revalidation
    assert_eq!(result.revalidation_interval, Some(0.0));
}

#[test]
fn test_moqt_validator_claims_validation() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    // Token with short revalidation interval
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope.clone())
        .moqt_reval(30.0) // 30 seconds
        .build();

    // Validator that requires at least 60 seconds
    let validator = MoqtValidator::new().with_min_revalidation_interval(60.0);

    let result = validator.validate_moqt_claims(&token);
    assert!(matches!(
        result,
        Err(CatError::RevalidationIntervalTooShort)
    ));

    // Token with acceptable revalidation interval
    let token2 = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(120.0) // 2 minutes
        .build();

    let result = validator.validate_moqt_claims(&token2);
    assert!(result.is_ok());
}

#[test]
fn test_moqt_validator_no_revalidation_support() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(300.0)
        .build();

    // Validator that doesn't support revalidation
    let validator = MoqtValidator::new().without_revalidation_support();

    let result = validator.validate_moqt_claims(&token);
    assert!(matches!(result, Err(CatError::RevalidationRequired)));
}

#[test]
fn test_moqt_scope_builder() {
    // Test the fluent builder API
    let scope = MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .action(MoqtAction::Fetch)
        .namespace_exact(b"cdn.example.com")
        .namespace_nil() // End of namespace
        .track_prefix(b"/stream/")
        .build();

    assert_eq!(scope.actions.len(), 2);
    assert!(scope.allows_action(&MoqtAction::Publish));
    assert!(scope.allows_action(&MoqtAction::Fetch));
    assert!(!scope.allows_action(&MoqtAction::Subscribe));
    assert_eq!(scope.namespace_matches.len(), 2);
    assert!(scope.track_match.is_some());
}

#[test]
fn test_moqt_roles() {
    // Test predefined roles
    let pub_scope = roles::publisher(b"example.com", b"/live/");
    assert!(pub_scope.allows_action(&MoqtAction::Publish));
    assert!(pub_scope.allows_action(&MoqtAction::PublishNamespace));
    assert!(!pub_scope.allows_action(&MoqtAction::Fetch));

    let sub_scope = roles::subscriber(b"example.com", b"/vod/");
    assert!(sub_scope.allows_action(&MoqtAction::Subscribe));
    assert!(sub_scope.allows_action(&MoqtAction::Fetch));
    assert!(!sub_scope.allows_action(&MoqtAction::Publish));

    let admin_scope = roles::admin(b"example.com");
    assert!(admin_scope.allows_action(&MoqtAction::Publish));
    assert!(admin_scope.allows_action(&MoqtAction::Subscribe));
    assert!(admin_scope.allows_action(&MoqtAction::TrackStatus));

    let ro_scope = roles::read_only(b"example.com", b"/archive/");
    assert!(ro_scope.allows_action(&MoqtAction::Subscribe));
    assert!(ro_scope.allows_action(&MoqtAction::Fetch));
    assert!(!ro_scope.allows_action(&MoqtAction::Publish));
    assert!(!ro_scope.allows_action(&MoqtAction::PublishNamespace));
}

#[test]
fn test_moqt_default_blocked() {
    // "The default for all actions is 'Blocked'"
    let token = CatTokenBuilder::new().issuer("https://test.com").build(); // No MOQT scopes

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::simple(MoqtAction::Publish, b"example.com", b"/stream");
    let result = validator.authorize(&token, &request);

    assert!(!result.authorized);
    assert!(result.matched_scope_index.is_none());
}

#[test]
fn test_moqt_empty_scopes() {
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scopes(vec![]) // Empty scopes array
        .build();

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::simple(MoqtAction::Publish, b"example.com", b"/stream");
    let result = validator.authorize(&token, &request);

    assert!(!result.authorized);
}
