/*!
 * MOQT Claims Example
 * 
 * This example demonstrates the usage of MOQT claims in CAT tokens
 * as defined in draft-law-moq-cat4moqt.md.
 * 
 * MOQT claims allow expressing fine-grained authorization for Media Over QUIC
 * Transport actions such as ANNOUNCE, SUBSCRIBE, PUBLISH, and FETCH operations
 * with namespace and track-level permissions using binary matching.
 */

use cat_impl::claims::{
    BinaryMatch, MoqtAction, MoqtScope, NamespaceMatch,
};
use cat_impl::token::CatTokenBuilder;
use cat_impl::{encode_token, decode_token};
use cat_impl::crypto::HmacSha256Algorithm;
use chrono::{Duration, Utc};

fn print_header(title: &str) {
    println!("\n{}", "=".repeat(60));
    println!("{}", title);
    println!("{}", "=".repeat(60));
}

fn demonstrate_basic_moqt_token() {
    print_header("Basic MOQT Token Example");
    
    println!("Creating a basic MOQT token with ANNOUNCE and PUBLISH permissions...");
    
    // Create a scope allowing ANNOUNCE and PUBLISH actions for example.com namespace
    // with prefix matching on /sports/ tracks
    let scope = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::Publish,
        ])
        .with_namespace_match(NamespaceMatch::exact(b"cdn.example.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/sports/".to_vec()));

    let token = CatTokenBuilder::new()
        .issuer("https://streaming-service.com")
        .audience(vec!["moqt-relay.example.com".to_string()])
        .expires_at(Utc::now() + Duration::hours(2))
        .cwt_id("sports-publisher-token")
        .moqt_scope(scope)
        .moqt_reval(300.0) // 5-minute revalidation interval
        .build();

    println!("✓ Created MOQT token");
    println!("  Issuer: https://streaming-service.com");
    println!("  Namespace: cdn.example.com (exact match)");
    println!("  Track: /sports/* (prefix match)");
    println!("  Actions: ANNOUNCE, PUBLISH");
    println!("  Revalidation: 5 minutes");
    
    // Test authorization
    println!("\nTesting authorization:");
    
    let test_cases = vec![
        (MoqtAction::PublishNamespace, "cdn.example.com".as_bytes(), "/sports/football".as_bytes(), true),
        (MoqtAction::Publish, "cdn.example.com".as_bytes(), "/sports/basketball/live".as_bytes(), true),
        (MoqtAction::Fetch, "cdn.example.com".as_bytes(), "/sports/tennis".as_bytes(), false), // Not allowed
        (MoqtAction::PublishNamespace, "other.example.com".as_bytes(), "/sports/soccer".as_bytes(), false), // Wrong namespace
        (MoqtAction::PublishNamespace, "cdn.example.com".as_bytes(), "/news/breaking".as_bytes(), false), // Wrong track prefix
    ];
    
    for (action, namespace, track, expected) in test_cases {
        let result = token.allows_moqt_action(&action, namespace, track);
        let status = if result == expected { "✓" } else { "✗" };
        println!("  {} {:?} on {}/{} -> {}", 
                 status, action, 
                 String::from_utf8_lossy(namespace),
                 String::from_utf8_lossy(track),
                 result);
    }
}

fn demonstrate_spec_examples() {
    print_header("MOQT Specification Examples");
    
    println!("Example 1: Exact match from spec - 'example.com/bob'");
    
    let exact_scope = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::exact(b"/bob".to_vec()));
    
    let exact_token = CatTokenBuilder::new()
        .issuer("https://exact-example.com")
        .moqt_scope(exact_scope)
        .build();
    
    println!("Testing exact match permissions:");
    println!("  ✓ Permits: example.com/bob");
    println!("  ✗ Prohibits: example.com/bob/123, example.com/alice, other.com/bob");
    
    assert!(exact_token.allows_moqt_action(&MoqtAction::PublishNamespace, "example.com".as_bytes(), "/bob".as_bytes()));
    assert!(!exact_token.allows_moqt_action(&MoqtAction::PublishNamespace, "example.com".as_bytes(), "/bob/123".as_bytes()));
    assert!(!exact_token.allows_moqt_action(&MoqtAction::PublishNamespace, "example.com".as_bytes(), "/alice".as_bytes()));
    
    println!("\nExample 2: Prefix match from spec - 'example.com/bob*'");
    
    let prefix_scope = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/bob".to_vec()));
    
    let prefix_token = CatTokenBuilder::new()
        .issuer("https://prefix-example.com")
        .moqt_scope(prefix_scope)
        .build();
    
    println!("Testing prefix match permissions:");
    println!("  ✓ Permits: example.com/bob, example.com/bob/123, example.com/bob/logs");
    println!("  ✗ Prohibits: example.com/alice, other.com/bob");
    
    assert!(prefix_token.allows_moqt_action(&MoqtAction::PublishNamespace, "example.com".as_bytes(), "/bob".as_bytes()));
    assert!(prefix_token.allows_moqt_action(&MoqtAction::PublishNamespace, "example.com".as_bytes(), "/bob/123".as_bytes()));
    assert!(prefix_token.allows_moqt_action(&MoqtAction::PublishNamespace, "example.com".as_bytes(), "/bob/logs".as_bytes()));
    assert!(!prefix_token.allows_moqt_action(&MoqtAction::PublishNamespace, "example.com".as_bytes(), "/alice".as_bytes()));
}

fn demonstrate_multiple_scopes() {
    print_header("Multiple MOQT Scopes Example");
    
    println!("Creating token with multiple scopes for different access patterns...");
    
    // Scope 1: Publishing live streams
    let live_scope = MoqtScope::new()
        .with_actions(vec![MoqtAction::PublishNamespace, MoqtAction::Publish])
        .with_namespace_match(NamespaceMatch::exact(b"live.example.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/stream/".to_vec()));
    
    // Scope 2: Fetching recorded content  
    let vod_scope = MoqtScope::new()
        .with_actions(vec![MoqtAction::Fetch, MoqtAction::Subscribe])
        .with_namespace_match(NamespaceMatch::exact(b"vod.example.com".to_vec()))
        .with_track_match(BinaryMatch::suffix(b".mp4".to_vec()));
    
    // Scope 3: Admin operations on tracks with admin prefix
    let admin_scope = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::TrackStatus,
        ])
        .with_namespace_match(NamespaceMatch::prefix(b"admin.".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"admin".to_vec()));
    
    let multi_token = CatTokenBuilder::new()
        .issuer("https://multi-service.com")
        .audience(vec!["unified-moqt-relay".to_string()])
        .expires_at(Utc::now() + Duration::hours(24))
        .moqt_scopes(vec![live_scope, vod_scope, admin_scope])
        .build();
    
    println!("✓ Created multi-scope token with:");
    println!("  Scope 1: Live streaming (ANNOUNCE, PUBLISH on live.example.com/stream/*)");
    println!("  Scope 2: Video on Demand (FETCH, SUBSCRIBE on vod.example.com/*.mp4)");
    println!("  Scope 3: Admin operations (multiple actions on admin.*/*admin*)");
    
    println!("\nTesting multi-scope authorization:");
    
    let test_cases = vec![
        // Live streaming tests
        (MoqtAction::PublishNamespace, "live.example.com".as_bytes(), "/stream/sports".as_bytes(), true),
        (MoqtAction::Publish, "live.example.com".as_bytes(), "/stream/news/breaking".as_bytes(), true),
        (MoqtAction::Fetch, "live.example.com".as_bytes(), "/stream/music".as_bytes(), false), // Wrong action
        
        // VOD tests  
        (MoqtAction::Fetch, "vod.example.com".as_bytes(), "movie.mp4".as_bytes(), true),
        (MoqtAction::Subscribe, "vod.example.com".as_bytes(), "series/episode1.mp4".as_bytes(), true),
        (MoqtAction::Publish, "vod.example.com".as_bytes(), "content.mp4".as_bytes(), false), // Wrong action
        (MoqtAction::Fetch, "vod.example.com".as_bytes(), "audio.mp3".as_bytes(), false), // Wrong suffix
        
        // Admin tests
        (MoqtAction::TrackStatus, "admin.example.com".as_bytes(), "admin-dashboard".as_bytes(), true),
        (MoqtAction::SubscribeNamespace, "admin.internal.net".as_bytes(), "user-admin".as_bytes(), true),
        (MoqtAction::PublishNamespace, "public.example.com".as_bytes(), "admin-panel".as_bytes(), false), // Wrong namespace prefix
    ];
    
    for (action, namespace, track, expected) in test_cases {
        let result = multi_token.allows_moqt_action(&action, namespace, track);
        let status = if result == expected { "✓" } else { "✗" };
        println!("  {} {:?} on {}/{} -> {}", 
                 status, action,
                 String::from_utf8_lossy(namespace),
                 String::from_utf8_lossy(track), 
                 result);
    }
}

fn demonstrate_token_encoding_decoding() {
    print_header("MOQT Token Encoding/Decoding Example");
    
    println!("Creating MOQT token and testing serialization...");
    
    // Create a comprehensive MOQT token
    let scope1 = MoqtScope::new()
        .with_actions(vec![MoqtAction::PublishNamespace, MoqtAction::Publish])
        .with_namespace_match(NamespaceMatch::exact(b"cdn.broadcaster.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/live/".to_vec()));
        
    let scope2 = MoqtScope::new()
        .with_actions(vec![MoqtAction::Fetch])
        .with_namespace_match(NamespaceMatch::exact(b"archive.broadcaster.com".to_vec()))
        .with_track_match(BinaryMatch::suffix(b".m4s".to_vec()));
    
    let original_token = CatTokenBuilder::new()
        .issuer("https://broadcaster.com")
        .audience(vec!["cdn-relay.net".to_string()])
        .expires_at(Utc::now() + Duration::hours(12))
        .cwt_id("broadcast-token-001")
        .moqt_scopes(vec![scope1, scope2])
        .moqt_reval(600.0) // 10 minutes
        .build();
    
    // Encode the token
    let key = HmacSha256Algorithm::generate_key();
    let algorithm = HmacSha256Algorithm::new(&key);
    
    let encoded_token = encode_token(&original_token, &algorithm).unwrap();
    println!("✓ Token encoded successfully");
    println!("  Length: {} characters", encoded_token.len());
    println!("  Parts: {}", encoded_token.split('.').count());
    
    // Decode the token
    let decoded_token = decode_token(&encoded_token, &algorithm).unwrap();
    println!("✓ Token decoded successfully");
    
    // Verify MOQT claims were preserved
    assert_eq!(decoded_token.moqt.moqt_reval, Some(600.0));
    assert!(decoded_token.moqt.moqt.is_some());
    
    let decoded_scopes = decoded_token.moqt.moqt.as_ref().unwrap();
    assert_eq!(decoded_scopes.len(), 2);
    
    println!("✓ MOQT claims preserved:");
    println!("  Revalidation interval: {} seconds", decoded_token.moqt.moqt_reval.unwrap());
    println!("  Number of scopes: {}", decoded_scopes.len());
    
    // Test that authorization still works after decoding
    assert!(decoded_token.allows_moqt_action(
        &MoqtAction::PublishNamespace, 
        "cdn.broadcaster.com".as_bytes(), 
        "/live/event123".as_bytes()
    ));
    assert!(decoded_token.allows_moqt_action(
        &MoqtAction::Fetch,
        "archive.broadcaster.com".as_bytes(),
        "recording.m4s".as_bytes()
    ));
    
    println!("✓ Authorization works correctly after decoding");
}

fn demonstrate_binary_matching_patterns() {
    print_header("Binary Matching Patterns Example");
    
    println!("Demonstrating different binary matching patterns...");
    
    // Exact match
    let exact_match = BinaryMatch::exact("live-stream".as_bytes().to_vec());
    println!("\nExact match for 'live-stream':");
    println!("  ✓ 'live-stream' -> {}", exact_match.matches("live-stream".as_bytes()));
    println!("  ✗ 'live-stream-hd' -> {}", exact_match.matches("live-stream-hd".as_bytes()));
    println!("  ✗ 'my-live-stream' -> {}", exact_match.matches("my-live-stream".as_bytes()));
    
    // Prefix match
    let prefix_match = BinaryMatch::prefix("/api/v1/".as_bytes().to_vec());
    println!("\nPrefix match for '/api/v1/':");
    println!("  ✓ '/api/v1/streams' -> {}", prefix_match.matches("/api/v1/streams".as_bytes()));
    println!("  ✓ '/api/v1/users/123' -> {}", prefix_match.matches("/api/v1/users/123".as_bytes()));
    println!("  ✗ '/api/v2/streams' -> {}", prefix_match.matches("/api/v2/streams".as_bytes()));
    println!("  ✗ '/v1/api/streams' -> {}", prefix_match.matches("/v1/api/streams".as_bytes()));
    
    // Suffix match
    let suffix_match = BinaryMatch::suffix(".webm".as_bytes().to_vec());
    println!("\nSuffix match for '.webm':");
    println!("  ✓ 'video.webm' -> {}", suffix_match.matches("video.webm".as_bytes()));
    println!("  ✓ '/path/to/stream.webm' -> {}", suffix_match.matches("/path/to/stream.webm".as_bytes()));
    println!("  ✗ 'video.mp4' -> {}", suffix_match.matches("video.mp4".as_bytes()));
    println!("  ✗ 'video.webm.tmp' -> {}", suffix_match.matches("video.webm.tmp".as_bytes()));
    
    // Note: contains match was removed from spec - only exact/prefix/suffix are supported

    // Empty match (matches everything)
    let empty_match = BinaryMatch::default();
    println!("\nEmpty match (allows all):");
    println!("  ✓ 'anything' -> {}", empty_match.matches("anything".as_bytes()));
    println!("  ✓ '' -> {}", empty_match.matches("".as_bytes()));
    println!("  ✓ '/complex/path/123' -> {}", empty_match.matches("/complex/path/123".as_bytes()));
}

fn demonstrate_revalidation_claim() {
    print_header("MOQT Revalidation Claim Example");
    
    println!("Demonstrating MOQT revalidation intervals...");
    
    // Short revalidation interval for sensitive operations
    let admin_token = CatTokenBuilder::new()
        .issuer("https://admin.example.com") 
        .moqt_scope(MoqtScope::new()
            .with_actions(vec![MoqtAction::TrackStatus, MoqtAction::SubscribeNamespace])
            .with_namespace_match(NamespaceMatch::prefix(b"admin.".to_vec()))
            .with_track_match(BinaryMatch::default()))
        .moqt_reval(60.0) // Revalidate every minute
        .build();
    
    println!("✓ Admin token: 60 second revalidation interval");
    
    // Medium revalidation interval for regular streaming
    let stream_token = CatTokenBuilder::new()
        .issuer("https://stream.example.com")
        .moqt_scope(MoqtScope::new()
            .with_actions(vec![MoqtAction::Publish, MoqtAction::PublishNamespace])
            .with_namespace_match(NamespaceMatch::exact(b"live.example.com".to_vec()))
            .with_track_match(BinaryMatch::prefix(b"/streams/".to_vec())))
        .moqt_reval(300.0) // Revalidate every 5 minutes
        .build();
    
    println!("✓ Stream token: 300 second (5 minute) revalidation interval");
    
    // Long revalidation interval for read-only access
    let readonly_token = CatTokenBuilder::new()
        .issuer("https://cdn.example.com")
        .moqt_scope(MoqtScope::new()
            .with_actions(vec![MoqtAction::Fetch, MoqtAction::Subscribe])
            .with_namespace_match(NamespaceMatch::prefix(b"public.".to_vec()))
            .with_track_match(BinaryMatch::default()))
        .moqt_reval(3600.0) // Revalidate every hour
        .build();
    
    println!("✓ Read-only token: 3600 second (1 hour) revalidation interval");
    
    // No revalidation (persistent until expiration)
    let persistent_token = CatTokenBuilder::new()
        .issuer("https://persistent.example.com")
        .moqt_scope(MoqtScope::new()
            .with_actions(vec![MoqtAction::Fetch])
            .with_namespace_match(NamespaceMatch::exact(b"archive.example.com".to_vec()))
            .with_track_match(BinaryMatch::suffix(b".mp4".to_vec())))
        // No moqt_reval claim - no revalidation required
        .build();
    
    println!("✓ Persistent token: no revalidation required");
    
    println!("\nRevalidation intervals:");
    println!("  Admin operations: {} seconds", admin_token.moqt.moqt_reval.unwrap_or(0.0));
    println!("  Live streaming: {} seconds", stream_token.moqt.moqt_reval.unwrap_or(0.0));
    println!("  Read-only access: {} seconds", readonly_token.moqt.moqt_reval.unwrap_or(0.0));
    println!("  Persistent access: {} (none)", 
             if persistent_token.moqt.moqt_reval.is_some() { "some" } else { "none" });
}

fn demonstrate_dpop_integration() {
    print_header("MOQT with DPoP Integration Example");
    
    println!("Demonstrating MOQT tokens with DPoP proof-of-possession...");
    
    // Example DPoP configuration as mentioned in the spec
    let _dpop_token = CatTokenBuilder::new()
        .issuer("https://secure-broadcaster.com")
        .audience(vec!["secure-relay.net".to_string()])
        .expires_at(Utc::now() + Duration::hours(4))
        .confirmation(b"test_key_thumbprint_32bytes_xxx".to_vec()) // Example JWK thumbprint (32 bytes)
        .dpop_settings(cat_impl::CatDpopSettings::new().with_window(300).with_jti_processing(true))
        .moqt_scope(MoqtScope::new()
            .with_actions(vec![MoqtAction::PublishNamespace, MoqtAction::Publish])
            .with_namespace_match(NamespaceMatch::exact(b"cdn.example.com".to_vec()))
            .with_track_match(BinaryMatch::prefix(b"/sports/".to_vec())))
        .build();
    
    println!("✓ Created DPoP-enabled MOQT token");
    println!("  JWK Thumbprint binding: enabled");
    println!("  DPoP window: 300 seconds");
    println!("  Replay protection (jti): enabled");
    println!("  MOQT actions: ANNOUNCE, PUBLISH");
    
    println!("\nDPoP Integration Benefits:");
    println!("  🔒 Token binding to client key pair");
    println!("  🔄 Fresh DPoP proofs required for each action");
    println!("  🛡️  Theft prevention (stolen tokens unusable)");
    println!("  ✅ Enhanced trust verification");
    
    println!("\nMOQT Action to HTTP Method Mapping (for DPoP):");
    println!("  CLIENT_SETUP    -> POST");
    println!("  SERVER_SETUP    -> POST");
    println!("  ANNOUNCE        -> PUT");
    println!("  SUBSCRIBE_NAMESPACE -> GET");
    println!("  SUBSCRIBE       -> GET");
    println!("  PUBLISH         -> POST");
    println!("  FETCH           -> GET");
}

fn main() {
    println!("MOQT CAT Claims Examples");
    println!("Based on draft-law-moq-cat4moqt.md");
    
    demonstrate_basic_moqt_token();
    demonstrate_spec_examples();
    demonstrate_multiple_scopes();
    demonstrate_token_encoding_decoding();
    demonstrate_binary_matching_patterns();
    demonstrate_revalidation_claim();
    demonstrate_dpop_integration();
    
    print_header("Summary");
    println!("MOQT claims provide fine-grained authorization for Media Over QUIC:");
    println!("📋 Action-based permissions (ANNOUNCE, SUBSCRIBE, PUBLISH, FETCH, etc.)");
    println!("🎯 Binary namespace and track matching (exact, prefix, suffix, contains)");
    println!("🔄 Optional revalidation intervals for dynamic security");
    println!("🔐 Integration with DPoP for proof-of-possession");
    println!("📊 Multiple scopes for complex authorization scenarios");
    println!("🔧 Comprehensive encoding/decoding with full CBOR serialization");
    println!("\nMOQT claims enable secure, scalable media distribution with");
    println!("precise access control at the namespace and track level.");
}