use cat_impl::*;
use chrono::Utc;

#[test]
fn test_core_claims() {
    let token = CatToken::new()
        .with_issuer("https://issuer.example.com")
        .with_audience(vec!["audience1".to_string(), "audience2".to_string()])
        .with_expiration(Utc::now() + chrono::Duration::hours(1))
        .with_not_before(Utc::now() - chrono::Duration::minutes(5))
        .with_cwt_id("unique-token-id".to_string());

    assert_eq!(
        token.core.iss,
        Some("https://issuer.example.com".to_string())
    );
    assert!(
        token
            .core
            .aud
            .as_ref()
            .unwrap()
            .contains(&"audience1".to_string())
    );
    assert!(
        token
            .core
            .aud
            .as_ref()
            .unwrap()
            .contains(&"audience2".to_string())
    );
    assert!(token.core.exp.is_some());
    assert!(token.core.nbf.is_some());
    assert_eq!(token.core.cti, Some("unique-token-id".to_string()));
}

#[test]
fn test_cat_claims() {
    let token = CatToken::new()
        .with_version("1.0")
        .with_usage_limit(100)
        .with_replay_protection("nonce-12345")
        .with_proof_of_possession(true)
        .with_geo_coordinate(37.7749, -122.4194, Some(10.0))
        .with_geohash("9q8yy");

    assert_eq!(token.cat.catv, Some("1.0".to_string()));
    assert_eq!(token.cat.catu, Some(100));
    assert_eq!(token.cat.catreplay, Some("nonce-12345".to_string()));
    assert_eq!(token.cat.catpor, Some(true));

    assert!(token.cat.catgeocoord.is_some());
    let coords = token.cat.catgeocoord.unwrap();
    assert_eq!(coords.lat, 37.7749);
    assert_eq!(coords.lon, -122.4194);
    assert_eq!(coords.accuracy, Some(10.0));

    assert_eq!(token.cat.geohash, Some("9q8yy".to_string()));
}

#[test]
fn test_informational_claims() {
    let iat = Utc::now();
    let token = CatToken::new()
        .with_subject("user123")
        .with_issued_at(iat)
        .with_interface_data("interface-data");

    assert_eq!(token.informational.sub, Some("user123".to_string()));
    assert_eq!(token.informational.iat, Some(iat.timestamp()));
    assert_eq!(
        token.informational.catifdata,
        Some("interface-data".to_string())
    );
}

#[test]
fn test_dpop_claims() {
    let token = CatToken::new()
        .with_confirmation("confirmation-key")
        .with_dpop_claim("dpop-data");

    assert_eq!(token.dpop.cnf, Some("confirmation-key".to_string()));
    assert_eq!(token.dpop.catdpop, Some("dpop-data".to_string()));
}

#[test]
fn test_request_claims() {
    let token = CatToken::new()
        .with_interface_claim("interface123")
        .with_request_claim("request456");

    assert_eq!(token.request.catif, Some("interface123".to_string()));
    assert_eq!(token.request.catr, Some("request456".to_string()));
}

#[test]
fn test_uri_patterns() {
    let patterns = vec![
        UriPattern::Exact("https://api.example.com".to_string()),
        UriPattern::Prefix("https://".to_string()),
        UriPattern::Suffix(".json".to_string()),
        UriPattern::Regex(r"^https://.*\.example\.com$".to_string()),
        UriPattern::Hash("hash123".to_string()),
    ];

    let token = CatToken::new().with_uri_patterns(patterns.clone());
    assert_eq!(token.cat.cath, Some(patterns));
}

#[test]
fn test_token_builder() {
    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["client1".to_string()])
        .expires_at(Utc::now() + chrono::Duration::hours(2))
        .version("2.0")
        .subject("user456")
        .confirmation("conf-key")
        .interface_claim("if789")
        .build();

    assert_eq!(token.core.iss, Some("https://auth.example.com".to_string()));
    assert_eq!(token.cat.catv, Some("2.0".to_string()));
    assert_eq!(token.informational.sub, Some("user456".to_string()));
    assert_eq!(token.dpop.cnf, Some("conf-key".to_string()));
    assert_eq!(token.request.catif, Some("if789".to_string()));
}

#[test]
fn test_geo_coordinate_validation() {
    // Valid coordinates
    let coord1 = GeoCoordinate {
        lat: 45.0,
        lon: 90.0,
        accuracy: None,
    };
    assert!(coord1.lat.abs() <= 90.0);
    assert!(coord1.lon.abs() <= 180.0);

    // Edge case coordinates
    let coord2 = GeoCoordinate {
        lat: -90.0,
        lon: -180.0,
        accuracy: Some(5.0),
    };
    assert!(coord2.lat.abs() <= 90.0);
    assert!(coord2.lon.abs() <= 180.0);

    let coord3 = GeoCoordinate {
        lat: 90.0,
        lon: 180.0,
        accuracy: Some(0.1),
    };
    assert!(coord3.lat.abs() <= 90.0);
    assert!(coord3.lon.abs() <= 180.0);
}

#[test]
fn test_claim_constants() {
    // Core claims
    assert_eq!(CLAIM_ISS, 1);
    assert_eq!(CLAIM_AUD, 3);
    assert_eq!(CLAIM_EXP, 4);
    assert_eq!(CLAIM_NBF, 5);
    assert_eq!(CLAIM_CTI, 7);

    // CAT claims
    assert_eq!(CLAIM_CATREPLAY, 33001);
    assert_eq!(CLAIM_CATPOR, 33002);
    assert_eq!(CLAIM_CATV, 33003);
    assert_eq!(CLAIM_CATNIP, 33004);
    assert_eq!(CLAIM_CATU, 33005);

    // New claims
    assert_eq!(CLAIM_SUB, 33000);
    assert_eq!(CLAIM_IAT, 33014);
    assert_eq!(CLAIM_CATIFDATA, 33020);
    assert_eq!(CLAIM_CNF, 8);
    assert_eq!(CLAIM_CATDPOP, 33015);
    assert_eq!(CLAIM_CATIF, 33016);
    assert_eq!(CLAIM_CATR, 33017);
}
