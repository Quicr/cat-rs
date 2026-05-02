use cat_impl::*;
use chrono::{Duration, Utc};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn create_simple_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec!["client1".to_string(), "client2".to_string()])
        .with_expiration(exp)
        .with_not_before(now)
        .with_cwt_id("token-12345")
        .with_version("1.0.0")
        .with_subject("user@example.com")
        .with_issued_at(now)
}

fn create_complex_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    let iat = now - Duration::minutes(1);

    let uri_patterns = vec![
        UriPattern::Exact("https://api.example.com".to_string()),
        UriPattern::Prefix("https://secure.".to_string()),
        UriPattern::Suffix("/api/v1".to_string()),
        UriPattern::Regex(r"^https://.*\.test\.com$".to_string()),
        UriPattern::Hash("abcdef123456".to_string()),
    ];

    CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec![
            "client1".to_string(),
            "client2".to_string(),
            "mobile-app".to_string(),
        ])
        .with_expiration(exp)
        .with_not_before(now)
        .with_cwt_id("token-12345")
        .with_version("1.2.0")
        .with_usage_limit(500)
        .with_replay_protection("nonce-67890")
        .with_proof_of_possession(true)
        .with_geo_coordinate(40.7128, -74.0060, Some(100.0))
        .with_geohash("dr5regw")
        .with_uri_patterns(uri_patterns)
        .with_subject("user@example.com")
        .with_issued_at(iat)
        .with_interface_data("mobile-interface-v2")
        .with_confirmation(b"jwk-thumbprint-xyz".to_vec())
        .with_dpop_settings(cat_impl::CatDpopSettings::new().with_window(300))
        .with_interface_claim("auth-interface")
        .with_request_claim("login-request-abc")
        .with_ip_address("192.168.1.100")
        .with_ip_range("10.0.0.0/8")
        .with_asn(64512)
        .with_asn_range(64512, 65535)
}

fn bench_token_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_creation");

    group.bench_function("simple_token", |b| {
        b.iter(|| black_box(create_simple_token()))
    });

    group.bench_function("complex_token", |b| {
        b.iter(|| black_box(create_complex_token()))
    });

    group.finish();
}

fn bench_token_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_validation");

    let simple_token = create_simple_token();
    let complex_token = create_complex_token();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://auth.example.com".to_string()])
        .with_expected_audiences(vec!["client1".to_string(), "client2".to_string()])
        .with_clock_skew_tolerance(60);

    group.bench_function("simple_token_validation", |b| {
        b.iter(|| black_box(validator.validate(&simple_token)).ok())
    });

    group.bench_function("complex_token_validation", |b| {
        b.iter(|| black_box(validator.validate(&complex_token)).ok())
    });

    group.finish();
}

fn bench_token_cloning(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_cloning");

    let simple_token = create_simple_token();
    let complex_token = create_complex_token();

    group.bench_function("simple_token_clone", |b| {
        b.iter(|| black_box(simple_token.clone()))
    });

    group.bench_function("complex_token_clone", |b| {
        b.iter(|| black_box(complex_token.clone()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_token_creation,
    bench_token_validation,
    bench_token_cloning
);
criterion_main!(benches);
