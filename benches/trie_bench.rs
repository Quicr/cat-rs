use cat_impl::*;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn create_test_patterns() -> Vec<String> {
    vec![
        "https://api.example.com".to_string(),
        "https://cdn.example.com".to_string(),
        "https://auth.example.com".to_string(),
        "/api/v1/".to_string(),
        "/api/v2/".to_string(),
        "/static/".to_string(),
        ".json".to_string(),
        ".xml".to_string(),
        ".html".to_string(),
        "example.com".to_string(),
        "test.org".to_string(),
        "demo.net".to_string(),
    ]
}

fn create_test_texts() -> Vec<String> {
    vec![
        "https://api.example.com/users/123".to_string(),
        "https://cdn.example.com/images/logo.png".to_string(),
        "https://auth.example.com/login".to_string(),
        "/api/v1/users".to_string(),
        "/api/v2/posts".to_string(),
        "/static/css/style.css".to_string(),
        "/data/users.json".to_string(),
        "/config/settings.xml".to_string(),
        "/pages/index.html".to_string(),
        "mail.example.com".to_string(),
        "blog.test.org".to_string(),
        "app.demo.net".to_string(),
        "nonmatching.text".to_string(),
    ]
}

fn bench_prefix_trie_insert(c: &mut Criterion) {
    let patterns = create_test_patterns();

    c.bench_function("prefix_trie_insert", |b| {
        b.iter(|| {
            let mut trie = PrefixTrie::new();
            for (i, pattern) in patterns.iter().enumerate() {
                trie.insert(black_box(pattern), black_box(format!("value_{}", i)));
            }
            trie
        })
    });
}

fn bench_prefix_trie_search(c: &mut Criterion) {
    let patterns = create_test_patterns();
    let texts = create_test_texts();

    let mut trie = PrefixTrie::new();
    for (i, pattern) in patterns.iter().enumerate() {
        trie.insert(pattern, format!("value_{}", i));
    }

    c.bench_function("prefix_trie_search", |b| {
        b.iter(|| {
            for text in &texts {
                black_box(trie.search_prefix(black_box(text)));
            }
        })
    });
}

fn bench_suffix_trie_insert(c: &mut Criterion) {
    let patterns = create_test_patterns();

    c.bench_function("suffix_trie_insert", |b| {
        b.iter(|| {
            let mut trie = SuffixTrie::new();
            for (i, pattern) in patterns.iter().enumerate() {
                trie.insert(black_box(pattern), black_box(format!("value_{}", i)));
            }
            trie
        })
    });
}

fn bench_suffix_trie_search(c: &mut Criterion) {
    let patterns = create_test_patterns();
    let texts = create_test_texts();

    let mut trie = SuffixTrie::new();
    for (i, pattern) in patterns.iter().enumerate() {
        trie.insert(pattern, format!("value_{}", i));
    }

    c.bench_function("suffix_trie_search", |b| {
        b.iter(|| {
            for text in &texts {
                black_box(trie.search_suffix(black_box(text)));
            }
        })
    });
}

fn bench_uri_matcher(c: &mut Criterion) {
    let texts = create_test_texts();

    let mut matcher = UriMatcher::new();

    // Add different types of patterns
    matcher
        .add_pattern(claims::UriPattern::Exact(
            "https://api.example.com".to_string(),
        ))
        .unwrap();
    matcher
        .add_pattern(claims::UriPattern::Prefix("https://cdn.".to_string()))
        .unwrap();
    matcher
        .add_pattern(claims::UriPattern::Suffix(".json".to_string()))
        .unwrap();
    matcher
        .add_pattern(claims::UriPattern::Regex(r"^/api/v\d+/".to_string()))
        .unwrap();

    c.bench_function("uri_matcher_matches", |b| {
        b.iter(|| {
            for text in &texts {
                black_box(matcher.matches(black_box(text)));
            }
        })
    });
}

fn bench_trie_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_scaling");

    for size in [10, 100, 1000].iter() {
        let patterns: Vec<String> = (0..*size).map(|i| format!("pattern_{:04}", i)).collect();

        group.bench_with_input(
            BenchmarkId::new("prefix_trie_insert", size),
            size,
            |b, _size| {
                b.iter(|| {
                    let mut trie = PrefixTrie::new();
                    for (i, pattern) in patterns.iter().enumerate() {
                        trie.insert(black_box(pattern), black_box(format!("value_{}", i)));
                    }
                    trie
                })
            },
        );

        // Benchmark search with pre-built trie
        let mut trie = PrefixTrie::new();
        for (i, pattern) in patterns.iter().enumerate() {
            trie.insert(pattern, format!("value_{}", i));
        }

        group.bench_with_input(
            BenchmarkId::new("prefix_trie_search", size),
            size,
            |b, _size| {
                b.iter(|| {
                    for pattern in patterns.iter().take(10) {
                        // Search first 10 patterns
                        black_box(trie.search_prefix(black_box(pattern)));
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_prefix_trie_insert,
    bench_prefix_trie_search,
    bench_suffix_trie_insert,
    bench_suffix_trie_search,
    bench_uri_matcher,
    bench_trie_scaling
);

criterion_main!(benches);
