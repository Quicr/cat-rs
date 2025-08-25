/*!
 * Composite Claims Example
 * 
 * This example demonstrates the usage of composite claims in CAT tokens
 * as defined in draft-lemmons-cose-composite-claims-01.
 * 
 * Composite claims allow expressing logical relationships between sets of
 * claims using OR, NOR, and AND operations, enabling complex access control
 * scenarios such as multi-region authorization, service dependencies, and
 * compliance requirements.
 */

use cat_impl::claims::{
    CatToken, CompositeClaim, CompositeOperator, composite_utils,
};
use cat_impl::token::CatTokenValidator;
use chrono::{Duration, Utc};

fn print_header(title: &str) {
    println!("\n{}", "=".repeat(50));
    println!("{}", title);
    println!("{}", "=".repeat(50));
}

fn create_token_for_region(issuer: &str, region: &str) -> CatToken {
    let exp = Utc::now() + Duration::hours(24);
    
    CatToken::new()
        .with_issuer(issuer)
        .with_audience(vec!["payment-service".to_string()])
        .with_expiration(exp)
        .with_cwt_id(&format!("token-{}", region))
        .with_uri_patterns(vec![]) // Placeholder for region-specific URIs
}

fn create_token_for_service(issuer: &str, service: &str) -> CatToken {
    let exp = Utc::now() + Duration::hours(1);
    
    CatToken::new()
        .with_issuer(issuer)
        .with_audience(vec![service.to_string()])
        .with_expiration(exp)
        .with_cwt_id("service-token")
}

fn create_expired_token(issuer: &str) -> CatToken {
    let exp = Utc::now() - Duration::hours(1);
    
    CatToken::new()
        .with_issuer(issuer)
        .with_audience(vec!["restricted-service".to_string()])
        .with_expiration(exp)
        .with_cwt_id("expired-token")
}

fn demonstrate_or_composite() {
    print_header("OR Composite Example: Multi-Region Access");
    
    println!("Creating tokens for different regions...");
    
    // Create tokens for different geographic regions
    let us_token = create_token_for_region("us-issuer", "US");
    let eu_token = create_token_for_region("eu-issuer", "EU");
    let apac_token = create_token_for_region("apac-issuer", "APAC");
    
    // Create OR composite: user can access from ANY of these regions
    let region_composite = composite_utils::create_or_from_tokens(vec![
        us_token, eu_token, apac_token
    ]);
    
    // Main token with regional composite claim
    let main_token = CatToken::new()
        .with_issuer("global-bank")
        .with_audience(vec!["payment-gateway".to_string()])
        .with_expiration(Utc::now() + Duration::hours(8))
        .with_or_composite(region_composite);
    
    // Validate the token
    let validator = CatTokenValidator::new().with_clock_skew_tolerance(300);
    
    match validator.validate(&main_token) {
        Ok(_) => {
            println!("✓ Token validation succeeded");
            println!("User can access payment services from US, EU, or APAC regions");
        }
        Err(_) => {
            println!("✗ Token validation failed");
        }
    }
}

fn demonstrate_and_composite() {
    print_header("AND Composite Example: Multi-Service Authorization");
    
    println!("Creating tokens for different services...");
    
    // Create tokens for different services that must ALL be authorized
    let auth_token = create_token_for_service("auth-service", "authentication");
    let data_token = create_token_for_service("data-service", "user-data");
    let audit_token = create_token_for_service("audit-service", "audit-log");
    
    // Create AND composite: user needs access to ALL services
    let service_composite = composite_utils::create_and_from_tokens(vec![
        auth_token, data_token, audit_token
    ]);
    
    // Main token with service composite claim
    let main_token = CatToken::new()
        .with_issuer("enterprise-sso")
        .with_audience(vec!["admin-portal".to_string()])
        .with_expiration(Utc::now() + Duration::hours(2))
        .with_and_composite(service_composite);
    
    let validator = CatTokenValidator::new().with_clock_skew_tolerance(300);
    
    match validator.validate(&main_token) {
        Ok(_) => {
            println!("✓ Token validation succeeded");
            println!("User has admin access requiring authentication, data, AND audit services");
        }
        Err(_) => {
            println!("✗ Token validation failed");
        }
    }
}

fn demonstrate_nor_composite() {
    print_header("NOR Composite Example: Restricted Access");
    
    println!("Creating tokens for restricted locations...");
    
    // Create expired tokens to simulate restricted access
    let restricted_token1 = create_expired_token("restricted-issuer-1");
    let restricted_token2 = create_expired_token("restricted-issuer-2");
    
    // Create NOR composite: user should NOT be accessing from these regions
    let restricted_composite = composite_utils::create_nor_from_tokens(vec![
        restricted_token1, restricted_token2
    ]);
    
    let main_token = CatToken::new()
        .with_issuer("compliance-service")
        .with_audience(vec!["financial-data".to_string()])
        .with_expiration(Utc::now() + Duration::hours(4))
        .with_nor_composite(restricted_composite);
    
    let validator = CatTokenValidator::new().with_clock_skew_tolerance(300);
    
    match validator.validate(&main_token) {
        Ok(_) => {
            println!("✓ Token validation succeeded");
            println!("User is not accessing from restricted regions");
        }
        Err(_) => {
            println!("✗ Token validation failed");
        }
    }
}

fn demonstrate_nested_composite() {
    print_header("Nested Composite Example: Complex Access Control");
    
    println!("Creating complex nested access control...");
    
    // Scenario: (US OR EU) AND (business-hours OR emergency-access)
    
    // Geographic tokens
    let us_token = create_token_for_region("us-issuer", "US");
    let eu_token = create_token_for_region("eu-issuer", "EU");
    let geo_composite = composite_utils::create_or_from_tokens(vec![us_token, eu_token]);
    
    // Time-based tokens
    let business_token = create_token_for_service("time-service", "business-hours");
    let emergency_token = create_token_for_service("emergency-service", "emergency-access");
    let time_composite = composite_utils::create_or_from_tokens(vec![business_token, emergency_token]);
    
    // Combine with AND: must satisfy both geography AND time constraints
    let mut root_composite = CompositeClaim::new(CompositeOperator::And);
    root_composite.add_composite(geo_composite);
    root_composite.add_composite(time_composite);
    
    println!("Nesting depth: {}", root_composite.get_depth());
    
    let main_token = CatToken::new()
        .with_issuer("global-finance")
        .with_audience(vec!["trading-system".to_string()])
        .with_expiration(Utc::now() + Duration::hours(12))
        .with_and_composite(root_composite);
    
    let validator = CatTokenValidator::new().with_clock_skew_tolerance(300);
    
    match validator.validate(&main_token) {
        Ok(_) => {
            println!("✓ Token validation succeeded");
            println!("User meets both geographic (US OR EU) AND time-based constraints");
        }
        Err(e) => {
            println!("✗ Token validation failed: {:?}", e);
        }
    }
}

fn demonstrate_composite_claims_container() {
    print_header("Composite Claims Container Example");
    
    println!("Creating token with multiple composite claim types...");
    
    // Create different types of composite claims
    let region_or = composite_utils::create_or_from_tokens(vec![
        create_token_for_region("us-issuer", "US"),
        create_token_for_region("ca-issuer", "CA"),
    ]);
    
    let service_and = composite_utils::create_and_from_tokens(vec![
        create_token_for_service("auth-service", "authentication"),
        create_token_for_service("billing-service", "billing"),
    ]);
    
    // Create a token with multiple composite types
    let complex_token = CatToken::new()
        .with_issuer("multi-cloud-provider")
        .with_audience(vec!["cloud-resources".to_string()])
        .with_expiration(Utc::now() + Duration::hours(6))
        .with_or_composite(region_or)
        .with_and_composite(service_and);
    
    println!("Token has composites: {}", complex_token.composite.has_composites());
    
    let validator = CatTokenValidator::new().with_clock_skew_tolerance(300);
    
    match validator.validate(&complex_token) {
        Ok(_) => {
            println!("✓ Complex token validation succeeded");
            println!("Token satisfies OR geography AND requires authentication+billing services");
        }
        Err(e) => {
            println!("✗ Token validation failed: {:?}", e);
        }
    }
}

fn demonstrate_composite_creation_utilities() {
    print_header("Composite Creation Utilities Example");
    
    println!("Demonstrating various ways to create composite claims...");
    
    // Create tokens
    let tokens = vec![
        create_token_for_service("service-a", "payments"),
        create_token_for_service("service-b", "analytics"),
        create_token_for_service("service-c", "reporting"),
    ];
    
    // Using utility functions
    let or_composite = composite_utils::create_or_from_tokens(tokens.clone());
    let and_composite = composite_utils::create_and_from_tokens(tokens.clone());
    let nor_composite = composite_utils::create_nor_from_tokens(tokens);
    
    println!("Created OR composite with {} claims", or_composite.claims.len());
    println!("Created AND composite with {} claims", and_composite.claims.len());
    println!("Created NOR composite with {} claims", nor_composite.claims.len());
    
    // Manual creation
    let mut manual_composite = CompositeClaim::new(CompositeOperator::Or);
    manual_composite.add_token(create_token_for_service("manual-service", "test"));
    manual_composite.add_composite(or_composite);
    
    println!("Manual composite depth: {}", manual_composite.get_depth());
}

fn demonstrate_performance_considerations() {
    print_header("Performance Considerations Example");
    
    println!("Demonstrating depth limits and performance considerations...");
    
    // Create a composite with reasonable depth
    let mut composite = CompositeClaim::new(CompositeOperator::Or);
    composite.add_token(create_token_for_service("base-service", "base"));
    
    // Add some nesting (within reasonable limits)
    for level in 1..=3 {
        let mut new_composite = CompositeClaim::new(CompositeOperator::And);
        new_composite.add_token(create_token_for_service(&format!("level-{}", level), "nested"));
        new_composite.add_composite(composite);
        composite = new_composite;
    }
    
    println!("Composite depth: {}", composite.get_depth());
    
    let token = CatToken::new()
        .with_issuer("performance-test")
        .with_audience(vec!["test-service".to_string()])
        .with_expiration(Utc::now() + Duration::hours(1))
        .with_or_composite(composite);
    
    let validator = CatTokenValidator::new();
    
    let start = std::time::Instant::now();
    let result = validator.validate(&token);
    let duration = start.elapsed();
    
    match result {
        Ok(_) => println!("✓ Validation succeeded in {:?}", duration),
        Err(e) => println!("✗ Validation failed in {:?}: {:?}", duration, e),
    }
}

fn main() {
    println!("CAT Composite Claims Examples");
    println!("Based on draft-lemmons-cose-composite-claims-01");
    
    demonstrate_or_composite();
    demonstrate_and_composite();
    demonstrate_nor_composite();
    demonstrate_nested_composite();
    demonstrate_composite_claims_container();
    demonstrate_composite_creation_utilities();
    demonstrate_performance_considerations();
    
    print_header("Summary");
    println!("Composite claims provide powerful logical relationships:");
    println!("• OR: At least one claim set must be acceptable");
    println!("• AND: All claim sets must be acceptable");
    println!("• NOR: No claim sets can be acceptable");
    println!("• Supports arbitrary nesting for complex scenarios");
    println!("• Useful for multi-region, multi-service, and compliance scenarios");
    println!("• Performance considerations for deep nesting levels");
}