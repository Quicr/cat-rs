use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const CLAIM_ISS: i64 = 1;
pub const CLAIM_AUD: i64 = 3;
pub const CLAIM_EXP: i64 = 4;
pub const CLAIM_NBF: i64 = 5;
pub const CLAIM_CTI: i64 = 7;

pub const CLAIM_CATREPLAY: i64 = 308;
pub const CLAIM_CATPOR: i64 = 309;
pub const CLAIM_CATV: i64 = 310;
pub const CLAIM_CATNIP: i64 = 311;
pub const CLAIM_CATU: i64 = 312;
pub const CLAIM_CATM: i64 = 313;
pub const CLAIM_CATALPN: i64 = 314;
pub const CLAIM_CATH: i64 = 315;
pub const CLAIM_CATGEOISO3166: i64 = 316;
pub const CLAIM_CATGEOCOORD: i64 = 317;
pub const CLAIM_GEOHASH: i64 = 282;
pub const CLAIM_CATGEOALT: i64 = 318;
pub const CLAIM_CATTPK: i64 = 319;

// Informational Claims
pub const CLAIM_SUB: i64 = 2;
pub const CLAIM_IAT: i64 = 6;
pub const CLAIM_CATIFDATA: i64 = 320;

// DPoP Claims
pub const CLAIM_CNF: i64 = 8;
pub const CLAIM_CATDPOP: i64 = 321;

// Request Claims
pub const CLAIM_CATIF: i64 = 322;
pub const CLAIM_CATR: i64 = 323;

// Composite Claims (RFC draft-lemmons-cose-composite-claims-01)
pub const CLAIM_OR: i64 = 324;
pub const CLAIM_NOR: i64 = 325;
pub const CLAIM_AND: i64 = 326;

// MOQT Claims (draft-law-moq-cat4moqt)
pub const CLAIM_MOQT: i64 = 327; // TBD_MOQT in the spec
pub const CLAIM_MOQT_REVAL: i64 = 328; // TBD_MOQT_REVAL in the spec

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreClaims {
    pub iss: Option<String>,
    pub aud: Option<Vec<String>>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub cti: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatClaims {
    pub catreplay: Option<String>,
    pub catpor: Option<bool>,
    pub catv: Option<String>,
    pub catnip: Option<Vec<NetworkIdentifier>>,
    pub catu: Option<u32>,
    pub catm: Option<String>,
    pub catalpn: Option<Vec<String>>,
    pub cath: Option<Vec<UriPattern>>,
    pub catgeoiso3166: Option<Vec<String>>,
    pub catgeocoord: Option<GeoCoordinate>,
    pub geohash: Option<String>,
    pub catgeoalt: Option<i32>,
    pub cattpk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InformationalClaims {
    pub sub: Option<String>,
    pub iat: Option<i64>,
    pub catifdata: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DpopClaims {
    pub cnf: Option<String>,
    pub catdpop: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestClaims {
    pub catif: Option<String>,
    pub catr: Option<String>,
}

/// Logical operators for composite claims
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CompositeOperator {
    /// At least one claim set must be acceptable
    Or,
    /// No claim sets can be acceptable
    Nor,
    /// All claim sets must be acceptable
    And,
}

/// A claim set that can contain either a token or a nested composite claim
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimSet {
    /// A regular CAT token
    Token(Box<CatToken>),
    /// A nested composite claim for arbitrary nesting depth
    Composite(Box<CompositeClaim>),
}

/// Composite claim structure implementing logical relationships between claim sets
/// as defined in draft-lemmons-cose-composite-claims-01
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompositeClaim {
    /// The logical operator for this composite claim
    pub op: CompositeOperator,
    /// Array of claim sets to evaluate
    pub claims: Vec<ClaimSet>,
}

impl CompositeClaim {
    /// Create a new composite claim with the specified operator
    pub fn new(op: CompositeOperator) -> Self {
        Self {
            op,
            claims: Vec::new(),
        }
    }

    /// Add a token as a claim set
    pub fn add_token(&mut self, token: CatToken) {
        self.claims.push(ClaimSet::Token(Box::new(token)));
    }

    /// Add a nested composite claim
    pub fn add_composite(&mut self, composite: CompositeClaim) {
        self.claims.push(ClaimSet::Composite(Box::new(composite)));
    }

    /// Add a claim set directly
    pub fn add_claim_set(&mut self, claim_set: ClaimSet) {
        self.claims.push(claim_set);
    }

    /// Get the maximum nesting depth of this composite claim
    pub fn get_depth(&self) -> usize {
        let mut max_depth = 1;
        for claim_set in &self.claims {
            if let ClaimSet::Composite(composite) = claim_set {
                let child_depth = composite.get_depth();
                max_depth = max_depth.max(child_depth + 1);
            }
        }
        max_depth
    }

    /// Evaluate this composite claim against a validation context
    pub fn evaluate<V>(&self, validator: &V) -> bool 
    where
        V: Fn(&CatToken) -> Result<(), Box<dyn std::error::Error>>,
    {
        match self.op {
            CompositeOperator::Or => {
                // At least one claim set must be acceptable
                self.claims.iter().any(|claim_set| self.evaluate_claim_set(claim_set, validator))
            }
            CompositeOperator::Nor => {
                // No claim sets can be acceptable
                !self.claims.iter().any(|claim_set| self.evaluate_claim_set(claim_set, validator))
            }
            CompositeOperator::And => {
                // All claim sets must be acceptable
                self.claims.iter().all(|claim_set| self.evaluate_claim_set(claim_set, validator))
            }
        }
    }

    fn evaluate_claim_set<V>(&self, claim_set: &ClaimSet, validator: &V) -> bool
    where
        V: Fn(&CatToken) -> Result<(), Box<dyn std::error::Error>>,
    {
        match claim_set {
            ClaimSet::Token(token) => validator(token.as_ref()).is_ok(),
            ClaimSet::Composite(composite) => composite.evaluate(validator),
        }
    }
}

/// Container for composite claims in a CAT token
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompositeClaims {
    /// OR composite claim
    pub or_claim: Option<CompositeClaim>,
    /// NOR composite claim
    pub nor_claim: Option<CompositeClaim>,
    /// AND composite claim
    pub and_claim: Option<CompositeClaim>,
}

impl Default for CompositeClaims {
    fn default() -> Self {
        Self {
            or_claim: None,
            nor_claim: None,
            and_claim: None,
        }
    }
}

impl CompositeClaims {
    /// Check if any composite claims are present
    pub fn has_composites(&self) -> bool {
        self.or_claim.is_some() || self.nor_claim.is_some() || self.and_claim.is_some()
    }

    /// Validate all composite claims
    pub fn validate_all<V>(&self, validator: &V) -> Result<(), Box<dyn std::error::Error>>
    where
        V: Fn(&CatToken) -> Result<(), Box<dyn std::error::Error>>,
    {
        if let Some(ref or_claim) = self.or_claim {
            if !or_claim.evaluate(validator) {
                return Err("OR composite claim validation failed".into());
            }
        }
        
        if let Some(ref nor_claim) = self.nor_claim {
            if !nor_claim.evaluate(validator) {
                return Err("NOR composite claim validation failed".into());
            }
        }
        
        if let Some(ref and_claim) = self.and_claim {
            if !and_claim.evaluate(validator) {
                return Err("AND composite claim validation failed".into());
            }
        }
        
        Ok(())
    }

    /// Get the maximum nesting depth across all composite claims
    pub fn get_max_depth(&self) -> usize {
        let mut max_depth = 0;
        
        if let Some(ref claim) = self.or_claim {
            max_depth = max_depth.max(claim.get_depth());
        }
        if let Some(ref claim) = self.nor_claim {
            max_depth = max_depth.max(claim.get_depth());
        }
        if let Some(ref claim) = self.and_claim {
            max_depth = max_depth.max(claim.get_depth());
        }
        
        max_depth
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoCoordinate {
    pub lat: f64,
    pub lon: f64,
    pub accuracy: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UriPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Regex(String),
    Hash(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkIdentifier {
    IpAddress(String),
    IpRange(String),
    Asn(u32),
    AsnRange(u32, u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MoqtAction {
    ClientSetup = 0,
    ServerSetup = 1,
    Announce = 2,
    SubscribeNamespace = 3,
    Subscribe = 4,
    SubscribeUpdate = 5,
    Publish = 6,
    Fetch = 7,
    TrackStatus = 8,
}

impl From<i32> for MoqtAction {
    fn from(value: i32) -> Self {
        match value {
            0 => MoqtAction::ClientSetup,
            1 => MoqtAction::ServerSetup,
            2 => MoqtAction::Announce,
            3 => MoqtAction::SubscribeNamespace,
            4 => MoqtAction::Subscribe,
            5 => MoqtAction::SubscribeUpdate,
            6 => MoqtAction::Publish,
            7 => MoqtAction::Fetch,
            8 => MoqtAction::TrackStatus,
            _ => MoqtAction::ClientSetup, // Default fallback
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryMatch {
    pub exact: Option<Vec<u8>>,
    pub prefix: Option<Vec<u8>>,
    pub suffix: Option<Vec<u8>>,
    pub contains: Option<Vec<u8>>,
}

impl Default for BinaryMatch {
    fn default() -> Self {
        Self {
            exact: None,
            prefix: None,
            suffix: None,
            contains: None,
        }
    }
}

impl BinaryMatch {
    pub fn exact(data: Vec<u8>) -> Self {
        Self {
            exact: Some(data),
            ..Default::default()
        }
    }
    
    pub fn prefix(data: Vec<u8>) -> Self {
        Self {
            prefix: Some(data),
            ..Default::default()
        }
    }
    
    pub fn suffix(data: Vec<u8>) -> Self {
        Self {
            suffix: Some(data),
            ..Default::default()
        }
    }
    
    pub fn contains(data: Vec<u8>) -> Self {
        Self {
            contains: Some(data),
            ..Default::default()
        }
    }
    
    pub fn matches(&self, input: &[u8]) -> bool {
        if let Some(ref exact_match) = self.exact {
            return input == exact_match.as_slice();
        }
        
        if let Some(ref prefix_match) = self.prefix {
            return input.starts_with(prefix_match);
        }
        
        if let Some(ref suffix_match) = self.suffix {
            return input.ends_with(suffix_match);
        }
        
        if let Some(ref contains_match) = self.contains {
            return input.windows(contains_match.len()).any(|window| window == contains_match.as_slice());
        }
        
        true // Empty match object matches all names
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoqtScope {
    pub actions: Vec<MoqtAction>,
    pub namespace_match: BinaryMatch,
    pub track_match: BinaryMatch,
}

impl MoqtScope {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            namespace_match: BinaryMatch::default(),
            track_match: BinaryMatch::default(),
        }
    }
    
    pub fn with_actions(mut self, actions: Vec<MoqtAction>) -> Self {
        self.actions = actions;
        self
    }
    
    pub fn with_namespace_match(mut self, namespace_match: BinaryMatch) -> Self {
        self.namespace_match = namespace_match;
        self
    }
    
    pub fn with_track_match(mut self, track_match: BinaryMatch) -> Self {
        self.track_match = track_match;
        self
    }
    
    pub fn allows_action(&self, action: &MoqtAction) -> bool {
        self.actions.contains(action)
    }
    
    pub fn matches_namespace(&self, namespace: &[u8]) -> bool {
        self.namespace_match.matches(namespace)
    }
    
    pub fn matches_track(&self, track: &[u8]) -> bool {
        self.track_match.matches(track)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoqtClaims {
    pub moqt: Option<Vec<MoqtScope>>,
    pub moqt_reval: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatToken {
    pub core: CoreClaims,
    pub cat: CatClaims,
    pub informational: InformationalClaims,
    pub dpop: DpopClaims,
    pub request: RequestClaims,
    pub composite: CompositeClaims,
    pub moqt: MoqtClaims,
    pub custom: HashMap<i64, ciborium::Value>,
}

impl CatToken {
    pub fn new() -> Self {
        Self {
            core: CoreClaims {
                iss: None,
                aud: None,
                exp: None,
                nbf: None,
                cti: None,
            },
            cat: CatClaims {
                catreplay: None,
                catpor: None,
                catv: None,
                catnip: None,
                catu: None,
                catm: None,
                catalpn: None,
                cath: None,
                catgeoiso3166: None,
                catgeocoord: None,
                geohash: None,
                catgeoalt: None,
                cattpk: None,
            },
            informational: InformationalClaims {
                sub: None,
                iat: None,
                catifdata: None,
            },
            dpop: DpopClaims {
                cnf: None,
                catdpop: None,
            },
            request: RequestClaims {
                catif: None,
                catr: None,
            },
            composite: CompositeClaims::default(),
            moqt: MoqtClaims {
                moqt: None,
                moqt_reval: None,
            },
            custom: HashMap::new(),
        }
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.core.iss = Some(issuer.into());
        self
    }

    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.core.aud = Some(audience);
        self
    }

    pub fn with_expiration(mut self, exp: DateTime<Utc>) -> Self {
        self.core.exp = Some(exp.timestamp());
        self
    }

    pub fn with_not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.core.nbf = Some(nbf.timestamp());
        self
    }

    pub fn with_cwt_id(mut self, cti: impl Into<String>) -> Self {
        self.core.cti = Some(cti.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.cat.catv = Some(version.into());
        self
    }

    pub fn with_usage_limit(mut self, limit: u32) -> Self {
        self.cat.catu = Some(limit);
        self
    }

    pub fn with_replay_protection(mut self, nonce: impl Into<String>) -> Self {
        self.cat.catreplay = Some(nonce.into());
        self
    }

    pub fn with_proof_of_possession(mut self, enabled: bool) -> Self {
        self.cat.catpor = Some(enabled);
        self
    }

    pub fn with_geo_coordinate(mut self, lat: f64, lon: f64, accuracy: Option<f64>) -> Self {
        self.cat.catgeocoord = Some(GeoCoordinate { lat, lon, accuracy });
        self
    }

    pub fn with_geohash(mut self, geohash: impl Into<String>) -> Self {
        self.cat.geohash = Some(geohash.into());
        self
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.informational.sub = Some(subject.into());
        self
    }

    pub fn with_issued_at(mut self, iat: chrono::DateTime<chrono::Utc>) -> Self {
        self.informational.iat = Some(iat.timestamp());
        self
    }

    pub fn with_interface_data(mut self, data: impl Into<String>) -> Self {
        self.informational.catifdata = Some(data.into());
        self
    }

    pub fn with_confirmation(mut self, cnf: impl Into<String>) -> Self {
        self.dpop.cnf = Some(cnf.into());
        self
    }

    pub fn with_dpop_claim(mut self, dpop: impl Into<String>) -> Self {
        self.dpop.catdpop = Some(dpop.into());
        self
    }

    pub fn with_interface_claim(mut self, interface: impl Into<String>) -> Self {
        self.request.catif = Some(interface.into());
        self
    }

    pub fn with_request_claim(mut self, request: impl Into<String>) -> Self {
        self.request.catr = Some(request.into());
        self
    }

    pub fn with_uri_patterns(mut self, patterns: Vec<UriPattern>) -> Self {
        self.cat.cath = Some(patterns);
        self
    }

    pub fn with_network_identifiers(mut self, nips: Vec<NetworkIdentifier>) -> Self {
        self.cat.catnip = Some(nips);
        self
    }

    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        let nip = NetworkIdentifier::IpAddress(ip.into());
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    pub fn with_ip_range(mut self, range: impl Into<String>) -> Self {
        let nip = NetworkIdentifier::IpRange(range.into());
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    pub fn with_asn(mut self, asn: u32) -> Self {
        let nip = NetworkIdentifier::Asn(asn);
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    pub fn with_asn_range(mut self, start: u32, end: u32) -> Self {
        let nip = NetworkIdentifier::AsnRange(start, end);
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    /// Add an OR composite claim
    pub fn with_or_composite(mut self, or_claim: CompositeClaim) -> Self {
        self.composite.or_claim = Some(or_claim);
        self
    }

    /// Add a NOR composite claim
    pub fn with_nor_composite(mut self, nor_claim: CompositeClaim) -> Self {
        self.composite.nor_claim = Some(nor_claim);
        self
    }

    /// Add an AND composite claim
    pub fn with_and_composite(mut self, and_claim: CompositeClaim) -> Self {
        self.composite.and_claim = Some(and_claim);
        self
    }

    /// Add MOQT scopes
    pub fn with_moqt_scopes(mut self, scopes: Vec<MoqtScope>) -> Self {
        self.moqt.moqt = Some(scopes);
        self
    }

    /// Add a single MOQT scope
    pub fn with_moqt_scope(mut self, scope: MoqtScope) -> Self {
        if let Some(ref mut scopes) = self.moqt.moqt {
            scopes.push(scope);
        } else {
            self.moqt.moqt = Some(vec![scope]);
        }
        self
    }

    /// Set MOQT revalidation interval
    pub fn with_moqt_reval(mut self, interval_seconds: f64) -> Self {
        self.moqt.moqt_reval = Some(interval_seconds);
        self
    }

    /// Check if token allows specific MOQT action for namespace and track
    pub fn allows_moqt_action(&self, action: &MoqtAction, namespace: &[u8], track: &[u8]) -> bool {
        if let Some(ref scopes) = self.moqt.moqt {
            scopes.iter().any(|scope| {
                scope.allows_action(action) && 
                scope.matches_namespace(namespace) &&
                scope.matches_track(track)
            })
        } else {
            false // Default to blocked if no MOQT claims
        }
    }
}

/// Utility functions for creating composite claims
pub mod composite_utils {
    use super::*;

    /// Create an OR composite claim from a vector of tokens
    pub fn create_or_from_tokens(tokens: Vec<CatToken>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Or);
        for token in tokens {
            composite.add_token(token);
        }
        composite
    }

    /// Create a NOR composite claim from a vector of tokens
    pub fn create_nor_from_tokens(tokens: Vec<CatToken>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Nor);
        for token in tokens {
            composite.add_token(token);
        }
        composite
    }

    /// Create an AND composite claim from a vector of tokens
    pub fn create_and_from_tokens(tokens: Vec<CatToken>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::And);
        for token in tokens {
            composite.add_token(token);
        }
        composite
    }

    /// Create an OR composite claim from a vector of claim sets
    pub fn create_or_from_claim_sets(claim_sets: Vec<ClaimSet>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Or);
        for claim_set in claim_sets {
            composite.add_claim_set(claim_set);
        }
        composite
    }

    /// Create a NOR composite claim from a vector of claim sets
    pub fn create_nor_from_claim_sets(claim_sets: Vec<ClaimSet>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Nor);
        for claim_set in claim_sets {
            composite.add_claim_set(claim_set);
        }
        composite
    }

    /// Create an AND composite claim from a vector of claim sets
    pub fn create_and_from_claim_sets(claim_sets: Vec<ClaimSet>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::And);
        for claim_set in claim_sets {
            composite.add_claim_set(claim_set);
        }
        composite
    }
}
