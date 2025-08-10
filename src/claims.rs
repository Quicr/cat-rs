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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatToken {
    pub core: CoreClaims,
    pub cat: CatClaims,
    pub informational: InformationalClaims,
    pub dpop: DpopClaims,
    pub request: RequestClaims,
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
}
