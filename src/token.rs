use crate::{CatError, CatToken, Cwt, CwtHeader, CryptographicAlgorithm, UriPattern, NetworkIdentifier};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use std::collections::HashSet;

pub struct CatTokenValidator {
    expected_issuers: Option<HashSet<String>>,
    expected_audiences: Option<HashSet<String>>,
    clock_skew_tolerance: i64,
}

impl CatTokenValidator {
    pub fn new() -> Self {
        Self {
            expected_issuers: None,
            expected_audiences: None,
            clock_skew_tolerance: 60, // 60 seconds default
        }
    }

    pub fn with_expected_issuers(mut self, issuers: Vec<String>) -> Self {
        self.expected_issuers = Some(issuers.into_iter().collect());
        self
    }

    pub fn with_expected_audiences(mut self, audiences: Vec<String>) -> Self {
        self.expected_audiences = Some(audiences.into_iter().collect());
        self
    }

    pub fn with_clock_skew_tolerance(mut self, tolerance_seconds: i64) -> Self {
        self.clock_skew_tolerance = tolerance_seconds;
        self
    }

    pub fn validate(&self, token: &CatToken) -> Result<(), CatError> {
        let now = Utc::now().timestamp();
        
        if let Some(exp) = token.core.exp {
            if now > exp + self.clock_skew_tolerance {
                return Err(CatError::TokenExpired);
            }
        }

        if let Some(nbf) = token.core.nbf {
            if now < nbf - self.clock_skew_tolerance {
                return Err(CatError::TokenNotYetValid);
            }
        }

        if let Some(ref expected_issuers) = self.expected_issuers {
            if let Some(ref iss) = token.core.iss {
                if !expected_issuers.contains(iss) {
                    return Err(CatError::InvalidIssuer);
                }
            } else {
                return Err(CatError::MissingRequiredClaim("iss".to_string()));
            }
        }

        if let Some(ref expected_audiences) = self.expected_audiences {
            if let Some(ref aud) = token.core.aud {
                if !aud.iter().any(|a| expected_audiences.contains(a)) {
                    return Err(CatError::InvalidAudience);
                }
            } else {
                return Err(CatError::MissingRequiredClaim("aud".to_string()));
            }
        }

        self.validate_geographic_restrictions(token)?;
        self.validate_usage_limits(token)?;

        Ok(())
    }

    fn validate_geographic_restrictions(&self, token: &CatToken) -> Result<(), CatError> {
        if let Some(ref coords) = token.cat.catgeocoord {
            if coords.lat.abs() > 90.0 || coords.lon.abs() > 180.0 {
                return Err(CatError::GeographicValidationFailed(
                    "Invalid coordinates".to_string()
                ));
            }
        }

        if let Some(ref geohash) = token.cat.geohash {
            if geohash.is_empty() || geohash.len() > 12 {
                return Err(CatError::GeographicValidationFailed(
                    "Invalid geohash".to_string()
                ));
            }
        }

        Ok(())
    }

    fn validate_usage_limits(&self, _token: &CatToken) -> Result<(), CatError> {
        Ok(())
    }
}

pub struct CatTokenBuilder {
    inner: CatToken,
}

impl CatTokenBuilder {
    pub fn new() -> Self {
        Self {
            inner: CatToken::new(),
        }
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.inner = self.inner.with_issuer(issuer);
        self
    }

    pub fn audience(mut self, audiences: Vec<String>) -> Self {
        self.inner = self.inner.with_audience(audiences);
        self
    }

    pub fn expires_at(mut self, exp: DateTime<Utc>) -> Self {
        self.inner = self.inner.with_expiration(exp);
        self
    }

    pub fn not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.inner = self.inner.with_not_before(nbf);
        self
    }

    pub fn cwt_id(mut self, cti: impl Into<String>) -> Self {
        self.inner = self.inner.with_cwt_id(cti);
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.inner = self.inner.with_version(version);
        self
    }

    pub fn usage_limit(mut self, limit: u32) -> Self {
        self.inner = self.inner.with_usage_limit(limit);
        self
    }

    pub fn replay_protection(mut self, nonce: impl Into<String>) -> Self {
        self.inner = self.inner.with_replay_protection(nonce);
        self
    }

    pub fn proof_of_possession(mut self, enabled: bool) -> Self {
        self.inner = self.inner.with_proof_of_possession(enabled);
        self
    }

    pub fn geo_coordinate(mut self, lat: f64, lon: f64, accuracy: Option<f64>) -> Self {
        self.inner = self.inner.with_geo_coordinate(lat, lon, accuracy);
        self
    }

    pub fn geohash(mut self, geohash: impl Into<String>) -> Self {
        self.inner = self.inner.with_geohash(geohash);
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.inner = self.inner.with_subject(subject);
        self
    }

    pub fn issued_at(mut self, iat: chrono::DateTime<chrono::Utc>) -> Self {
        self.inner = self.inner.with_issued_at(iat);
        self
    }

    pub fn interface_data(mut self, data: impl Into<String>) -> Self {
        self.inner = self.inner.with_interface_data(data);
        self
    }

    pub fn confirmation(mut self, cnf: impl Into<String>) -> Self {
        self.inner = self.inner.with_confirmation(cnf);
        self
    }

    pub fn dpop_claim(mut self, dpop: impl Into<String>) -> Self {
        self.inner = self.inner.with_dpop_claim(dpop);
        self
    }

    pub fn interface_claim(mut self, interface: impl Into<String>) -> Self {
        self.inner = self.inner.with_interface_claim(interface);
        self
    }

    pub fn request_claim(mut self, request: impl Into<String>) -> Self {
        self.inner = self.inner.with_request_claim(request);
        self
    }

    pub fn uri_patterns(mut self, patterns: Vec<UriPattern>) -> Self {
        self.inner = self.inner.with_uri_patterns(patterns);
        self
    }

    pub fn network_identifiers(mut self, nips: Vec<NetworkIdentifier>) -> Self {
        self.inner = self.inner.with_network_identifiers(nips);
        self
    }

    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.inner = self.inner.with_ip_address(ip);
        self
    }

    pub fn ip_range(mut self, range: impl Into<String>) -> Self {
        self.inner = self.inner.with_ip_range(range);
        self
    }

    pub fn asn(mut self, asn: u32) -> Self {
        self.inner = self.inner.with_asn(asn);
        self
    }

    pub fn asn_range(mut self, start: u32, end: u32) -> Self {
        self.inner = self.inner.with_asn_range(start, end);
        self
    }

    pub fn build(self) -> CatToken {
        self.inner
    }
}

pub fn encode_token(
    token: &CatToken,
    algorithm: &dyn CryptographicAlgorithm,
) -> Result<String, CatError> {
    let cwt = Cwt::new(algorithm.algorithm_id(), token.clone());
    
    let header = CwtHeader {
        alg: algorithm.algorithm_id(),
        kid: cwt.header.kid.clone(),
        typ: cwt.header.typ.clone(),
    };

    let header_cbor = {
        let mut header_map = std::collections::HashMap::new();
        header_map.insert(1i64, ciborium::Value::Integer(header.alg.into()));
        if let Some(ref kid) = header.kid {
            header_map.insert(4i64, ciborium::Value::Text(kid.clone()));
        }
        if let Some(ref typ) = header.typ {
            header_map.insert(16i64, ciborium::Value::Text(typ.clone()));
        }

        let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = header_map
            .into_iter()
            .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
            .collect();

        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut buffer)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        buffer
    };

    let payload_cbor = cwt.encode_payload()?;
    
    let signing_input = crate::crypto::create_signing_input(&header_cbor, &payload_cbor);
    let signature = algorithm.sign(&signing_input)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_cbor);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_cbor);
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

pub fn decode_token(
    token_str: &str,
    algorithm: &dyn CryptographicAlgorithm,
) -> Result<CatToken, CatError> {
    let parts: Vec<&str> = token_str.split('.').collect();
    if parts.len() != 3 {
        return Err(CatError::InvalidTokenFormat);
    }

    let header_cbor = URL_SAFE_NO_PAD.decode(parts[0])
        .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
    let payload_cbor = URL_SAFE_NO_PAD.decode(parts[1])
        .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2])
        .map_err(|e| CatError::InvalidBase64(e.to_string()))?;

    let signing_input = crate::crypto::create_signing_input(&header_cbor, &payload_cbor);
    
    if !algorithm.verify(&signing_input, &signature)? {
        return Err(CatError::SignatureVerificationFailed);
    }

    Cwt::decode_payload(&payload_cbor)
}