use crate::{CatError, CatToken, CoreClaims, CatClaims, GeoCoordinate};
use crate::claims::*;
use ciborium::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CwtHeader {
    pub alg: i64,
    pub kid: Option<String>,
    pub typ: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cwt {
    pub header: CwtHeader,
    pub payload: CatToken,
    pub signature: Vec<u8>,
}

impl Cwt {
    pub fn new(alg: i64, payload: CatToken) -> Self {
        Self {
            header: CwtHeader {
                alg,
                kid: None,
                typ: Some("CAT".to_string()),
            },
            payload,
            signature: Vec::new(),
        }
    }

    pub fn with_key_id(mut self, kid: impl Into<String>) -> Self {
        self.header.kid = Some(kid.into());
        self
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, CatError> {
        let mut claims_map: HashMap<i64, Value> = HashMap::new();

        if let Some(ref iss) = self.payload.core.iss {
            claims_map.insert(CLAIM_ISS, Value::Text(iss.clone()));
        }

        if let Some(ref aud) = self.payload.core.aud {
            let aud_values: Vec<Value> = aud.iter().map(|a| Value::Text(a.clone())).collect();
            claims_map.insert(CLAIM_AUD, Value::Array(aud_values));
        }

        if let Some(exp) = self.payload.core.exp {
            claims_map.insert(CLAIM_EXP, Value::Integer(exp.into()));
        }

        if let Some(nbf) = self.payload.core.nbf {
            claims_map.insert(CLAIM_NBF, Value::Integer(nbf.into()));
        }

        if let Some(ref cti) = self.payload.core.cti {
            claims_map.insert(CLAIM_CTI, Value::Bytes(cti.as_bytes().to_vec()));
        }

        if let Some(ref catreplay) = self.payload.cat.catreplay {
            claims_map.insert(CLAIM_CATREPLAY, Value::Text(catreplay.clone()));
        }

        if let Some(catpor) = self.payload.cat.catpor {
            claims_map.insert(CLAIM_CATPOR, Value::Bool(catpor));
        }

        if let Some(ref catv) = self.payload.cat.catv {
            claims_map.insert(CLAIM_CATV, Value::Text(catv.clone()));
        }

        if let Some(ref catnip) = self.payload.cat.catnip {
            let nip_values: Vec<Value> = catnip.iter().map(|nip| {
                match nip {
                    NetworkIdentifier::IpAddress(ip) => Value::Text(ip.clone()),
                    NetworkIdentifier::IpRange(range) => {
                        let mut nip_map = Vec::new();
                        nip_map.push((Value::Text("ip_range".to_string()), Value::Text(range.clone())));
                        Value::Map(nip_map)
                    },
                    NetworkIdentifier::Asn(asn) => {
                        let mut nip_map = Vec::new();
                        nip_map.push((Value::Text("asn".to_string()), Value::Integer((*asn).into())));
                        Value::Map(nip_map)
                    },
                    NetworkIdentifier::AsnRange(start, end) => {
                        let mut nip_map = Vec::new();
                        nip_map.push((Value::Text("asn_range".to_string()), 
                                     Value::Array(vec![Value::Integer((*start).into()), Value::Integer((*end).into())])));
                        Value::Map(nip_map)
                    },
                }
            }).collect();
            claims_map.insert(CLAIM_CATNIP, Value::Array(nip_values));
        }

        if let Some(catu) = self.payload.cat.catu {
            claims_map.insert(CLAIM_CATU, Value::Integer(catu.into()));
        }

        if let Some(ref catm) = self.payload.cat.catm {
            claims_map.insert(CLAIM_CATM, Value::Text(catm.clone()));
        }

        if let Some(ref catalpn) = self.payload.cat.catalpn {
            let alpn_values: Vec<Value> = catalpn.iter().map(|a| Value::Text(a.clone())).collect();
            claims_map.insert(CLAIM_CATALPN, Value::Array(alpn_values));
        }

        if let Some(ref cath) = self.payload.cat.cath {
            let pattern_values: Vec<Value> = cath.iter().map(|pattern| {
                match pattern {
                    UriPattern::Exact(s) => Value::Text(s.clone()),
                    UriPattern::Prefix(s) => {
                        let mut pattern_map = Vec::new();
                        pattern_map.push((Value::Text("prefix".to_string()), Value::Text(s.clone())));
                        Value::Map(pattern_map)
                    },
                    UriPattern::Suffix(s) => {
                        let mut pattern_map = Vec::new();
                        pattern_map.push((Value::Text("suffix".to_string()), Value::Text(s.clone())));
                        Value::Map(pattern_map)
                    },
                    UriPattern::Regex(s) => {
                        let mut pattern_map = Vec::new();
                        pattern_map.push((Value::Text("regex".to_string()), Value::Text(s.clone())));
                        Value::Map(pattern_map)
                    },
                    UriPattern::Hash(s) => {
                        let mut pattern_map = Vec::new();
                        pattern_map.push((Value::Text("hash".to_string()), Value::Text(s.clone())));
                        Value::Map(pattern_map)
                    },
                }
            }).collect();
            claims_map.insert(CLAIM_CATH, Value::Array(pattern_values));
        }

        if let Some(ref catgeoiso3166) = self.payload.cat.catgeoiso3166 {
            let geo_values: Vec<Value> = catgeoiso3166.iter().map(|g| Value::Text(g.clone())).collect();
            claims_map.insert(CLAIM_CATGEOISO3166, Value::Array(geo_values));
        }

        if let Some(ref catgeocoord) = self.payload.cat.catgeocoord {
            let mut coord_map = Vec::new();
            coord_map.push((Value::Text("lat".to_string()), Value::Float(catgeocoord.lat)));
            coord_map.push((Value::Text("lon".to_string()), Value::Float(catgeocoord.lon)));
            if let Some(accuracy) = catgeocoord.accuracy {
                coord_map.push((Value::Text("accuracy".to_string()), Value::Float(accuracy)));
            }
            claims_map.insert(CLAIM_CATGEOCOORD, Value::Map(coord_map));
        }

        if let Some(ref geohash) = self.payload.cat.geohash {
            claims_map.insert(CLAIM_GEOHASH, Value::Text(geohash.clone()));
        }

        if let Some(catgeoalt) = self.payload.cat.catgeoalt {
            claims_map.insert(CLAIM_CATGEOALT, Value::Integer(catgeoalt.into()));
        }

        if let Some(ref cattpk) = self.payload.cat.cattpk {
            claims_map.insert(CLAIM_CATTPK, Value::Text(cattpk.clone()));
        }

        // Informational claims
        if let Some(ref sub) = self.payload.informational.sub {
            claims_map.insert(CLAIM_SUB, Value::Text(sub.clone()));
        }

        if let Some(iat) = self.payload.informational.iat {
            claims_map.insert(CLAIM_IAT, Value::Integer(iat.into()));
        }

        if let Some(ref catifdata) = self.payload.informational.catifdata {
            claims_map.insert(CLAIM_CATIFDATA, Value::Text(catifdata.clone()));
        }

        // DPoP claims
        if let Some(ref cnf) = self.payload.dpop.cnf {
            claims_map.insert(CLAIM_CNF, Value::Text(cnf.clone()));
        }

        if let Some(ref catdpop) = self.payload.dpop.catdpop {
            claims_map.insert(CLAIM_CATDPOP, Value::Text(catdpop.clone()));
        }

        // Request claims
        if let Some(ref catif) = self.payload.request.catif {
            claims_map.insert(CLAIM_CATIF, Value::Text(catif.clone()));
        }

        if let Some(ref catr) = self.payload.request.catr {
            claims_map.insert(CLAIM_CATR, Value::Text(catr.clone()));
        }

        for (key, value) in &self.payload.custom {
            claims_map.insert(*key, value.clone());
        }

        let cbor_map: Vec<(Value, Value)> = claims_map
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect();

        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&Value::Map(cbor_map), &mut buffer)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;

        Ok(buffer)
    }

    pub fn decode_payload(cbor_data: &[u8]) -> Result<CatToken, CatError> {
        let value: Value = ciborium::de::from_reader(cbor_data)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;

        let claims_map = match value {
            Value::Map(map) => map,
            _ => return Err(CatError::InvalidTokenFormat),
        };

        let mut core = CoreClaims {
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            cti: None,
        };

        let mut cat = CatClaims {
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
        };

        let mut informational = InformationalClaims {
            sub: None,
            iat: None,
            catifdata: None,
        };

        let mut dpop = DpopClaims {
            cnf: None,
            catdpop: None,
        };

        let mut request = RequestClaims {
            catif: None,
            catr: None,
        };

        let mut custom = HashMap::new();

        for (key, value) in claims_map {
            let claim_id = match key {
                Value::Integer(i) => i.try_into().map_err(|_| CatError::InvalidTokenFormat)?,
                _ => continue,
            };

            match claim_id {
                CLAIM_ISS => {
                    if let Value::Text(s) = value {
                        core.iss = Some(s);
                    }
                }
                CLAIM_AUD => {
                    if let Value::Array(arr) = value {
                        let mut audiences = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                audiences.push(s);
                            }
                        }
                        core.aud = Some(audiences);
                    }
                }
                CLAIM_EXP => {
                    if let Value::Integer(i) = value {
                        core.exp = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_NBF => {
                    if let Value::Integer(i) = value {
                        core.nbf = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CTI => {
                    match value {
                        Value::Bytes(b) => {
                            core.cti = Some(String::from_utf8_lossy(&b).to_string());
                        }
                        Value::Text(s) => {
                            core.cti = Some(s);
                        }
                        _ => {}
                    }
                }
                CLAIM_CATREPLAY => {
                    if let Value::Text(s) = value {
                        cat.catreplay = Some(s);
                    }
                }
                CLAIM_CATPOR => {
                    if let Value::Bool(b) = value {
                        cat.catpor = Some(b);
                    }
                }
                CLAIM_CATV => {
                    if let Value::Text(s) = value {
                        cat.catv = Some(s);
                    }
                }
                CLAIM_CATNIP => {
                    if let Value::Array(arr) = value {
                        let mut nips = Vec::new();
                        for item in arr {
                            match item {
                                Value::Text(s) => {
                                    nips.push(NetworkIdentifier::IpAddress(s));
                                },
                                Value::Map(map) => {
                                    for (k, v) in map {
                                        if let Value::Text(key_str) = k {
                                            match key_str.as_str() {
                                                "ip_range" => {
                                                    if let Value::Text(range) = v {
                                                        nips.push(NetworkIdentifier::IpRange(range));
                                                    }
                                                },
                                                "asn" => {
                                                    if let Value::Integer(asn) = v {
                                                        if let Ok(asn_u32) = TryInto::<u32>::try_into(asn) {
                                                            nips.push(NetworkIdentifier::Asn(asn_u32));
                                                        }
                                                    }
                                                },
                                                "asn_range" => {
                                                    if let Value::Array(range_arr) = v {
                                                        if range_arr.len() == 2 {
                                                            if let (Value::Integer(start), Value::Integer(end)) = (&range_arr[0], &range_arr[1]) {
                                                                if let (Ok(start_u32), Ok(end_u32)) = 
                                                                    (TryInto::<u32>::try_into(*start), TryInto::<u32>::try_into(*end)) {
                                                                    nips.push(NetworkIdentifier::AsnRange(start_u32, end_u32));
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                _ => {}
                                            }
                                        }
                                    }
                                },
                                _ => {}
                            }
                        }
                        cat.catnip = Some(nips);
                    }
                }
                CLAIM_CATU => {
                    if let Value::Integer(i) = value {
                        cat.catu = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CATM => {
                    if let Value::Text(s) = value {
                        cat.catm = Some(s);
                    }
                }
                CLAIM_CATALPN => {
                    if let Value::Array(arr) = value {
                        let mut alpns = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                alpns.push(s);
                            }
                        }
                        cat.catalpn = Some(alpns);
                    }
                }
                CLAIM_CATH => {
                    if let Value::Array(arr) = value {
                        let mut patterns = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                patterns.push(UriPattern::Exact(s));
                            } else if let Value::Map(pattern_map) = item {
                                if let Some((key, val)) = pattern_map.into_iter().next() {
                                    if let (Value::Text(pattern_type), Value::Text(pattern_value)) = (key, val) {
                                        match pattern_type.as_str() {
                                            "exact" => patterns.push(UriPattern::Exact(pattern_value)),
                                            "prefix" => patterns.push(UriPattern::Prefix(pattern_value)),
                                            "suffix" => patterns.push(UriPattern::Suffix(pattern_value)),
                                            "regex" => patterns.push(UriPattern::Regex(pattern_value)),
                                            "hash" => patterns.push(UriPattern::Hash(pattern_value)),
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        cat.cath = Some(patterns);
                    }
                }
                CLAIM_CATGEOISO3166 => {
                    if let Value::Array(arr) = value {
                        let mut countries = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                countries.push(s);
                            }
                        }
                        cat.catgeoiso3166 = Some(countries);
                    }
                }
                CLAIM_CATGEOCOORD => {
                    if let Value::Map(map) = value {
                        let mut lat = None;
                        let mut lon = None;
                        let mut accuracy = None;

                        for (k, v) in map {
                            if let Value::Text(key_str) = k {
                                match key_str.as_str() {
                                    "lat" => {
                                        if let Value::Float(f) = v {
                                            lat = Some(f);
                                        }
                                    }
                                    "lon" => {
                                        if let Value::Float(f) = v {
                                            lon = Some(f);
                                        }
                                    }
                                    "accuracy" => {
                                        if let Value::Float(f) = v {
                                            accuracy = Some(f);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }

                        if let (Some(lat), Some(lon)) = (lat, lon) {
                            cat.catgeocoord = Some(GeoCoordinate { lat, lon, accuracy });
                        }
                    }
                }
                CLAIM_GEOHASH => {
                    if let Value::Text(s) = value {
                        cat.geohash = Some(s);
                    }
                }
                CLAIM_CATGEOALT => {
                    if let Value::Integer(i) = value {
                        cat.catgeoalt = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CATTPK => {
                    if let Value::Text(s) = value {
                        cat.cattpk = Some(s);
                    }
                }
                CLAIM_SUB => {
                    if let Value::Text(s) = value {
                        informational.sub = Some(s);
                    }
                }
                CLAIM_IAT => {
                    if let Value::Integer(i) = value {
                        informational.iat = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CATIFDATA => {
                    if let Value::Text(s) = value {
                        informational.catifdata = Some(s);
                    }
                }
                CLAIM_CNF => {
                    if let Value::Text(s) = value {
                        dpop.cnf = Some(s);
                    }
                }
                CLAIM_CATDPOP => {
                    if let Value::Text(s) = value {
                        dpop.catdpop = Some(s);
                    }
                }
                CLAIM_CATIF => {
                    if let Value::Text(s) = value {
                        request.catif = Some(s);
                    }
                }
                CLAIM_CATR => {
                    if let Value::Text(s) = value {
                        request.catr = Some(s);
                    }
                }
                _ => {
                    custom.insert(claim_id, value);
                }
            }
        }

        Ok(CatToken { core, cat, informational, dpop, request, custom })
    }
}