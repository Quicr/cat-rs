// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Prelude module for convenient imports
//!
//! ```rust,ignore
//! use cat_impl::prelude::*;
//! ```

pub use crate::claims::{
    BinaryMatch, CatDpopSettings, CatToken, ConfirmationClaim, MoqtAction, MoqtClaims, MoqtScope,
    NamespaceMatch,
};
pub use crate::crypto::{
    CryptographicAlgorithm, Es256Algorithm, HmacSha256Algorithm, Ps256Algorithm,
};
pub use crate::dpop::{
    DpopProof, DpopValidator, compute_access_token_hash, confirmation_from_jwk,
    confirmation_matches_jwk, generate_jti,
};
pub use crate::error::CatError;
pub use crate::jwk::Jwk;
pub use crate::moqt::{MoqtAuthRequest, MoqtAuthResult, MoqtScopeBuilder, MoqtValidator};
pub use crate::token::{CatTokenBuilder, CatTokenValidator, decode_token, encode_token};
