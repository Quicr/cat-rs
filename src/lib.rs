pub mod claims;
pub mod crypto;
pub mod cwt;
pub mod dpop;
pub mod error;
pub mod jwk;
pub mod moqt;
pub mod token;

// Conditional trie module selection based on features
#[cfg(feature = "qp-trie")]
mod trie_qp;
#[cfg(feature = "qp-trie")]
pub use trie_qp::*;

#[cfg(feature = "builtin-trie")]
mod trie;
#[cfg(feature = "builtin-trie")]
pub use trie::*;

pub use claims::*;
pub use crypto::*;
pub use cwt::*;
pub use dpop::*;
pub use error::*;
pub use jwk::*;
pub use moqt::*;
pub use token::*;
