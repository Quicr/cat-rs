pub mod claims;
pub mod crypto;
pub mod cwt;
pub mod dpop;
pub mod error;
pub mod jwk;
pub mod moqt;
pub mod token;

// Conditional trie module selection based on features
// qp-trie takes precedence if both are enabled
#[cfg(feature = "qp-trie")]
mod trie_qp;
#[cfg(feature = "qp-trie")]
pub use trie_qp::*;

#[cfg(all(feature = "builtin-trie", not(feature = "qp-trie")))]
mod trie;
#[cfg(all(feature = "builtin-trie", not(feature = "qp-trie")))]
pub use trie::*;

pub use claims::*;
pub use crypto::*;
pub use cwt::*;
pub use dpop::*;
pub use error::*;
pub use jwk::*;
pub use moqt::*;
pub use token::*;
