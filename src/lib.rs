pub mod claims;
pub mod crypto;
pub mod cwt;
pub mod error;
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
pub use error::*;
pub use token::*;
