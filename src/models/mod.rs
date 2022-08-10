//! Models used in in-toto

mod envelope;
mod helpers;
mod layout;
mod link;
mod metadata;
mod predicate;
mod state;

pub use helpers::*;
pub use layout::*;
pub use link::*;
pub use metadata::*;
pub use predicate::{PredicateLayout, PredicateVersion, PredicateWrapper};
pub use state::{StateLayout, StateWrapper, StatementVer};

#[cfg(test)]
mod test {
    use once_cell::sync::Lazy;

    use super::{LinkMetadata, LinkMetadataBuilder};

    pub static BLANK_META: Lazy<LinkMetadata> = Lazy::new(|| {
        let builder = LinkMetadataBuilder::default();
        builder.build().unwrap()
    });
}
