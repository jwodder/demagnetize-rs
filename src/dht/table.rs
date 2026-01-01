use super::{NodeId, NodeInfo};
use crate::types::InfoHash;
use std::time::SystemTime;
use thiserror::Error;

// BEP 5's `K` value
const MAX_BUCKET_SIZE: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NodeTable<T>(Subtable<T>);

impl<T> NodeTable<T> {
    pub(super) fn new() -> Self {
        NodeTable(Subtable::Bucket(Bucket::new()))
    }

    /// Returns the serialized information needed to save the routing table to
    /// disk
    // - Should this include buckets' "last changed" timestamps?
    // - Should this include nodes' "active" timestamps?
    pub(super) fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    pub(super) fn deserialize(_bs: &[u8]) -> Result<NodeTable<T>, DeserializeNodeTableError> {
        todo!()
    }

    /// Insert a node into the table
    // Possible results:
    //  - New node is inserted (possibly replacing a bad node)
    //  - New node is discarded
    //  - Bucket is split and new node is inserted
    //   - Should this technically be done as soon as the bucket becomes full
    //     rather than on trying to add to a full bucket?
    //  - Most questionable node needs to be pinged first
    #[expect(clippy::needless_pass_by_ref_mut)]
    pub(super) fn insert(&mut self, _node: NodeInfo<T>) -> InsertResult<T> {
        todo!()
    }

    /// Return the nodes closest to the given info hash
    // TODO: How many nodes should be returned?
    pub(super) fn nearest_nodes(&self, _info_hash: InfoHash) -> Vec<NodeInfo<T>> {
        todo!()
    }

    /// Mark a node as currently active after a successful ping
    #[expect(clippy::needless_pass_by_ref_mut)]
    pub(super) fn mark_active(&mut self, _id: NodeId) {
        todo!()
    }

    /// Mark a node as having failed to respond to multiple queries in a row
    #[expect(clippy::needless_pass_by_ref_mut)]
    pub(super) fn mark_bad(&mut self, _id: NodeId) {
        // Should this remove the bad node immediately or just wait until the
        // bucket needs to insert something?
        todo!()
    }

    // For each (nonempty?) bucket whose "last_changed" field is > 15 minutes
    // old, return a random node ID in the bucket's range (which the caller
    // will then send "find_nodes" queries for)
    //
    // TODO: What should happen to such buckets afterwards?  Could this result
    // in an old bucket repeatedly generating a new refresh target on every
    // call?
    pub(super) fn refresh_targets(&self) -> Vec<NodeId> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Subtable<T> {
    Bucket(Bucket<T>),
    Split {
        zero: Box<Subtable<T>>,
        one: Box<Subtable<T>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Bucket<T> {
    last_changed: SystemTime,
    nodes: Vec<(NodeInfo<T>, SystemTime)>,
}

impl<T> Bucket<T> {
    pub(super) fn new() -> Self {
        Bucket {
            last_changed: SystemTime::now(),
            nodes: Vec::with_capacity(MAX_BUCKET_SIZE),
        }
    }

    fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn is_full(&self) -> bool {
        self.nodes.len() >= MAX_BUCKET_SIZE
    }

    fn split(self, bit_depth: usize) -> Subtable<T> {
        let mut zero_nodes = Vec::with_capacity(MAX_BUCKET_SIZE);
        let mut one_nodes = Vec::with_capacity(MAX_BUCKET_SIZE);
        for n in self.nodes {
            if n.0.id.get_bit(bit_depth) {
                one_nodes.push(n);
            } else {
                zero_nodes.push(n);
            }
        }
        Subtable::Split {
            zero: Box::new(Subtable::Bucket(Bucket::from_nodes(zero_nodes))),
            one: Box::new(Subtable::Bucket(Bucket::from_nodes(one_nodes))),
        }
    }

    fn from_nodes(nodes: Vec<(NodeInfo<T>, SystemTime)>) -> Bucket<T> {
        let last_changed = nodes
            .iter()
            .map(|n| n.1)
            .max()
            .unwrap_or_else(SystemTime::now);
        Bucket {
            last_changed,
            nodes,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InsertResult<T> {
    /// The new node was inserted into the table
    Inserted,

    /// The new node was discarded due to the bucket being full
    Discarded,

    /// Before we can determine whether the new node can be inserted, the given
    /// node needs to be pinged to see whether it's still active
    NeedToPing(NodeInfo<T>),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("TODO")]
pub(super) struct DeserializeNodeTableError;
