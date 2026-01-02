use super::{NodeId, NodeInfo};
use crate::types::InfoHash;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use thiserror::Error;
use tokio_util::either::Either;

// BEP 5's `K` value
const MAX_BUCKET_SIZE: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DhtTable {
    my_id: NodeId,
    ipv4: NodeTable<Ipv4Addr>,
    ipv6: NodeTable<Ipv6Addr>,
}

impl DhtTable {
    pub(crate) fn new<R: Rng>(mut rng: R) -> DhtTable {
        let my_id = NodeId(rng.random());
        let ipv4 = NodeTable::new();
        let ipv6 = NodeTable::new();
        DhtTable { my_id, ipv4, ipv6 }
    }

    /// Returns the serialized information needed to save the routing table to
    /// disk
    // - Should this include buckets' "last changed" timestamps?
    // - Should this include nodes' "active" timestamps?
    pub(super) fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    pub(crate) fn deserialize(_bs: &[u8]) -> Result<DhtTable, DeserializeDhtError> {
        todo!()
    }

    pub(super) fn my_id(&self) -> NodeId {
        self.my_id
    }

    /// Insert a node into the table
    // Possible results:
    //  - New node is inserted (possibly replacing a bad node)
    //  - New node is discarded
    //  - Bucket is split and new node is inserted
    //   - Should this technically be done as soon as the bucket becomes full
    //     rather than on trying to add to a full bucket?
    //  - Most questionable node needs to be pinged first
    pub(super) fn insert(&mut self, node: NodeInfo<IpAddr>) -> InsertResult<IpAddr> {
        match node.discriminate() {
            Either::Left(n4) => self.ipv4.insert(n4).into(),
            Either::Right(n6) => self.ipv6.insert(n6).into(),
        }
    }

    /// Return the nodes closest to the given info hash
    pub(super) fn nearest_nodes(&self, info_hash: InfoHash) -> Vec<NodeInfo<IpAddr>> {
        self.ipv4
            .nearest_nodes(info_hash)
            .into_iter()
            .map(NodeInfo::<IpAddr>::from)
            .chain(
                self.ipv6
                    .nearest_nodes(info_hash)
                    .into_iter()
                    .map(NodeInfo::<IpAddr>::from),
            )
            .collect()
    }

    /// Mark a node as currently active after a successful ping
    pub(super) fn mark_active(&mut self, id: NodeId, is_ipv6: bool) {
        if is_ipv6 {
            self.ipv6.mark_active(id);
        } else {
            self.ipv4.mark_active(id);
        }
    }

    /// Mark a node as having failed to respond to multiple queries in a row
    pub(super) fn mark_bad(&mut self, id: NodeId, is_ipv6: bool) {
        if is_ipv6 {
            self.ipv6.mark_bad(id);
        } else {
            self.ipv4.mark_bad(id);
        }
    }

    // For each (nonempty?) bucket whose "last_changed" field is > 15 minutes
    // old, return a random node ID in the bucket's range (which the caller
    // will then send "find_nodes" queries for)
    //
    // TODO: What should happen to such buckets afterwards?  Could this result
    // in an old bucket repeatedly generating a new refresh target on every
    // call?
    pub(super) fn refresh_targets(&self) -> Vec<NodeId> {
        let mut targets = self.ipv4.refresh_targets();
        targets.extend(self.ipv6.refresh_targets());
        targets
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NodeTable<T>(Subtable<T>);

impl<T> NodeTable<T> {
    pub(super) fn new() -> Self {
        NodeTable(Subtable::Bucket(Bucket::new()))
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

impl From<InsertResult<Ipv4Addr>> for InsertResult<IpAddr> {
    fn from(value: InsertResult<Ipv4Addr>) -> InsertResult<IpAddr> {
        match value {
            InsertResult::Inserted => InsertResult::Inserted,
            InsertResult::Discarded => InsertResult::Discarded,
            InsertResult::NeedToPing(node) => InsertResult::NeedToPing(node.into()),
        }
    }
}

impl From<InsertResult<Ipv6Addr>> for InsertResult<IpAddr> {
    fn from(value: InsertResult<Ipv6Addr>) -> InsertResult<IpAddr> {
        match value {
            InsertResult::Inserted => InsertResult::Inserted,
            InsertResult::Discarded => InsertResult::Discarded,
            InsertResult::NeedToPing(node) => InsertResult::NeedToPing(node.into()),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("TODO")]
pub(super) struct DeserializeDhtError;
