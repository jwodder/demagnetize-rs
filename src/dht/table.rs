use super::NodeId;
use std::time::SystemTime;

// BEP 5's `K` value
const MAX_BUCKET_SIZE: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum NodeTable<T> {
    Bucket(Bucket<T>),
    Split {
        zero: Box<NodeTable<T>>,
        one: Box<NodeTable<T>>,
    },
}

impl<T> NodeTable<T> {
    pub(super) fn new() -> Self {
        NodeTable::Bucket(Bucket::new())
    }

    pub(super) fn nearest(&self, _n: NodeId) -> Vec<&NodeInfo<T>> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Bucket<T> {
    last_changed: SystemTime,
    nodes: Vec<NodeInfo<T>>,
}

impl<T> Bucket<T> {
    pub(super) fn new() -> Self {
        Bucket {
            last_changed: SystemTime::now(),
            nodes: Vec::with_capacity(MAX_BUCKET_SIZE),
        }
    }

    pub(super) fn split(self, bit_depth: usize) -> NodeTable<T> {
        let mut zero_nodes = Vec::with_capacity(MAX_BUCKET_SIZE);
        let mut one_nodes = Vec::with_capacity(MAX_BUCKET_SIZE);
        for n in self.nodes {
            if n.id.get_bit(bit_depth) {
                one_nodes.push(n);
            } else {
                zero_nodes.push(n);
            }
        }
        NodeTable::Split {
            zero: Box::new(NodeTable::Bucket(Bucket::from_nodes(zero_nodes))),
            one: Box::new(NodeTable::Bucket(Bucket::from_nodes(one_nodes))),
        }
    }

    fn from_nodes(nodes: Vec<NodeInfo<T>>) -> Bucket<T> {
        let last_changed = nodes
            .iter()
            .map(|n| n.active)
            .max()
            .unwrap_or_else(SystemTime::now);
        Bucket {
            last_changed,
            nodes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NodeInfo<T> {
    id: NodeId,
    ip: T,
    port: u16,
    active: SystemTime,
}
