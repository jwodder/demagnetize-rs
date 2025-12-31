use super::NodeId;
use super::table::NodeTable;
use std::net::{Ipv4Addr, Ipv6Addr};

// TODO: See <https://ryhl.io/blog/actors-with-tokio/>
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DhtActor {
    my_id: NodeId,
    ipv4: NodeTable<Ipv4Addr>,
    ipv6: NodeTable<Ipv6Addr>,
}

// TODO: Operations to implement:
// - Saving to a file
// - Restoring from a file
// - Looking up the closest node(s) to an info hash
// - Adding a node in response to a PORT peer message
// - Refreshing buckets after 15 minutes of inactivity
// - Rebuilding in response to a change in our IP address
// - "Upon inserting the first node into its routing table and when starting up
//   thereafter, the node should attempt to find the closest nodes in the DHT
//   to itself.  It does this by issuing find_node messages to closer and
//   closer nodes until it cannot find any closer."
