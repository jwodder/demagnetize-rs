// TODO: Operations to implement:
// - Looking up the peers for an info hash
// - Refreshing buckets after 15 minutes of inactivity
//  - Do this via a task that queries expired buckets every 60 seconds
//  - Exactly what nodes should the "find_nodes" queries be sent to?
// - Rebuilding in response to a change in our IP address
// - "Upon inserting the first node into its routing table and when starting up
//   thereafter, the node should attempt to find the closest nodes in the DHT
//   to itself.  It does this by issuing find_node messages to closer and
//   closer nodes until it cannot find any closer."

#![expect(unused_variables)]
use super::NodeId;
use super::messages;
use super::table::NodeTable;
use crate::consts::UDP_PACKET_LEN;
use crate::peer::Peer;
use crate::types::InfoHash;
use crate::util::{ErrorChain, decode_bencode};
use bendy::encoding::ToBencode;
use bytes::{Bytes, BytesMut};
use rand::Rng;
use std::collections::{HashMap, hash_map::Entry};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

const ACTION_CHANNEL_SIZE: usize = 64;
const TRANSACTION_ID_LENGTH: usize = 2;

#[derive(Debug)]
pub(crate) struct DhtActor {
    my_id: NodeId,
    ipv4: NodeTable<Ipv4Addr>,
    ipv6: NodeTable<Ipv6Addr>,
    ipv4_socket: UdpSocket,
    ipv6_socket: UdpSocket,
    action_recv: mpsc::Receiver<ActorMessage>,
    awaiting_responses: HashMap<SocketAddr, HashMap<Bytes, InFlight>>,
}

impl DhtActor {
    pub(crate) async fn new<R: Rng>(mut rng: R) -> std::io::Result<(DhtActor, DhtHandle)> {
        // TODO: Use a dedicated error type?
        let ipv4_socket = UdpSocket::bind("0.0.0.0:0").await?;
        match ipv4_socket.local_addr() {
            Ok(addr) => log::debug!(
                "DHT node using UDP port {} for IPv4 communication",
                addr.port()
            ),
            Err(e) => {
                log::warn!("Could not determine local address for DHT UDP socket on IPv4: {e}");
            }
        }
        let ipv6_socket = UdpSocket::bind("[::]:0").await?;
        match ipv6_socket.local_addr() {
            Ok(addr) => log::debug!(
                "DHT node using UDP port {} for IPv6 communication",
                addr.port()
            ),
            Err(e) => {
                log::warn!("Could not determine local address for DHT UDP socket on IPv6: {e}");
            }
        }
        let my_id = NodeId(rng.random());
        let ipv4 = NodeTable::new();
        let ipv6 = NodeTable::new();
        let (sender, receiver) = mpsc::channel(ACTION_CHANNEL_SIZE);
        let actor = DhtActor {
            my_id,
            ipv4,
            ipv6,
            ipv4_socket,
            ipv6_socket,
            action_recv: receiver,
            awaiting_responses: HashMap::new(),
        };
        let handle = DhtHandle { sender };
        Ok((actor, handle))
    }

    /// Returns the serialized information needed to save the routing table to
    /// disk
    fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    pub(crate) fn deserialize(_bs: &[u8]) -> Result<(DhtActor, DhtHandle), DeserializeDhtError> {
        todo!()
    }

    pub(crate) async fn run(mut self) {
        loop {
            let mut ipv4_packet = BytesMut::with_capacity(UDP_PACKET_LEN);
            let mut ipv6_packet = BytesMut::with_capacity(UDP_PACKET_LEN);
            tokio::select! {
                // TODO: Use async-channel instead of tokio's mpsc so we don't
                // get into trouble with mutability of the receiver?
                Some(msg) = self.action_recv.recv() => {
                    match msg {
                        ActorMessage::Serialize {response_to} => {
                            let data = self.serialize();
                            let _ = response_to.send(data);
                        }
                        ActorMessage::LookupPeers {info_hash, response_to} => todo!(),
                        ActorMessage::NewNode {ip, port} => self.ping(None, ip, port).await,
                        ActorMessage::Shutdown => return,
                    }
                }
                r = self.ipv4_socket.recv_buf_from(&mut ipv4_packet) => {
                    match r {
                        Ok((_, addr)) => self.handle_rpc_message(ipv6_packet, addr),
                        Err(e) => log::warn!("Error receiving incoming DHT packet on IPv4: {e}"),
                    }
                }
                r = self.ipv6_socket.recv_buf_from(&mut ipv6_packet) => {
                    match r {
                        Ok((_, addr)) => self.handle_rpc_message(ipv6_packet, addr),
                        Err(e) => log::warn!("Error receiving incoming DHT packet on IPv6: {e}"),
                    }
                }
                // TODO: Handle expiring query transactions
                // TODO: Handle bucket refresh jobs
            }
        }
    }

    fn handle_rpc_message(&mut self, msg: BytesMut, sender: SocketAddr) {
        let (in_flight, is_err) = {
            let Entry::Occupied(mut expected) = self.awaiting_responses.entry(sender) else {
                log::debug!("DHT node received unexpected packet from {sender}; discarding");
                return;
            };
            let is_err = match messages::get_message_type(&msg) {
                Ok(b"q") => {
                    log::debug!("DHT node received a query from {sender}; ignoring");
                    return;
                }
                Ok(b"r") => false,
                Ok(b"e") => true,
                Ok(_) => return,  // TODO: Log
                Err(_) => return, // TODO: Log
            };
            let transaction_id = match messages::get_transaction_id(&msg) {
                Ok(t) => t,
                Err(e) => {
                    log::debug!(
                        "DHT node received packet from {sender} without valid transaction ID: {}",
                        ErrorChain(e)
                    );
                    return;
                }
            };
            let Some(in_flight) = expected.get_mut().remove(&transaction_id) else {
                log::debug!("DHT node received reply from {sender} with unexpected transaction ID");
                return;
            };
            if expected.get().is_empty() {
                expected.remove();
            }
            (in_flight, is_err)
        };
        match in_flight {
            InFlight::Ping {
                ip, port, node_id, ..
            } => {
                if is_err {
                    match decode_bencode::<messages::ErrorResponse>(&msg) {
                        Ok(r) => {
                            let e = messages::RpcError::from(r);
                            log::debug!(
                                "DHT node received error from {sender} in response to ping: {}",
                                ErrorChain(e)
                            );
                        }
                        Err(e) => log::debug!(
                            "DHT node received malformed error message from node at {sender} in response to ping: {}",
                            ErrorChain(e)
                        ),
                    }
                    // TODO: Should the ping attempt be discarded?  Retried as
                    // though it timed out?  Should the node be marked as bad?
                } else {
                    match decode_bencode::<messages::PingResponse>(&msg) {
                        Ok(r) => {
                            let about_client = if let Some(ref v) = r.client {
                                format!(" (client = {v:?})")
                            } else {
                                String::new()
                            };
                            log::debug!(
                                "DHT node received ping response from node {} at {sender}{}",
                                r.node_id,
                                about_client
                            );
                            if let Some(old_id) = node_id {
                                if old_id == r.node_id {
                                    todo!("Mark node as good")
                                } else {
                                    todo!("Remove old node/mark it bad and insert new one")
                                }
                            } else {
                                todo!("Insert node into table")
                            }
                        }
                        Err(e) => {
                            log::debug!(
                                "DHT node received malformed ping response from node at {sender}: {}",
                                ErrorChain(e)
                            );
                            // TODO: Should the ping attempt be discarded?
                            // Retried as though it timed out?  Should the node
                            // be marked as bad?
                        }
                    }
                }
            }
        }
    }

    async fn ping(&mut self, node_id: Option<NodeId>, ip: IpAddr, port: u16) {
        let transaction_id = gen_transaction_id();
        let addr = SocketAddr::from((ip, port));
        let query = messages::PingQuery {
            transaction_id: transaction_id.clone(),
            client: None, // TODO
            node_id: self.my_id,
            read_only: Some(true),
        };
        let msg = match query.to_bencode() {
            Ok(msg) => msg,
            Err(e) => {
                log::warn!(
                    "Failed to construct DHT ping query packet for {addr}: {}",
                    ErrorChain(e)
                );
                return;
            }
        };
        let r = match ip {
            IpAddr::V4(_) => self.ipv4_socket.send_to(&msg, addr).await,
            IpAddr::V6(_) => self.ipv6_socket.send_to(&msg, addr).await,
        };
        if let Err(e) = r {
            log::warn!("Failed to send DHT ping query to {addr}: {e}");
            return;
        }
        let in_flight = InFlight::Ping {
            ip,
            port,
            node_id,
            failures: 0,
        };
        self.awaiting_responses
            .entry(addr)
            .or_default()
            .insert(transaction_id, in_flight);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DhtHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl DhtHandle {
    pub(crate) async fn serialize(&self) -> Vec<u8> {
        let (sender, receiver) = oneshot::channel();
        let msg = ActorMessage::Serialize {
            response_to: sender,
        };
        let _ = self.sender.send(msg).await;
        // TODO: Error handling:
        receiver.await.expect("Actor killed")
    }

    pub(crate) async fn lookup_peers(&self, info_hash: InfoHash) -> Vec<Peer> {
        let (sender, receiver) = oneshot::channel();
        let msg = ActorMessage::LookupPeers {
            info_hash,
            response_to: sender,
        };
        let _ = self.sender.send(msg).await;
        // TODO: Error handling:
        receiver.await.expect("Actor killed")
    }

    pub(crate) async fn new_node(&self, ip: IpAddr, port: u16) {
        let msg = ActorMessage::NewNode { ip, port };
        let _ = self.sender.send(msg).await;
    }

    pub(crate) async fn shutdown(&self) {
        // TODO: Should this wait for completion?
        let msg = ActorMessage::Shutdown;
        let _ = self.sender.send(msg).await;
    }
}

#[derive(Debug)]
pub(crate) enum ActorMessage {
    Serialize {
        response_to: oneshot::Sender<Vec<u8>>,
    },
    LookupPeers {
        info_hash: InfoHash,
        response_to: oneshot::Sender<Vec<Peer>>,
    },
    NewNode {
        ip: IpAddr,
        port: u16,
    },
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InFlight {
    Ping {
        ip: IpAddr,
        port: u16,
        node_id: Option<NodeId>,
        failures: usize,
    },
    // find_node
    // get_peers
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("TODO")]
pub(crate) struct DeserializeDhtError;

fn gen_transaction_id() -> Bytes {
    let data: [u8; TRANSACTION_ID_LENGTH] = rand::rng().random();
    Bytes::from(data.to_vec())
}
