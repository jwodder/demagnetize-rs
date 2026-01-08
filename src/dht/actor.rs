#![expect(unused_variables, clippy::needless_pass_by_ref_mut)]
use super::messages;
use super::{NodeId, NodeInfo};
use crate::consts::UDP_PACKET_LEN;
use crate::peer::Peer;
use crate::types::InfoHash;
use bytes::{BufMut, Bytes, BytesMut};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

const ACTION_CHANNEL_SIZE: usize = 64;

#[derive(Debug)]
pub(crate) struct DhtActor {
    my_id: NodeId,
    ipv4_socket: UdpSocket,
    ipv6_socket: UdpSocket,
    action_recv: mpsc::Receiver<ActorMessage>,
    txn_gen: TransactionGenerator,
    sessions: HashMap<usize, LookupSession>,
    next_session_id: usize,
    timeout: Duration,
    bootstrap_nodes: Vec<InetAddr>,
}

impl DhtActor {
    pub(crate) async fn new<R: Rng>(
        mut rng: R,
        timeout: Duration,
        bootstrap_nodes: Vec<InetAddr>,
    ) -> Result<(DhtActor, DhtHandle), CreateDhtActorError> {
        let my_id = NodeId(rng.random());
        let ipv4_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(CreateDhtActorError::BindIPv4)?;
        match ipv4_socket.local_addr() {
            Ok(addr) => log::trace!(
                "DHT node using UDP port {} for IPv4 communication",
                addr.port()
            ),
            Err(e) => {
                log::warn!("Could not determine local address for DHT UDP socket on IPv4: {e}");
            }
        }
        let ipv6_socket = UdpSocket::bind("[::]:0")
            .await
            .map_err(CreateDhtActorError::BindIPv6)?;
        match ipv6_socket.local_addr() {
            Ok(addr) => log::trace!(
                "DHT node using UDP port {} for IPv6 communication",
                addr.port()
            ),
            Err(e) => {
                log::warn!("Could not determine local address for DHT UDP socket on IPv6: {e}");
            }
        }
        let (sender, receiver) = mpsc::channel(ACTION_CHANNEL_SIZE);
        let actor = DhtActor {
            my_id,
            ipv4_socket,
            ipv6_socket,
            action_recv: receiver,
            txn_gen: TransactionGenerator::new(),
            sessions: HashMap::new(),
            next_session_id: 0,
            timeout,
            bootstrap_nodes,
        };
        let handle = DhtHandle { sender };
        Ok((actor, handle))
    }

    pub(crate) async fn run(mut self) {
        // TODO: Resolve bootstrap node addresses
        loop {
            let mut ipv4_packet = BytesMut::with_capacity(UDP_PACKET_LEN);
            let mut ipv6_packet = BytesMut::with_capacity(UDP_PACKET_LEN);
            tokio::select! {
                Some(msg) = self.action_recv.recv() => {
                    match msg {
                        ActorMessage::LookupPeers {info_hash, response_to} => todo!(),
                        ActorMessage::Shutdown => return,
                    }
                }
                r = self.ipv4_socket.recv_buf_from(&mut ipv4_packet) => {
                    match r {
                        Ok((_, addr)) => todo!(),
                        Err(e) => log::warn!("Error receiving incoming DHT packet on IPv4: {e}"),
                    }
                }
                r = self.ipv6_socket.recv_buf_from(&mut ipv6_packet) => {
                    match r {
                        Ok((_, addr)) => todo!(),
                        Err(e) => log::warn!("Error receiving incoming DHT packet on IPv6: {e}"),
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DhtHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl DhtHandle {
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

    pub(crate) async fn shutdown(&self) {
        // TODO: Should this wait for completion?
        let msg = ActorMessage::Shutdown;
        let _ = self.sender.send(msg).await;
    }
}

#[derive(Debug)]
pub(crate) enum ActorMessage {
    LookupPeers {
        info_hash: InfoHash,
        response_to: oneshot::Sender<Vec<Peer>>,
    },
    Shutdown,
}

#[derive(Debug, Error)]
pub(crate) enum CreateDhtActorError {
    #[error("failed to create UDP socket over IPv4")]
    BindIPv4(#[source] std::io::Error),
    #[error("failed to create UDP socket over IPv6")]
    BindIPv6(#[source] std::io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransactionGenerator(u32);

impl TransactionGenerator {
    fn new() -> Self {
        Self(0)
    }

    fn generate(&mut self) -> Bytes {
        let t = self.0;
        self.0 = self.0.wrapping_add(1);
        let mut buf = BytesMut::with_capacity(4);
        buf.put_u32(t);
        buf.freeze()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LookupSession {
    info_hash: InfoHash,
    using_ipv6: bool,
    nodes: NodeSpace,
    to_query: Vec<SocketAddr>,
}

impl LookupSession {
    fn handle_message(&mut self, sender: SocketAddr, tid: &[u8], msg: &[u8]) -> bool {
        todo!()
    }

    fn handle_timeout(&mut self, sender: SocketAddr, tid: &[u8]) {
        todo!()
    }

    fn get_outgoing(
        &mut self,
        txn_gen: &mut TransactionGenerator,
    ) -> Vec<(SocketAddr, messages::GetPeersQuery)> {
        todo!()
    }

    fn done(&mut self) -> bool {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeSpace;

impl NodeSpace {
    fn new(info_hash: InfoHash) -> NodeSpace {
        todo!()
    }

    fn add(&mut self, node: NodeInfo) {
        todo!()
    }

    fn closest_unqueried(&mut self, k: usize) -> Vec<NodeInfo> {
        // The returned nodes are marked queried as they're returned
        todo!()
    }

    fn closest_responsive(&self, k: usize) -> Vec<NodeInfo> {
        todo!()
    }

    fn mark_responsive(&mut self, id: NodeId) {
        todo!()
    }

    fn addr2node(&self, addr: SocketAddr) -> Option<NodeInfo> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InetAddr {
    host: url::Host,
    port: u16,
}
