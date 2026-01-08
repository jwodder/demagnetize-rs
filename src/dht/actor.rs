#![expect(unused_variables, clippy::needless_pass_by_ref_mut)]
use super::messages;
use super::{NodeId, NodeInfo};
use crate::consts::UDP_PACKET_LEN;
use crate::peer::Peer;
use crate::types::InfoHash;
use bendy::encoding::ToBencode;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::stream::{self, StreamExt};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot},
    time::sleep,
};
use tokio_util::task::JoinMap;

const ACTION_CHANNEL_SIZE: usize = 64;
const RESOLVE_JOB_LIMIT: usize = 10;
const CLOSEST: usize = 8;

#[derive(Debug)]
pub(crate) struct DhtActor {
    my_id: NodeId,
    udp: UdpHandle,
    action_recv: mpsc::Receiver<ActorMessage>,
    txn_gen: TransactionGenerator,
    sessions: HashMap<usize, LookupSession>,
    lookup_senders: HashMap<usize, oneshot::Sender<FoundPeers>>,
    next_session_id: usize,
    timeout: Duration,
    bootstrap_nodes: Vec<InetAddr>,
    txn_timeouts: JoinMap<(SocketAddr, Bytes), ()>,
}

impl DhtActor {
    pub(crate) async fn new<R: Rng>(
        mut rng: R,
        timeout: Duration,
        bootstrap_nodes: Vec<InetAddr>,
    ) -> Result<(DhtActor, DhtHandle), CreateDhtActorError> {
        let my_id = NodeId(rng.random());
        let udp = UdpHandle::new().await?;
        let (sender, receiver) = mpsc::channel(ACTION_CHANNEL_SIZE);
        let actor = DhtActor {
            my_id,
            udp,
            action_recv: receiver,
            txn_gen: TransactionGenerator::new(),
            sessions: HashMap::new(),
            lookup_senders: HashMap::new(),
            next_session_id: 0,
            timeout,
            bootstrap_nodes,
            txn_timeouts: JoinMap::new(),
        };
        let handle = DhtHandle { sender };
        Ok((actor, handle))
    }

    pub(crate) async fn run(mut self) {
        let bootstrap_addrs = self.resolve_bootstrap().await;
        if bootstrap_addrs.is_empty() {
            log::error!("Failed to resolve any addresses for DHT bootstrap nodes");
            return;
        }
        loop {
            tokio::select! {
                Some(msg) = self.action_recv.recv() => {
                    match msg {
                        ActorMessage::LookupPeers {info_hash, response_to} => {
                            let mut session = LookupSession::new(info_hash, self.my_id, self.udp.using_ipv6());
                            session.bootstrap(bootstrap_addrs.clone());
                            let outgoing = session.get_outgoing(&mut self.txn_gen);
                            let sid = self.next_session_id;
                            self.sessions.insert(sid, session);
                            self.lookup_senders.insert(sid, response_to);
                            for (addr, query) in outgoing {
                                self.send_query(addr, query).await;
                            }
                        }
                        ActorMessage::Shutdown => return,
                    }
                }
                r = self.udp.recv() => {
                    match r {
                        Ok((addr, packet)) => self.handle_message(addr, packet).await,
                        Err(e) => log::warn!("Error receiving incoming DHT message: {e}"),
                    }
                }
            }
        }
    }

    async fn resolve_bootstrap(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::with_capacity(self.bootstrap_nodes.len());
        let mut resolutions = stream::iter(
            self.bootstrap_nodes
                .iter()
                .map(|n| n.resolve(self.udp.using_ipv6())),
        )
        .buffer_unordered(RESOLVE_JOB_LIMIT);
        while let Some(r) = resolutions.next().await {
            addrs.extend(r);
        }
        addrs
    }

    async fn send_query(&mut self, addr: SocketAddr, query: messages::GetPeersQuery) {
        let txn = query.transaction_id.clone();
        let msg = match query.to_bencode() {
            Ok(msg) => msg,
            Err(e) => todo!(),
        };
        if let Err(e) = self.udp.send(addr, &msg).await {
            todo!(); // Include notifying the LookupSession that the sending failed
        }
        self.txn_timeouts.spawn((addr, txn), sleep(self.timeout));
    }

    #[expect(clippy::unused_async)]
    async fn handle_message(&mut self, addr: SocketAddr, msg: Bytes) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DhtHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl DhtHandle {
    pub(crate) async fn lookup_peers(&self, info_hash: InfoHash) -> FoundPeers {
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
        response_to: oneshot::Sender<FoundPeers>,
    },
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FoundPeers {
    peers: Vec<Peer>,
    closest_nodes: Vec<SocketAddr>,
}

#[derive(Debug, Error)]
pub(crate) enum CreateDhtActorError {
    #[error("failed to create UDP socket over IPv4")]
    BindIPv4(#[source] std::io::Error),
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
    my_id: NodeId,
    using_ipv6: bool,
    peers: HashSet<Peer>,
    nodes: NodeSpace,
    to_query: Vec<SocketAddr>,
    in_flight: HashSet<(SocketAddr, Bytes)>,
}

impl LookupSession {
    fn new(info_hash: InfoHash, my_id: NodeId, using_ipv6: bool) -> LookupSession {
        LookupSession {
            my_id,
            using_ipv6,
            peers: HashSet::new(),
            nodes: NodeSpace::new(info_hash),
            to_query: Vec::new(),
            in_flight: HashSet::new(),
        }
    }

    fn bootstrap(&mut self, bootstrap_addrs: Vec<SocketAddr>) {
        self.to_query.extend(bootstrap_addrs);
    }

    // TODO: The caller should weed out messages with "y" values other than "r"
    // and "e" beforehand
    fn handle_message(&mut self, sender: SocketAddr, txn: Bytes, msg: &[u8]) -> bool {
        if self.in_flight.remove(&(sender, txn)) {
            let sender = self.nodes.addr2display(sender);
            match messages::decode_response::<messages::GetPeersResponse>(msg) {
                Ok(response) => {
                    let mut nodes = Vec::with_capacity(
                        response.nodes.len().saturating_add(response.nodes6.len()),
                    );
                    nodes.extend(response.nodes.into_iter().map(NodeInfo::from));
                    nodes.extend(response.nodes6.into_iter().map(NodeInfo::from));
                    log::debug!(
                        "{sender} replied with {} peer(s) and {} node(s)",
                        response.values.len(),
                        nodes.len()
                    );
                    self.peers.extend(response.values);
                    for n in nodes {
                        self.nodes.add(n);
                    }
                }
                Err(messages::ResponseError::Rpc(e)) => {
                    log::warn!("{sender} replied with error message: {e}");
                }
                Err(e) => log::warn!("{sender} sent invalid message: {e}"),
            }
            true
        } else {
            false
        }
    }

    fn handle_timeout(&mut self, sender: SocketAddr, txn: Bytes) {
        self.in_flight.remove(&(sender, txn));
    }

    fn get_outgoing(
        &mut self,
        txn_gen: &mut TransactionGenerator,
    ) -> Vec<(SocketAddr, messages::GetPeersQuery)> {
        self.to_query
            .drain(..)
            .map(|addr| {
                let txn_id = txn_gen.generate();
                self.in_flight.insert((addr, txn_id.clone()));
                let query = messages::GetPeersQuery {
                    transaction_id: txn_id,
                    client: Some(messages::gen_client()),
                    node_id: self.my_id,
                    info_hash: self.nodes.target(),
                    read_only: Some(true),
                    want: self
                        .using_ipv6
                        .then(|| vec![messages::Want::N4, messages::Want::N6]),
                };
                (addr, query)
            })
            .collect()
    }

    fn get_result(&mut self) -> Option<FoundPeers> {
        self.in_flight.is_empty().then(|| {
            let peers = Vec::from_iter(self.peers.drain());
            let closest_nodes = self
                .nodes
                .closest_responsive(CLOSEST)
                .into_iter()
                .map(|n| n.address())
                .collect::<Vec<_>>();
            FoundPeers {
                peers,
                closest_nodes,
            }
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeSpace {
    info_hash: InfoHash,
}

impl NodeSpace {
    fn new(info_hash: InfoHash) -> NodeSpace {
        NodeSpace { info_hash }
    }

    fn add(&mut self, node: NodeInfo) {
        todo!()
    }

    fn target(&self) -> InfoHash {
        self.info_hash
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

    fn addr2display(&self, addr: SocketAddr) -> NodeDisplay {
        match self.addr2node(addr) {
            Some(n) => NodeDisplay::WithId(n),
            None => NodeDisplay::NoId(addr),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InetAddr {
    host: url::Host,
    port: u16,
}

impl InetAddr {
    #[expect(clippy::unused_async)]
    async fn resolve(&self, use_ipv6: bool) -> Option<SocketAddr> {
        todo!()
    }
}

#[derive(Debug)]
struct UdpHandle {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
}

impl UdpHandle {
    async fn new() -> Result<UdpHandle, CreateDhtActorError> {
        let ipv4 = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(CreateDhtActorError::BindIPv4)?;
        match ipv4.local_addr() {
            Ok(addr) => log::trace!(
                "DHT node using UDP port {} for IPv4 communication",
                addr.port()
            ),
            Err(e) => {
                log::warn!("Could not determine local address for DHT UDP socket on IPv4: {e}");
            }
        }
        let ipv6 = match UdpSocket::bind("[::]:0").await {
            Ok(s) => {
                match s.local_addr() {
                    Ok(addr) => log::trace!(
                        "DHT node using UDP port {} for IPv6 communication",
                        addr.port()
                    ),
                    Err(e) => {
                        log::warn!(
                            "Could not determine local address for DHT UDP socket on IPv6: {e}"
                        );
                    }
                }
                Some(s)
            }
            Err(e) => {
                log::warn!(
                    "Failed to create UDP socket over IPv6 for DHT: {e}; proceding without IPv6"
                );
                None
            }
        };
        Ok(UdpHandle { ipv4, ipv6 })
    }

    // TODO: Wrap the error in a type that also stores the address family for
    // use in the error message
    async fn recv(&self) -> std::io::Result<(SocketAddr, Bytes)> {
        if let Some(ipv6) = self.ipv6.as_ref() {
            let mut ipv4_packet = BytesMut::with_capacity(UDP_PACKET_LEN);
            let mut ipv6_packet = BytesMut::with_capacity(UDP_PACKET_LEN);
            tokio::select! {
                r = self.ipv4.recv_buf_from(&mut ipv4_packet) => {
                    match r {
                        Ok((_, addr)) => Ok((addr, ipv4_packet.freeze())),
                        Err(e) => Err(e),
                    }
                }
                r = ipv6.recv_buf_from(&mut ipv6_packet) => {
                    match r {
                        Ok((_, addr)) => Ok((addr, ipv6_packet.freeze())),
                        Err(e) => Err(e),
                    }
                }
            }
        } else {
            let mut packet = BytesMut::with_capacity(UDP_PACKET_LEN);
            match self.ipv4.recv_buf_from(&mut packet).await {
                Ok((_, addr)) => Ok((addr, packet.freeze())),
                Err(e) => Err(e),
            }
        }
    }

    // TODO: Wrap the error in a type that also stores the address family for
    // use in the error message
    #[expect(clippy::unused_async)]
    async fn send(&self, addr: SocketAddr, buf: &[u8]) -> std::io::Result<()> {
        todo!()
    }

    fn using_ipv6(&self) -> bool {
        self.ipv6.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeDisplay {
    WithId(NodeInfo),
    NoId(SocketAddr),
}

impl fmt::Display for NodeDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeDisplay::WithId(n) => write!(f, "{n}"),
            NodeDisplay::NoId(addr) => write!(f, "DHT node at {addr}"),
        }
    }
}
