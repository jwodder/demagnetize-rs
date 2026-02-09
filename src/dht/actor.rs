use super::messages;
use super::{Distance, InetAddr, Node, NodeId};
use crate::consts::UDP_PACKET_LEN;
use crate::peer::Peer;
use crate::types::InfoHash;
use crate::util::ErrorChain;
use bendy::encoding::ToBencode;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::stream::{self, StreamExt};
use rand::RngExt;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque, hash_map::Entry};
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

/// The buffer size of the channel used by the `DhtHandle` to submit
/// `ActorMessage`s to the `DhtActor`
const ACTION_CHANNEL_SIZE: usize = 64;

/// The maximum number of bootstrap nodes to resolve the addresses of at once
const RESOLVE_JOB_LIMIT: usize = 10;

/// How many closest nodes to the info hash to submit queries to, and also how
/// many closest responsive nodes to the info hash to return for use in the
/// `.torrent` file's "nodes" field
const CLOSEST: usize = 8;

/// An actor for issuing queries to the BitTorrent Mainline Distributed Hash
/// Table (DHT).
///
/// As a DHT node, the actor is focused solely on issuing queries & handling
/// replies; it ignores all incoming queries and does not bother with
/// constructing or storing any routing tables or remembering any nodes other
/// than the bootstrap nodes and whatever each currently-active lookup session
/// has encountered.
#[derive(Debug)]
pub(crate) struct DhtActor {
    /// The ID that this DHT node will declare as its own in outgoing DHT
    /// queries
    my_id: NodeId,

    /// A handle for sending & receiving UDP messages over IPv4 and possibly
    /// also IPv6
    udp: UdpHandle,

    /// The channel over which the actor receives messages from the `DhtHandle`
    action_recv: mpsc::Receiver<ActorMessage>,

    /// Generator of transaction IDs
    txn_gen: TransactionGenerator,

    /// All currently-active peer lookup sessions, keyed by session ID
    sessions: HashMap<usize, LookupSession>,

    /// The oneshot channels over which the results of each lookup session will
    /// be sent when ready, keyed by session ID
    lookup_senders: HashMap<usize, oneshot::Sender<FoundPeers>>,

    /// The session ID to use for the next lookup session to be created (after
    /// which this field is incremented)
    next_session_id: usize,

    /// If a corresponding reply is not received within this much time after
    /// sending a DHT query, the query fails due to timeout.
    timeout: Duration,

    /// The unresolved addresses of the DHT nodes that will be queried at the
    /// start of every peer lookup session
    bootstrap_nodes: Vec<InetAddr>,

    /// The implementation of the reply timeouts: a
    /// [`tokio_util::task::JoinMap`] in which the tasks simply sleep for the
    /// length of the timeout, keyed by the address of the queried node and the
    /// transaction ID of the query
    txn_timeouts: JoinMap<(SocketAddr, Bytes), ()>,
}

impl DhtActor {
    /// Create a new `DhtActor` and a [`DhtHandle`] for communicating with it.
    ///
    /// The actor must be run by calling [`DhtActor::run()`] (normally in a
    /// separate task) before the handle can be of any use.
    ///
    /// # Errors
    ///
    /// Returns an error if creating a bound IPv4 UDP socket fails
    pub(crate) async fn new<R: RngExt>(
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

    /// Run the actor, handling messages from the handle along with lookup
    /// session events.
    ///
    /// `run()` starts out by resolving the addresses of the bootstrap nodes.
    /// If no addresses can be found, it immediately shuts down.  Otherwise, it
    /// runs until a "shutdown" message is sent by calling
    /// [`DhtHandle::shutdown()`].
    pub(crate) async fn run(mut self) {
        log::info!("Starting up DHT node ...");
        let bootstrap_addrs = self.resolve_bootstrap().await;
        if bootstrap_addrs.is_empty() {
            log::error!("Failed to resolve any addresses for DHT bootstrap nodes");
            return;
        }
        log::debug!("Finished resolving DHT bootstrap node addresses");
        loop {
            tokio::select! {
                Some(msg) = self.action_recv.recv() => {
                    match msg {
                        ActorMessage::LookupPeers {info_hash, response_to} => {
                            let mut session = LookupSession::new(info_hash, self.my_id, self.udp.using_ipv6(), bootstrap_addrs.clone());
                            let outgoing = session.get_outgoing(&mut self.txn_gen);
                            let sid = self.next_session_id;
                            self.next_session_id += 1;
                            self.sessions.insert(sid, session);
                            self.lookup_senders.insert(sid, response_to);
                            for (addr, query) in outgoing {
                                self.send_query(sid, addr, query).await;
                            }
                            // Do a postprocess just in case all the sendings
                            // failed and we're done now:
                            self.postprocess_session(sid);
                        }
                        ActorMessage::Shutdown {response_to} => {
                            let _ = response_to.send(());
                            return;
                        }
                    }
                }
                r = self.udp.recv() => {
                    match r {
                        Ok((addr, packet)) => self.handle_message(addr, packet).await,
                        Err(e) => log::warn!("Error receiving incoming DHT message: {e}"),
                    }
                }
                Some(((addr, txn), _)) = self.txn_timeouts.join_next() => {
                    for (&sid, s) in &mut self.sessions {
                        if s.handle_timeout(addr, txn.clone()) {
                            self.postprocess_session(sid);
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Resolve the addresses of the bootstrap nodes and return at most one
    /// address per node
    async fn resolve_bootstrap(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::with_capacity(self.bootstrap_nodes.len());
        let mut resolutions = stream::iter(
            self.bootstrap_nodes
                .iter()
                .cloned()
                .map(|n| n.resolve(self.udp.using_ipv6())),
        )
        .buffer_unordered(RESOLVE_JOB_LIMIT);
        while let Some(r) = resolutions.next().await {
            addrs.extend(r);
        }
        addrs
    }

    /// Send the "get_peers" query `query` to `addr` for the lookup session
    /// with ID `sid`, and register a timeout for receiving a reply.
    ///
    /// If the query fails to send or cannot be Bencoded,
    /// [`LookupSession::handle_send_failure()`] is called on the associated
    /// session.
    ///
    /// Calls to this method must be followed by a call to
    /// `postprocess_session(sid)` in case a `handle_send_failure()` call
    /// removed the last in-flight transaction in a session.
    async fn send_query(&mut self, sid: usize, addr: SocketAddr, query: messages::GetPeersQuery) {
        let txn = query.transaction_id.clone();
        let msg = match query.to_bencode() {
            Ok(msg) => msg,
            Err(e) => {
                log::warn!(
                    "Failed to construct DHT \"get_peers\" query packet for {addr}: {}",
                    ErrorChain(e)
                );
                if let Some(s) = self.sessions.get_mut(&sid) {
                    s.handle_send_failure(addr, txn);
                }
                return;
            }
        };
        if let Err(e) = self.udp.send(addr, &msg).await {
            log::warn!("Failed to send DHT message to {addr}: {e}");
            if let Some(s) = self.sessions.get_mut(&sid) {
                s.handle_send_failure(addr, txn);
            }
        } else {
            self.txn_timeouts.spawn((addr, txn), sleep(self.timeout));
        }
    }

    /// Handle an incoming message `msg` received from `addr` by the UDP
    /// handle.  If the message appears to be a valid DHT response or error
    /// message, pass it to each active session's
    /// [`LookupSession::handle_message()`] method until one handles it.
    async fn handle_message(&mut self, addr: SocketAddr, msg: Bytes) {
        let (txn, msg_type) = match messages::prescan(&msg) {
            Ok(messages::Prescan {
                transaction_id,
                msg_type,
            }) => (transaction_id, msg_type),
            Err(e) => {
                log::trace!("Received invalid DHT message from {addr}: {e}; ignoring");
                return;
            }
        };
        if msg_type == messages::MessageType::Query {
            log::trace!("Received DHT query message from {addr}; ignoring");
            return;
        }
        let mut found = false;
        for (&sid, s) in &mut self.sessions {
            if s.handle_message(addr, txn.clone(), &msg) {
                for (addr, query) in s.get_outgoing(&mut self.txn_gen) {
                    self.send_query(sid, addr, query).await;
                }
                self.postprocess_session(sid);
                found = true;
                break;
            }
        }
        if !found {
            log::trace!("Received unexpected DHT message from {addr}; ignoring");
        }
    }

    /// Check whether the lookup session with the given ID has finished and
    /// produced a result.  If it has, remove it from `self.sessions` and send
    /// the result over the corresponding channel from `self.lookup_senders`.
    fn postprocess_session(&mut self, sid: usize) {
        if let Entry::Occupied(mut entry) = self.sessions.entry(sid)
            && let Some(r) = entry.get_mut().get_result()
        {
            entry.remove();
            if let Some(sender) = self.lookup_senders.remove(&sid) {
                let _ = sender.send(r);
            }
        }
    }
}

/// A cloneable handle for interacting with a [`DhtActor`]
#[derive(Clone, Debug)]
pub(crate) struct DhtHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl DhtHandle {
    /// Ask the `DhtActor` to search the DHT for peers downloading the torrent
    /// with the given info hash and then wait for & return the result.
    ///
    /// # Errors
    ///
    /// If a failure occurs communicating with the actor (because it died),
    /// [`DhtHandleError`] is returned.
    pub(crate) async fn lookup_peers(
        &self,
        info_hash: InfoHash,
    ) -> Result<FoundPeers, DhtHandleError> {
        let (sender, receiver) = oneshot::channel();
        let msg = ActorMessage::LookupPeers {
            info_hash,
            response_to: sender,
        };
        self.sender.send(msg).await.map_err(|_| DhtHandleError)?;
        receiver.await.map_err(|_| DhtHandleError)
    }

    /// Ask the `DhtActor` to shut down as soon as it receives this message.
    /// Waits for the actor to send back confirmation.
    ///
    /// If the actor is already dead or dies during handling of the message, no
    /// error is returned, as we already got what we want.
    pub(crate) async fn shutdown(&self) {
        let (sender, receiver) = oneshot::channel();
        let msg = ActorMessage::Shutdown {
            response_to: sender,
        };
        if self.sender.send(msg).await.is_ok() {
            let _ = receiver.await;
        }
    }
}

/// The various messages that can be sent from a [`DhtHandle`] to a
/// [`DhtActor`]
#[derive(Debug)]
enum ActorMessage {
    /// A request to search the DHT for peers downloading the torrent with the
    /// given info hash and send back the result on the given channel
    LookupPeers {
        info_hash: InfoHash,
        response_to: oneshot::Sender<FoundPeers>,
    },

    /// A request to shut down the actor and send back a confirmation upon
    /// receipt
    Shutdown { response_to: oneshot::Sender<()> },
}

/// Data returned from a peer lookup session
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FoundPeers {
    /// The peers found on the DHT downloading a given info hash.  May be
    /// empty.
    pub(crate) peers: Vec<Peer>,

    /// Addresses of DHT nodes with IDs close to the info hash that responded
    /// successfully to at least one query.  Used to populate the "nodes" field
    /// of the resulting `.torrent` file.
    pub(crate) closest_nodes: Vec<SocketAddr>,
}

/// Error returned by [`DhtActor::new()`] and [`UdpHandle::new()`]
#[derive(Debug, Error)]
pub(crate) enum CreateDhtActorError {
    /// Failed to bind a UDP socket to the unspecified IPv4 address
    #[error("failed to create UDP socket over IPv4")]
    BindIPv4(#[source] std::io::Error),
}

/// Error returned by [`DhtHandle::lookup_peers()`] if a failure occurs
/// communicating with the actor, indicating it's now dead.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("DHT actor is down")]
pub(crate) struct DhtHandleError;

/// A struct for generating transaction IDs for the "t" field in outgoing DHT
/// queries using an incrementing wraparound counter
#[derive(Clone, Debug, Eq, PartialEq)]
struct TransactionGenerator(u32);

impl TransactionGenerator {
    fn new() -> Self {
        Self(0)
    }

    /// Generate a byte sequence to use as the transaction ID for the next
    /// outgoing query
    fn generate(&mut self) -> Bytes {
        let t = self.0;
        self.0 = self.0.wrapping_add(1);
        let mut buf = BytesMut::with_capacity(4);
        buf.put_u32(t);
        buf.freeze()
    }
}

/// A sans IO implementation of a "peer lookup session" for searching the DHT
/// for peers downloading the torrent with a given info hash.
///
/// Lookup works by first sending "get_peers" queries to a set of bootstrap DHT
/// nodes.  Upon receiving a successful response from any queried node, the
/// known nodes with IDs closest to the info hash that have not yet been
/// queried are also sent "get_peers" queries, and processing continues.  The
/// session ends when all sent queries have either gotten replies or timed out
/// and there are no known close unqueried nodes; this normally happens when
/// all close nodes have been queried and no further transactions resolve
/// without timing out.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LookupSession {
    /// The ID of the DHT node running this session
    my_id: NodeId,

    /// Whether the DHT node is using IPv6 and thus whether both IPv4 and IPv6
    /// nodes should be requested
    using_ipv6: bool,

    /// All peers returned in responses for this session
    peers: HashSet<Peer>,

    /// A record of all nodes seen or reported as part of this session
    nodes: NodeSpace,

    /// Addresses of DHT nodes to construct queries for on the next call to
    /// [`LookupSession::get_outgoing()`]
    to_query: Vec<SocketAddr>,

    /// All "get_peers" queries in this session currently awaiting a reply,
    /// identified by the address of the queried node and the transaction ID of
    /// the query
    in_flight: HashSet<(SocketAddr, Bytes)>,
}

impl LookupSession {
    fn new(
        info_hash: InfoHash,
        my_id: NodeId,
        using_ipv6: bool,
        bootstrap_addrs: Vec<SocketAddr>,
    ) -> LookupSession {
        LookupSession {
            my_id,
            using_ipv6,
            peers: HashSet::new(),
            nodes: NodeSpace::new(info_hash),
            to_query: bootstrap_addrs,
            in_flight: HashSet::new(),
        }
    }

    /// Handle a DHT response or error message `msg` received from `sender`
    /// with transaction ID `txn`.  Returns `true` if this session was
    /// expecting a reply for the given sender & transaction, in which case (if
    /// the message is a valid response) the peers & nodes in the message are
    /// recorded, and any new nodes with IDs close to the info hash are
    /// scheduled for querying.
    fn handle_message(&mut self, sender: SocketAddr, txn: Bytes, msg: &[u8]) -> bool {
        if self.in_flight.remove(&(sender, txn)) {
            let sender = self.nodes.addr2display(sender);
            match messages::decode_response::<messages::GetPeersResponse>(msg) {
                Ok(response) => {
                    let mut nodes = Vec::with_capacity(
                        response.nodes.len().saturating_add(response.nodes6.len()),
                    );
                    nodes.extend(response.nodes.into_iter().map(Node::from));
                    nodes.extend(response.nodes6.into_iter().map(Node::from));
                    log::debug!(
                        "{sender} replied with {} peer(s) and {} node(s) for info hash {}",
                        response.values.len(),
                        nodes.len(),
                        self.info_hash(),
                    );
                    self.peers.extend(response.values);
                    for n in nodes {
                        self.nodes.add(n);
                    }
                    if let NodeDisplay::WithId(n) = sender {
                        self.nodes.mark_responsive(n.id);
                    }
                    self.to_query.extend(
                        self.nodes
                            .closest_unqueried(CLOSEST)
                            .into_iter()
                            .map(|n| n.address()),
                    );
                }
                Err(messages::ResponseError::Rpc(e)) => {
                    log::warn!("{sender} replied with error message: {e}");
                }
                Err(e) => log::warn!("{sender} sent invalid reply message: {}", ErrorChain(e)),
            }
            true
        } else {
            false
        }
    }

    /// Inform the session that the wait for a reply from `addr` for the query
    /// with transaction ID `txn` has timed out.  Returns `true` if this
    /// session was awaiting such a reply, in which case it will no longer be
    /// doing so.
    fn handle_timeout(&mut self, addr: SocketAddr, txn: Bytes) -> bool {
        if self.in_flight.remove(&(addr, txn)) {
            let remote = self.nodes.addr2display(addr);
            log::debug!("Query to {remote} timed out");
            true
        } else {
            false
        }
    }

    /// Inform the session that the query previously returned by
    /// `get_outgoing()` for sending to `addr` and having transaction ID `txn`
    /// failed to send and thus no reply should be awaited.
    fn handle_send_failure(&mut self, addr: SocketAddr, txn: Bytes) {
        self.in_flight.remove(&(addr, txn));
    }

    /// Returns a collection of `(addr, query)` pairs each containing a
    /// "get_peers" query `query` to send to `addr`.  The session will await
    /// a reply to each returned query.
    fn get_outgoing(
        &mut self,
        txn_gen: &mut TransactionGenerator,
    ) -> Vec<(SocketAddr, messages::GetPeersQuery)> {
        let info_hash = self.info_hash();
        let client = Some(messages::gen_client());
        self.to_query
            .drain(..)
            .map(|addr| {
                log::debug!(
                    "Sending \"get_peers\" query to {} for info hash {info_hash}",
                    self.nodes.addr2display(addr)
                );
                let txn_id = txn_gen.generate();
                self.in_flight.insert((addr, txn_id.clone()));
                let query = messages::GetPeersQuery {
                    transaction_id: txn_id,
                    client: client.clone(),
                    node_id: self.my_id,
                    info_hash,
                    read_only: Some(true),
                    want: self
                        .using_ipv6
                        .then(|| vec![messages::Want::N4, messages::Want::N6]),
                };
                (addr, query)
            })
            .collect()
    }

    /// If the lookup session has finished, returns all peers found during the
    /// session and a collection of responsive nodes with IDs close to the info
    /// hash.
    fn get_result(&mut self) -> Option<FoundPeers> {
        self.in_flight.is_empty().then(|| {
            let peers = Vec::from_iter(self.peers.drain());
            let closest_nodes = self
                .nodes
                .closest_responsive(CLOSEST)
                .into_iter()
                .map(|n| n.address())
                .collect::<Vec<_>>();
            log::info!(
                "Found {} peers for {} on the DHT",
                peers.len(),
                self.info_hash(),
            );
            FoundPeers {
                peers,
                closest_nodes,
            }
        })
    }

    /// Returns the info hash that the session is searching for peers for
    fn info_hash(&self) -> InfoHash {
        self.nodes.target()
    }
}

/// A struct for recording & querying nodes seen during a peer lookup session
#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeSpace {
    /// The info hash that the associated lookup session is searching for
    info_hash: InfoHash,

    /// All nodes (except limited to one per socket address) returned in
    /// "nodes" and/or "nodes6" fields of responses received by the lookup
    /// session.  The nodes are grouped into queues keyed by the XOR distance
    /// between their ID and the target info hash, and the nodes in each queue
    /// are ordered with the most recently-added nodes at the front.
    nodes: BTreeMap<Distance, VecDeque<NodeInfo>>,

    /// A mapping from socket addresses to associated DHT nodes
    addr2node: HashMap<SocketAddr, Node>,
}

impl NodeSpace {
    fn new(info_hash: InfoHash) -> NodeSpace {
        NodeSpace {
            info_hash,
            nodes: BTreeMap::new(),
            addr2node: HashMap::new(),
        }
    }

    /// Add a node to the node space.  If the node's address already belongs to
    /// another node in the node space, the new node is discarded.
    ///
    /// As the node IDs of bootstrap nodes are not known, they cannot be added
    /// to a node space, but they also shouldn't need to be.
    fn add(&mut self, node: Node) {
        // TODO once `IpAddr.is_global()` is stabilized: Don't save nodes with
        // non-global IP addresses
        if let Entry::Vacant(entry) = self.addr2node.entry(node.address()) {
            entry.insert(node);
            let dist = node.id ^ self.info_hash;
            self.nodes.entry(dist).or_default().push_front(NodeInfo {
                node,
                queried: false,
                responsive: false,
            });
        }
    }

    /// Returns the info hash that the associated peer lookup session is
    /// looking up peers for and which the node space thus needs to know the
    /// closest nodes to
    fn target(&self) -> InfoHash {
        self.info_hash
    }

    /// Of the `k` known nodes closest to the info hash, any that have not yet
    /// been queried are returned and marked for future calls as having been
    /// queried.
    fn closest_unqueried(&mut self, k: usize) -> Vec<Node> {
        self.nodes
            .values_mut()
            .flatten()
            .take(k)
            .filter(|info| !info.queried)
            .map(|info| {
                info.queried = true;
                info.node
            })
            .collect()
    }

    /// Returns the `k` known nodes closest to the info hash that are marked
    /// responsive
    fn closest_responsive(&self, k: usize) -> Vec<Node> {
        self.nodes
            .values()
            .flatten()
            .filter(|info| info.responsive)
            .take(k)
            .map(|info| info.node)
            .collect()
    }

    /// Mark the node with the given ID as responsive, meaning that it returned
    /// a successful response to a query
    fn mark_responsive(&mut self, id: NodeId) {
        if let Some(bucket) = self.nodes.get_mut(&(id ^ self.info_hash)) {
            for info in bucket {
                if info.node.id == id {
                    info.responsive = true;
                    break;
                }
            }
        }
    }

    /// Return a struct for `Display`-ing the ID & address of the node with the
    /// given address.  If the node is not in the node space (presumably
    /// because it's a bootstrap node), the returned struct will just display
    /// the address.
    fn addr2display(&self, addr: SocketAddr) -> NodeDisplay {
        match self.addr2node.get(&addr) {
            Some(&n) => NodeDisplay::WithId(n),
            None => NodeDisplay::NoId(addr),
        }
    }
}

/// Information about a DHT node stored in a [`NodeSpace`]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeInfo {
    /// The node itself (specifically, its ID and address)
    node: Node,

    /// Whether the node has been queried
    queried: bool,

    /// Whether the node is responsive (i.e., whether it returned a successful
    /// response to a query)
    responsive: bool,
}

/// A struct for sending & receiving UDP packets over IPv4 and possibly also
/// IPv6
#[derive(Debug)]
struct UdpHandle {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
}

impl UdpHandle {
    /// Create a new `UdpHandle`.  A new UDP socket is bound on IPv4, and an
    /// attempt is made to also bind another UDP socket on IPv6; if the latter
    /// fails, the resulting handle will not support IPv6.
    ///
    /// # Errors
    ///
    /// Returns an error if creating a bound IPv4 UDP socket fails
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

    /// Receive an incoming UDP packet and return it along with the remote
    /// sending address
    ///
    /// # Errors
    ///
    /// Has the same error conditions as
    /// [`tokio::net::UdpSocket::recv_buf_from()`].
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

    /// Send the packet `buf` to `addr` over UDP
    ///
    /// # Errors
    ///
    /// Returns an error if `addr` is an IPv6 address and IPv6 is disabled.
    /// Otherwise, has the same error conditions as
    /// [`tokio::net::UdpSocket::send_to()`].
    async fn send(&self, addr: SocketAddr, buf: &[u8]) -> Result<(), UdpSendError> {
        if addr.is_ipv4() {
            self.ipv4.send_to(buf, addr).await?;
        } else if let Some(ipv6) = self.ipv6.as_ref() {
            ipv6.send_to(buf, addr).await?;
        } else {
            return Err(UdpSendError::IPv6Disabled);
        }
        Ok(())
    }

    /// Returns true if this handle can send & receive packets over IPv6
    fn using_ipv6(&self) -> bool {
        self.ipv6.is_some()
    }
}

/// Error returned by [`UdpHandle::send()`]
#[derive(Debug, Error)]
enum UdpSendError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Attempted to send to an IPv6 address while IPv6 was disabled
    #[error("INTERNAL ERROR: attempted to send DHT message over IPv6 while IPv6 was disabled")]
    IPv6Disabled,
}

/// A struct for displaying the address and, if known, ID of a DHT node
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeDisplay {
    WithId(Node),
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
