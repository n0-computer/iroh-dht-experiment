use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    num::NonZeroU64,
    time::UNIX_EPOCH,
};

use futures_buffered::FuturesUnordered;
use indexmap::IndexSet;
use iroh::Endpoint;
use iroh_base::SignatureError;
use irpc::{
    channel::{mpsc, none::NoSender},
    rpc_requests,
};
use n0_future::{BufferedStreamExt, StreamExt, stream};
use rand::{SeedableRng, seq::index::sample};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

/// A DHT is two things:
///
/// # Data storage
///
/// A multimap of keys to values, where values are self contained pieces of data
/// that have some way to be verified and have some relationship to the key.
///
/// Values should have some kind of expiry mechanism, but they don't need
/// provenance since they are self-contained.
///
/// The storage part of the DHT is basically a standalone tracker, except for
/// the fact that it will reject set requests that are obviously far away
/// from the node id in terms of the DHT metric.
///
/// Disabling the latter mechanism would allow a single DHT node to act as a
/// tracker.
///
/// Examples of values:
///
/// - Provider node ids for a key, where the key is interpreted as a BLAKE3 hash
/// of some data. Expiry is a timestamp, validation is checking that the node
/// has the data by means of a BLAKE3 probe.
///
/// - A signed message, e.g. a pkarr record, where the key is interpreted as
/// the public key of the signer. Expiry is a timestamp, validation is
/// checking the signature against the public key.
///
/// - Self-contained immutable data, where the key is interpreted as a BLAKE3
/// hash of the data. Expiry is a timestamp, validation is checking that the
/// data matches the hash.
///
/// Data storage will use postcard on the wire and most likely also on disk.
///
/// # Routing
///
/// A way to find the n most natural locations for a given key. Routing is only
/// concerned with the key, not the value.
mod proto {
    use std::{fmt, num::NonZeroU64, ops::Deref};

    use irpc::{
        channel::{mpsc, oneshot},
        rpc_requests,
    };
    use serde::{Deserialize, Serialize};
    use serde_big_array::BigArray;

    pub const ALPN: &[u8] = b"iroh/dht/0";

    /// Entry type for BLAKE3 content discovery.
    ///
    /// Provides a similar functionality to BEP-5 in mainline, but for BLAKE3
    /// hashes instead of SHA-1 hashes.
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Blake3Provider {
        timestamp: u64, // Unix timestamp for expiry
        node_id: [u8; 32],
    }

    /// Entry type for BLAKE3 content discovery.
    ///
    /// Provides a similar functionality to BEP-5 in mainline, but for BLAKE3
    /// hashes instead of SHA-1 hashes.
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Blake3Immutable {
        pub timestamp: u64, // Unix timestamp for expiry
        pub data: Vec<u8>,
    }

    /// Entry type for signed messages, e.g. pkarr records, for node discovery.
    ///
    /// Provides a similar functionality BEP-44 in mainline.
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ED25519SignedMessage {
        /// Unix timestamp for expiry
        pub timestamp: u64,
        /// A 64-byte signature using Ed25519
        #[serde(with = "BigArray")]
        pub signature: [u8; 64],
        /// The signed message data. This must be <= 1024 bytes so an entire
        /// set request fits a single non-fragmented UDP packet even with QUIC
        /// overhead.
        pub data: Vec<u8>,
    }

    /// The order of the enum is important for serialization/deserialization
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Value {
        Blake3Provider(Blake3Provider),
        ED25519SignedMessage(ED25519SignedMessage),
        Blake3Immutable(Blake3Immutable),
    }

    impl Value {
        /// Returns the kind of this value.
        pub fn kind(&self) -> Kind {
            match self {
                Value::Blake3Provider(_) => Kind::Blake3Provider,
                Value::ED25519SignedMessage(_) => Kind::ED25519SignedMessage,
                Value::Blake3Immutable(_) => Kind::Blake3Immutable,
            }
        }
    }

    /// Must have the same order as `Value` for serialization/deserialization
    #[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Kind {
        Blake3Provider,
        ED25519SignedMessage,
        Blake3Immutable,
    }

    /// We use a 32 byte keyspace so we can represent things like modern hashes
    /// and public keys without having to map them to a smaller keyspace.
    #[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Id([u8; 32]); // 256-bit identifier

    impl From<[u8; 32]> for Id {
        fn from(bytes: [u8; 32]) -> Self {
            Id(bytes)
        }
    }

    impl Deref for Id {
        type Target = [u8; 32];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl fmt::Debug for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Id({})", hex::encode(self.0))
        }
    }

    impl fmt::Display for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", hex::encode(self.0))
        }
    }

    impl Id {
        fn blake3_hash(data: &[u8]) -> Self {
            let hash = blake3::hash(data);
            Id(hash.into())
        }

        fn node_id(id: iroh::NodeId) -> Self {
            Id::from(*id.as_bytes())
        }
    }

    /// Set a key to a value.
    ///
    /// The storage is allowed to reject set requests if the key is far away from
    /// the node id in terms of the DHT metric, or if the value is invalid.
    ///
    /// The storage is also allowed to drop values at any time. This is not a
    /// command but more a request to store the value.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Set {
        /// The key to set the value for.
        pub key: Id,
        /// The value being set.
        pub value: Value,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum SetResponse {
        /// The set request was successful.
        Ok,
        /// The key was too far away from the node id in terms of the DHT metric.
        ErrDistance,
        /// The value is too old.
        ErrExpired,
        /// The node does not have capacity to store the value.
        ErrFull,
        /// The value is invalid, e.g. the signature does not match the public key.
        ErrInvalid,
    }

    /// Get all values of a certain kind for a key, as a stream.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetAll {
        /// The key to get the values for.
        pub key: Id,
        /// The kind of value to get.
        pub kind: Kind,
        /// Optional seed for randomization of the returned stream of values.
        /// If this is not provided, items will be returned in an unspecified order.
        pub seed: Option<NonZeroU64>,
        /// Number of values to return, if specified. If not specified, all values
        /// of the specified kind for the key will be returned until the receiver
        /// stops or the stream ends.
        pub n: Option<NonZeroU64>,
    }

    /// A ping request to check if the node is alive and reachable.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Ping;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Pong;

    /// A request to query the routing table for the most natural locations
    #[derive(Debug, Serialize, Deserialize)]
    pub struct FindNode {
        /// The key to find the most natural locations (nodes) for.
        pub id: Id,
    }

    #[rpc_requests(message = RpcMessage)]
    #[derive(Debug, Serialize, Deserialize)]
    pub enum RpcRequests {
        /// Set a key to a value.
        #[rpc(tx = oneshot::Sender<SetResponse>)]
        Set(Set),
        /// Get all values of a certain kind for a key, as a stream of values.
        #[rpc(tx = mpsc::Sender<Value>)]
        GetAll(GetAll),
        /// A ping request to check if the node is alive and reachable.    
        #[rpc(tx = oneshot::Sender<Pong>)]
        Ping(Ping),
        /// A request to query the routing table for the most natural locations
        #[rpc(tx = mpsc::Sender<Id>)]
        FindNode(FindNode),
    }
}

mod routing {
    use std::{ffi::os_str::Display, fmt};

    use arrayvec::ArrayVec;
    use serde::{Deserialize, Serialize};

    use super::proto::Id;

    pub const K: usize = 20; // Bucket size
    pub const ALPHA: usize = 3; // Concurrency parameter
    pub const BUCKET_COUNT: usize = 256; // For 256-bit keys

    /// Calculate XOR distance between two 32-byte values
    fn xor(a: &Id, b: &Id) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = a[i] ^ b[i];
        }
        result
    }

    /// Count leading zero bits in a 32-byte array
    fn leading_zeros(data: &[u8; 32]) -> usize {
        for (byte_idx, &byte) in data.iter().enumerate() {
            if byte != 0 {
                return byte_idx * 8 + byte.leading_zeros() as usize;
            }
        }
        256 // All zeros
    }

    /// Distance in Kademlia is the number of leading zero bits in XOR
    /// Lower values = closer distance (higher leading zeros)
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Distance(u16);

    impl Distance {
        pub fn between(a: &Id, b: &Id) -> Self {
            let xor = xor(a, b);
            let n = BUCKET_COUNT - leading_zeros(&xor);
            Self(n as u16)
        }

        pub const MAX: Self = Self(u16::MAX);
    }

    impl fmt::Display for Distance {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    pub struct NodeInfo {
        pub id: Id,
        pub last_seen: u64,
    }

    impl NodeInfo {
        pub fn new(id: Id, last_seen: u64) -> Self {
            Self { id, last_seen }
        }
    }

    #[derive(Debug, Clone)]
    struct KBucket {
        nodes: ArrayVec<NodeInfo, K>,
    }

    impl KBucket {
        fn new() -> Self {
            Self {
                nodes: ArrayVec::new(),
            }
        }

        fn add_node(&mut self, node: NodeInfo) -> bool {
            // Check if node already exists and update it
            for existing in &mut self.nodes {
                if existing.id == node.id {
                    existing.last_seen = node.last_seen;
                    return true; // Updated existing node
                }
            }

            // Add new node if space available
            if self.nodes.len() < K {
                self.nodes.push(node);
                return true;
            }

            false // Bucket full
        }

        fn remove_node(&mut self, id: &Id) {
            self.nodes.retain(|n| n.id != *id);
        }

        fn get_nodes(&self) -> &[NodeInfo] {
            &self.nodes
        }
    }

    pub(crate) struct RoutingTable {
        buckets: [Box<KBucket>; BUCKET_COUNT],
        local_id: Id,
    }

    impl RoutingTable {
        pub fn new(local_id: Id) -> Self {
            let buckets = std::array::from_fn(|_| Box::new(KBucket::new()));
            Self { buckets, local_id }
        }

        fn bucket_index(&self, target: &Id) -> usize {
            let distance = xor(&self.local_id, target);
            let zeros = leading_zeros(&distance);
            std::cmp::min(zeros, BUCKET_COUNT - 1)
        }

        pub(crate) fn add_node(&mut self, node: NodeInfo) -> bool {
            if node.id == self.local_id {
                return false;
            }

            let bucket_idx = self.bucket_index(&node.id);
            self.buckets[bucket_idx].add_node(node)
        }

        fn remove_node(&mut self, id: &Id) {
            let bucket_idx = self.bucket_index(id);
            self.buckets[bucket_idx].remove_node(id);
        }

        pub(crate) fn nodes(&self) -> impl Iterator<Item = &NodeInfo> {
            self.buckets.iter().flat_map(|bucket| bucket.get_nodes())
        }

        pub(crate) fn find_closest_nodes(&self, target: &Id, k: usize) -> Vec<NodeInfo> {
            let mut candidates: Vec<(NodeInfo, Distance)> = Vec::new();

            for bucket in &self.buckets {
                for node in bucket.get_nodes() {
                    let distance = Distance::between(target, &node.id);
                    candidates.push((node.clone(), distance));
                }
            }

            candidates.sort_by(|a, b| b.1.cmp(&a.1));

            candidates
                .into_iter()
                .take(k)
                .map(|(node, _)| node)
                .collect()
        }
    }
}

use crate::{
    proto::{
        Blake3Immutable, FindNode, GetAll, Id, Kind, Ping, Pong, RpcMessage, RpcRequests, Set,
        SetResponse, Value,
    },
    routing::{ALPHA, Distance, K, NodeInfo, RoutingTable},
};

struct Node {
    id: Id,
    routing_table: RoutingTable,
    storage: MemStorage,
}

struct MemStorage {
    /// The DHT data storage, mapping keys to values.
    /// Separated by kind to allow for efficient retrieval.
    data: BTreeMap<Id, BTreeMap<Kind, IndexSet<Value>>>,
}

impl MemStorage {
    fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    /// Set a value for a key.
    fn set(&mut self, key: Id, value: Value) {
        let kind = value.kind();
        self.data
            .entry(key)
            .or_default()
            .entry(kind)
            .or_default()
            .insert(value);
    }

    /// Get all values of a certain kind for a key.
    fn get_all(&self, key: &Id, kind: &Kind) -> Option<&IndexSet<Value>> {
        self.data.get(key).and_then(|kinds| kinds.get(kind))
    }
}

#[derive(Debug, Clone)]
pub struct ApiClient(irpc::Client<ApiProto>);

impl ApiClient {
    async fn get_immutable(&self, hash: blake3::Hash) -> irpc::Result<Option<Vec<u8>>> {
        let id = Id::from(*hash.as_bytes());
        let mut rx = self
            .0
            .server_streaming(
                NetworkGet {
                    id,
                    kind: Kind::Blake3Immutable,
                    seed: None,
                    n: Some(NonZeroU64::new(1).unwrap()),
                },
                32,
            )
            .await?;
        loop {
            match rx.recv().await {
                Ok(Some((id, value))) => {
                    let Value::Blake3Immutable(Blake3Immutable { data, .. }) = value else {
                        continue; // Skip non-Blake3Immutable values
                    };
                    if blake3::hash(&data) == hash {
                        return Ok(Some(data));
                    } else {
                        continue; // Hash mismatch, skip this value
                    }
                }
                Ok(None) => {
                    break Ok(None);
                }
                Err(e) => {
                    break Err(e.into());
                }
            }
        }
    }

    async fn put_immutable(&self, value: &[u8]) -> irpc::Result<(blake3::Hash, Vec<Id>)> {
        let hash = blake3::hash(value);
        let id = Id::from(*hash.as_bytes());
        let mut rx = self
            .0
            .server_streaming(
                NetworkPut {
                    id,
                    value: Value::Blake3Immutable(Blake3Immutable {
                        timestamp: now(),
                        data: value.to_vec(),
                    }),
                },
                32,
            )
            .await?;
        let mut res = Vec::new();
        loop {
            match rx.recv().await {
                Ok(Some(id)) => res.push(id),
                Ok(None) => break,
                Err(_) => {}
            }
        }
        Ok((hash, res))
    }
}

#[derive(Debug, Clone)]
pub struct RpcClient(irpc::Client<RpcRequests>);

impl RpcClient {
    pub fn remote(endpoint: Endpoint, id: Id) -> std::result::Result<Self, SignatureError> {
        let id = iroh::NodeId::from_bytes(&id)?;
        let client = irpc_iroh::client(endpoint, id, proto::ALPN);
        Ok(Self(client))
    }

    pub fn new(client: irpc::Client<RpcRequests>) -> Self {
        Self(client)
    }

    pub async fn ping(&self) -> irpc::Result<Pong> {
        self.0.rpc(Ping).await
    }

    pub async fn set(&self, key: Id, value: Value) -> irpc::Result<SetResponse> {
        self.0.rpc(Set { key, value }).await
    }

    pub async fn get_all(
        &self,
        key: Id,
        kind: Kind,
        seed: Option<NonZeroU64>,
        n: Option<NonZeroU64>,
    ) -> irpc::Result<irpc::channel::mpsc::Receiver<Value>> {
        self.0
            .server_streaming(GetAll { key, kind, seed, n }, 32)
            .await
    }

    pub fn find_node(&self, id: Id) -> FindNodeProgress {
        FindNodeProgress(Box::pin(self.0.server_streaming(FindNode { id }, 32)))
    }
}

struct FindNodeProgress(n0_future::future::Boxed<irpc::Result<irpc::channel::mpsc::Receiver<Id>>>);

impl FindNodeProgress {
    /// Collects up to `n` node ids from the find_node stream.
    pub async fn collect(self, n: usize) -> irpc::Result<Vec<Id>> {
        let mut stream = self.0.await?;
        let mut ids = Vec::new();
        for _ in 0..n {
            if let Ok(Some(id)) = stream.recv().await {
                ids.push(id);
            } else {
                break;
            }
        }
        Ok(ids)
    }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub struct DistanceAndId {
    pub distance: Distance,
    pub id: Id,
}

pub trait OnNodeSeen: Send {
    fn seen(&self, id: Id) -> impl Future<Output = ()> + Send;
}

/// A pool that can efficiently provide clients given a node id, and knows its
/// own identity.
///
/// For tests, this is just a map from id to client. For production, this will
/// wrap an iroh Endpoint and have some sort of connection cache.
pub trait ClientPool: Send + Sync + Clone + Sized + 'static {
    /// Our own node id
    fn id(&self) -> Id;

    /// Hook to get or create a client for a remote Id. Use your pool/0-RTT here.
    fn client(&self, id: Id) -> impl Future<Output = Result<RpcClient, &'static str>> + Send;
}

#[derive(Debug, Serialize, Deserialize)]
struct PutProgressItem {
    id: Id,
}

#[rpc_requests(message = ApiMessage)]
#[derive(Debug, Serialize, Deserialize)]
enum ApiProto {
    #[rpc(wrap, tx = NoSender)]
    NodeSeen { info: NodeInfo },
    #[rpc(wrap, tx = mpsc::Sender<Id>)]
    NetworkPut { id: Id, value: Value },
    #[rpc(wrap, tx = mpsc::Sender<(Id, Value)>)]
    NetworkGet {
        id: Id,
        kind: Kind,
        seed: Option<NonZeroU64>,
        n: Option<NonZeroU64>,
    },
}

/// State of the actor that is required in the async handlers
#[derive(Debug, Clone)]
struct State<P> {
    /// ability to send messages to ourselves, e.g. to update the routing table
    api: irpc::Client<ApiProto>,
    /// client pool
    pool: P,
    /// configuration
    config: Config,
}

struct Actor<P> {
    node: Node,
    /// receiver for rpc messages from the network
    rpc_rx: tokio::sync::mpsc::Receiver<RpcMessage>,
    /// receiver for api messages from in process or local network
    api_rx: tokio::sync::mpsc::Receiver<ApiMessage>,
    /// ongoing tasks
    tasks: JoinSet<()>,
    /// state
    state: State<P>,
}

impl OnNodeSeen for irpc::Client<ApiProto> {
    async fn seen(&self, id: Id) {
        let msg = NodeSeen {
            info: NodeInfo {
                id,
                last_seen: now(),
            },
        };
        self.notify(msg).await.ok();
    }
}

/// Dht lookup config
#[derive(Debug, Clone, Copy)]
struct Config {
    /// DHT parameter K
    k: usize,
    /// DHT parameter ALPHA
    alpha: usize,
    /// Parallelism for the set or getall requests once we have found the k
    /// closest nodes.
    parallelism: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            k: K,
            alpha: ALPHA,
            parallelism: 4,
        }
    }
}

impl<E> Actor<E>
where
    E: ClientPool,
{
    fn new(
        node: Node,
        rx: tokio::sync::mpsc::Receiver<RpcMessage>,
        endpoint: E,
    ) -> (Self, irpc::Client<ApiProto>) {
        let (api_tx, internal_rx) = tokio::sync::mpsc::channel(32);
        let api: irpc::Client<ApiProto> = api_tx.into();
        (
            Self {
                node,
                rpc_rx: rx,
                api_rx: internal_rx,
                tasks: JoinSet::new(),
                state: State {
                    api: api.clone(),
                    pool: endpoint,
                    config: Config::default(),
                },
            },
            api,
        )
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                msg = self.rpc_rx.recv() => {
                    if let Some(msg) = msg {
                        self.handle_rpc(msg).await;
                    } else {
                        break;
                    }
                }
                msg = self.api_rx.recv() => {
                    if let Some(msg) = msg {
                        self.handle_api(msg).await;
                    } else {
                        break;
                    }
                }
                Some(res) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    if let Err(e) = res {
                        tracing::error!("Task failed: {:?}", e);
                    }
                }
            }
        }
    }

    /// Handle a single API message
    async fn handle_api(&mut self, message: ApiMessage) {
        match message {
            ApiMessage::NodeSeen(msg) => {
                // Update our routing table
                self.node.routing_table.add_node(msg.info);
            }
            ApiMessage::NetworkGet(msg) => {
                // perform a network get by calling the iterative search using the closest
                // nodes from the local routing table, then performing individual requests
                // for the resulting k closest live nodes.
                let initial = self.node.routing_table.find_closest_nodes(&msg.id, K);
                self.tasks.spawn(self.state.clone().handle_network_get(
                    initial.into_iter().map(|node| node.id).collect(),
                    msg.inner,
                    msg.tx,
                ));
            }
            ApiMessage::NetworkPut(msg) => {
                // perform a network put by calling the iterative search using the closest
                // nodes from the local routing table, then performing individual requests
                // for the resulting k closest live nodes.
                let initial = self.node.routing_table.find_closest_nodes(&msg.id, K);
                self.tasks.spawn(self.state.clone().handle_network_put(
                    initial.into_iter().map(|node| node.id).collect(),
                    msg.inner,
                    msg.tx,
                ));
            }
        }
    }

    async fn handle_rpc(&mut self, message: RpcMessage) {
        match message {
            RpcMessage::Set(msg) => {
                // just set the value in the local storage
                //
                // TODO: sanity check that this node is a good node to store
                // the data at, using the local routing table, and if not return
                // a SetResponse::ErrDistance.
                //
                // TODO: check if the data is expired or invalid and return the
                // appropriate error response.
                self.node.storage.set(msg.key, msg.value.clone());
                msg.tx.send(SetResponse::Ok).await.ok();
            }
            RpcMessage::GetAll(msg) => {
                // Get all values, applying the provided filters and limits.
                let Some(values) = self.node.storage.get_all(&msg.key, &msg.kind) else {
                    return;
                };
                // Randomize the order of the results given the provided seed
                if let Some(seed) = msg.seed {
                    let mut rng = rand::rngs::StdRng::seed_from_u64(seed.get());
                    let n = msg.n.map(|x| x.get()).unwrap_or(values.len() as u64) as usize;
                    let indices = sample(&mut rng, values.len(), n);
                    for i in indices {
                        if let Some(value) = values.get_index(i) {
                            if msg.tx.send(value.clone()).await.is_err() {
                                break;
                            }
                        }
                    }
                } else {
                    // just send them in whatever order they return from the store.
                    for value in values {
                        if msg.tx.send(value.clone()).await.is_err() {
                            break;
                        }
                    }
                }
            }
            RpcMessage::Ping(msg) => {
                // just respond with pong.
                msg.tx.send(Pong).await.ok();
            }
            RpcMessage::FindNode(msg) => {
                // call local find_node and just return the results
                let nodes = self
                    .node
                    .routing_table
                    .find_closest_nodes(&msg.id, self.state.config.k);
                for node in nodes {
                    if msg.tx.send(node.id).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

impl<P: ClientPool> State<P> {
    async fn handle_network_put(self, initial: Vec<Id>, msg: NetworkPut, tx: mpsc::Sender<Id>) {
        let ids = self.clone().iterative_find_node(msg.id, initial).await;
        stream::iter(ids)
            .for_each_concurrent(self.config.parallelism, |id| {
                let pool = self.pool.clone();
                let value = msg.value.clone();
                let tx = tx.clone();
                async move {
                    if let Ok(client) = pool.client(id).await {
                        if client.set(msg.id, value).await.is_ok() {
                            tx.send(id).await.ok();
                        }
                    }
                }
            })
            .await;
    }

    async fn handle_network_get(
        self,
        initial: Vec<Id>,
        msg: NetworkGet,
        tx: mpsc::Sender<(Id, Value)>,
    ) {
        let ids = self.clone().iterative_find_node(msg.id, initial).await;
        stream::iter(ids)
            .for_each_concurrent(self.config.parallelism, |id| {
                let pool = self.pool.clone();
                let tx = tx.clone();
                async move {
                    let Ok(client) = pool.client(id).await else {
                        return;
                    };
                    let Ok(mut rx) = client.get_all(msg.id, msg.kind, msg.seed, msg.n).await else {
                        return;
                    };
                    loop {
                        match rx.recv().await {
                            Ok(Some(value)) => {
                                tx.send((id, value)).await.ok();
                            }
                            Ok(None) => {
                                break;
                            }
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                }
            })
            .await;
    }

    fn query_one(
        &self,
        id: Id,
        target: Id,
        k: usize,
    ) -> impl Future<Output = Result<Vec<Id>, &'static str>> + Send {
        async move {
            let client = self.pool.client(id).await?;
            let result = client
                .find_node(target)
                .collect(k / 2)
                .await
                .map_err(|_| "Failed to call find_node")?;
            Ok(result)
        }
    }

    fn iterative_find_node(
        self,
        target: Id,
        initial: Vec<Id>,
    ) -> impl Future<Output = Vec<Id>> + Send {
        async move {
            let mut candidates = initial
                .into_iter()
                .filter(|id| *id != self.pool.id())
                .map(|id| (Distance::between(&target, &id), id))
                .collect::<BTreeSet<_>>();
            let mut queried = HashSet::new();
            queried.insert(self.pool.id());
            let mut closest_distance = Distance::MAX;
            let mut tasks = FuturesUnordered::new();
            let mut result = BTreeSet::new();
            let mut i = 0;
            let mut updated = true;

            loop {
                i += 1;
                if candidates.is_empty() {
                    break;
                }

                let n = if updated {
                    println!("Round {i}, distance {closest_distance:?}, using alpha: {}", self.config.alpha);
                    self.config.alpha
                } else {
                    let n = self.config.k.saturating_sub(result.len());
                    println!("Round {i}, distance {closest_distance:?}, getting {n} more results");
                    n
                };

                for _ in 0..n {
                    let Some(pair @ (_, id)) = candidates.pop_first() else {
                        break;
                    };
                    queried.insert(id);
                    let fut = self.query_one(id, target, self.config.k);
                    tasks.push(async move { (pair, fut.await) });
                }

                updated = false;
                while let Some((pair @ (dist, id), cands)) = tasks.next().await {
                    let Ok(cands) = cands else {
                        // we must set updated to true so we don't exit early if there are failures in the first ALPHA candidates
                        updated = true;
                        continue;
                    };
                    for cand in cands {
                        let dist = Distance::between(&target, &cand);
                        let pair = (dist, cand);
                        if !queried.contains(&cand) {
                            candidates.insert(pair);
                        }
                    }
                    self.api
                        .notify(NodeSeen {
                            info: NodeInfo {
                                id,
                                last_seen: now(),
                            },
                        })
                        .await
                        .ok();
                    result.insert(pair);
                    if dist < closest_distance {
                        closest_distance = dist;
                        updated = true;
                    }
                }

                // we want to continue even if we didn't find a better candidate
                // if we have less than K nodes.
                if result.len() >= self.config.k && !updated {
                    break;
                }

                // truncate the result to k.
                while result.len() > self.config.k {
                    result.pop_last();
                }
            }

            // result already has size <= k
            result.into_iter().map(|(_, id)| id).collect()
        }
    }
}

fn now() -> u64 {
    UNIX_EPOCH.elapsed().unwrap().as_secs()
}

fn create_node<E: ClientPool>(id: Id, bootstrap: Vec<Id>, endpoint: E) -> (RpcClient, ApiClient) {
    let mut node = Node {
        id,
        routing_table: RoutingTable::new(id),
        storage: MemStorage::new(),
    };
    for bootstrap_id in bootstrap {
        if bootstrap_id != id {
            node.routing_table.add_node(NodeInfo {
                id: bootstrap_id,
                last_seen: now(),
            });
        }
    }
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let (actor, client) = Actor::<E>::new(node, rx, endpoint);
    tokio::spawn(actor.run());
    (RpcClient(irpc::Client::local(tx)), ApiClient(client))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use rand::Rng;

    use super::*;

    #[derive(Debug, Clone)]
    struct TestEndpoint {
        state: Arc<Mutex<BTreeMap<Id, RpcClient>>>,
        id: Id,
    }

    impl ClientPool for TestEndpoint {
        async fn client(&self, id: Id) -> Result<RpcClient, &'static str> {
            let state = self.state.lock().unwrap();
            state.get(&id).cloned().ok_or("Client not found")
        }

        fn id(&self) -> Id {
            self.id
        }
    }

    fn expected_ids(ids: &[Id], data: &[u8], n: usize) -> Vec<Id> {
        let key = Id::from(*blake3::hash(data).as_bytes());
        let mut expected = ids
            .iter()
            .cloned()
            .map(|id| (Distance::between(&id, &key), id))
            .collect::<Vec<_>>();
        expected.sort();
        expected.truncate(n);
        expected.into_iter().map(|(_, id)| id).collect()
    }

    fn print_ids(ids: &[Id], data: &[u8]) {
        let key = Id::from(*blake3::hash(data).as_bytes());
        let ids_and_distance = ids
            .iter()
            .cloned()
            .map(|id| (Distance::between(&id, &key), id))
            .collect::<Vec<_>>();
        println!("IDs:");
        for (dist, id) in ids_and_distance {
            println!(" - {} {}", id, dist);
        }
    }

    fn sorted_ids(ids: &[Id], key: Id) -> BTreeSet<(Distance, Id)> {
        ids.into_iter().map(|id| (Distance::between(id, &key), *id)).collect()
    }

    fn sorted_ids_map(ids: &[Id], key: Id) -> BTreeMap<Distance, BTreeSet<Id>> {
        let mut map: BTreeMap<Distance, BTreeSet<Id>> = BTreeMap::new();
        for id in ids {
            let dist = Distance::between(id, &key);
            map.entry(dist).or_default().insert(*id);
        }
        map
    }

    #[tokio::test]
    async fn smoke() {
        let n = 21;
        let mut rng = rand::rngs::StdRng::from_seed([0; 32]);
        let network = Arc::new(Mutex::new(BTreeMap::new()));
        let ids = (0..n)
            .map(|_| Id::from(rng.r#gen::<[u8; 32]>()))
            .collect::<Vec<_>>();
        let nodes = ids
            .iter()
            .enumerate()
            .map(|(offfset, id)| {
                let endpoint = TestEndpoint {
                    state: network.clone(),
                    id: *id,
                };
                let bootstrap = (0..20)
                    .map(|i| ids[(offfset + i + 1) % n])
                    .collect::<Vec<_>>();
                (*id, create_node(*id, bootstrap, endpoint))
            })
            .collect::<Vec<_>>();
        network
            .lock()
            .unwrap()
            .extend(nodes.iter().map(|(id, (rpc, _))| (*id, rpc.clone())));
        let (_, (_, api)) = nodes[0].clone();

        for i in 0..1 {
            let text = format!("Item {i}");
            let expected_ids = expected_ids(&ids, text.as_bytes(), 20);
            let (hash, ids) = api.put_immutable(text.as_bytes()).await.unwrap();
            println!("Actual IDs:");
            print_ids(&ids, text.as_bytes());
            println!("Expected IDs:");
            print_ids(&expected_ids, text.as_bytes());
            assert_eq!(expected_ids.len(), ids.len());
            for i in 0..ids.len() {
                assert_eq!(ids[i], expected_ids[i], "Mismatch at index {i}");
            }
            println!("Put immutable: hash = {}, ids = {:?}", hash, ids);
            let data = api.get_immutable(hash).await.unwrap();
            println!("Get immutable: data = {:?}", data);
        }
    }
}
