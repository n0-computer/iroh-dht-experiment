//! # Minimal DHT for iroh
//!
//! A DHT is two things:
//!
//! ## Data storage
//!
//! A multimap of keys to values, where values are self contained pieces of data
//! that have some way to be verified and have some relationship to the key.
//!
//! Values should have some kind of expiry mechanism, but they don't need
//! provenance since they are self-contained.
//!
//! The storage part of the DHT is basically a standalone tracker, except for
//! the fact that it will reject set requests that are obviously far away
//! from the node id in terms of the DHT metric.
//!
//! Disabling the latter mechanism would allow a single DHT node to act as a
//! tracker.
//!
//! Examples of values:
//!
//! - Provider node ids for a key, where the key is interpreted as a BLAKE3 hash
//! of some data. Expiry is a timestamp, validation is checking that the node
//! has the data by means of a BLAKE3 probe.
//!
//! - A signed message, e.g. a pkarr record, where the key is interpreted as
//! the public key of the signer. Expiry is a timestamp, validation is
//! checking the signature against the public key.
//!
//! - Self-contained immutable data, where the key is interpreted as a BLAKE3
//! hash of the data. Expiry is a timestamp, validation is checking that the
//! data matches the hash.
//!
//! Data storage will use postcard on the wire and most likely also on disk.
//!
//! ## Routing
//!
//! A way to find the n most natural locations for a given key. Routing is only
//! concerned with the key, not the value.
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    num::NonZeroU64,
    time::UNIX_EPOCH,
};

use futures_buffered::FuturesUnordered;
use indexmap::IndexSet;
use iroh::Endpoint;
use iroh_base::SignatureError;
use irpc::channel::mpsc;
use n0_future::{BufferedStreamExt, StreamExt, stream};
use rand::{SeedableRng, seq::index::sample};
use snafu::Snafu;
use tokio::task::JoinSet;
#[cfg(test)]
mod tests;
pub mod proto {
    //! RPC protocol that DHT nodes use to communicate with each other.
    //!
    //! These are low level operations that only affect the node being called.
    //! E.g. finding closest nodes for a node based on the current content of
    //! the routing table, as well as storing and getting values.
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
        pub fn blake3_hash(data: &[u8]) -> Self {
            let hash = blake3::hash(data);
            Id(hash.into())
        }

        pub fn node_id(id: iroh::NodeId) -> Self {
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
        #[rpc(tx = oneshot::Sender<Vec<Id>>)]
        FindNode(FindNode),
    }
}

mod routing {
    use std::{
        fmt,
        ops::{Index, IndexMut},
    };

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

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Distance([u8; 32]);

    impl Distance {
        pub fn between(a: &Id, b: &Id) -> Self {
            Self(xor(a, b))
        }

        /// This is the inverse of between.
        ///
        /// Distance::between(&x, &y).to_node(&y) == x
        pub fn to_node(&self, target: &Id) -> Id {
            Id::from(xor(&Id::from(self.0), target))
        }

        pub const MAX: Self = Self([u8::MAX; 32]);
    }

    impl fmt::Debug for Distance {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Distance({})", self)
        }
    }

    impl fmt::Display for Distance {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", hex::encode(self.0))
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

    #[derive(Debug, Clone, Default)]
    pub(crate) struct KBucket {
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

        pub fn nodes(&self) -> &[NodeInfo] {
            &self.nodes
        }
    }

    #[derive(Debug)]
    pub(crate) struct RoutingTable {
        pub buckets: Box<Buckets>,
        local_id: Id,
    }

    #[derive(Debug, Clone)]
    pub(crate) struct Buckets([KBucket; BUCKET_COUNT]);

    impl Buckets {
        pub fn iter(&self) -> std::slice::Iter<'_, KBucket> {
            self.0.iter()
        }
    }

    impl Index<usize> for Buckets {
        type Output = KBucket;
        fn index(&self, index: usize) -> &Self::Output {
            &self.0[index]
        }
    }

    impl IndexMut<usize> for Buckets {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.0[index]
        }
    }

    impl Default for Buckets {
        fn default() -> Self {
            Self(std::array::from_fn(|_| KBucket::new()))
        }
    }

    impl RoutingTable {
        pub fn new(local_id: Id, buckets: Option<Box<Buckets>>) -> Self {
            let buckets = buckets
                .map(|mut buckets| {
                    for bucket in buckets.0.iter_mut() {
                        bucket.nodes.retain(|n| n.id != local_id);
                    }
                    buckets
                })
                .unwrap_or_default();
            Self { buckets, local_id }
        }

        fn bucket_index(&self, target: &Id) -> usize {
            let distance = xor(&self.local_id, target);
            let zeros = leading_zeros(&distance);
            if zeros >= BUCKET_COUNT {
                0 // Same node case
            } else {
                BUCKET_COUNT - 1 - zeros
            }
        }

        pub(crate) fn add_node(&mut self, node: NodeInfo) -> bool {
            if node.id == self.local_id {
                return false;
            }

            let bucket_idx = self.bucket_index(&node.id);
            self.buckets[bucket_idx].add_node(node)
        }

        pub(crate) fn remove_node(&mut self, id: &Id) {
            let bucket_idx = self.bucket_index(id);
            self.buckets[bucket_idx].remove_node(id);
        }

        pub(crate) fn nodes(&self) -> impl Iterator<Item = &NodeInfo> {
            self.buckets.iter().flat_map(|bucket| bucket.nodes())
        }

        pub(crate) fn find_closest_nodes(&self, target: &Id, k: usize) -> Vec<Id> {
            // this does a brute force scan, but even so it should be very fast.
            // xor is basically free, and comparing distances as well.
            // so the most expensive thing is probably the memory allocation.
            //
            // for a full routing table, this would be 256*20*32 = 163840 bytes.
            let mut candidates = Vec::with_capacity(self.nodes().count());
            candidates.extend(self.nodes().map(|node| Distance::between(target, &node.id)));
            if k < candidates.len() {
                candidates.select_nth_unstable(k - 1);
                candidates.truncate(k);
            }
            candidates.sort_unstable();

            candidates
                .into_iter()
                .map(|dist| dist.to_node(target))
                .collect()
        }
    }
}

use crate::{
    api::{
        ApiMessage, GetRoutingTable, GetStorageStats, Lookup, NetworkGet, NetworkPut, NodesDead,
        NodesSeen,
    },
    proto::{
        Blake3Immutable, FindNode, GetAll, Id, Kind, Ping, Pong, RpcMessage, RpcRequests, Set,
        SetResponse, Value,
    },
    routing::{ALPHA, Buckets, Distance, K, NodeInfo, RoutingTable},
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
    /// notify the node that we have just seen these nodes.
    ///
    /// The impl should add these nodes to the routing table.
    pub async fn nodes_seen(&self, ids: &[Id]) -> irpc::Result<()> {
        self.0.notify(NodesSeen { ids: ids.to_vec() }).await
    }

    /// notify the node that we have tried to contact these nodes and have not gotten a response.
    ///
    /// The impl can either clean these nodes from its routing table immediately or after a repeat offense.
    pub async fn nodes_dead(&self, ids: &[Id]) -> irpc::Result<()> {
        self.0.notify(NodesDead { ids: ids.to_vec() }).await
    }

    pub async fn get_storage_stats(&self) -> irpc::Result<BTreeMap<Id, BTreeMap<Kind, usize>>> {
        self.0.rpc(GetStorageStats).await
    }

    pub async fn get_routing_table(&self) -> irpc::Result<Vec<Vec<NodeInfo>>> {
        self.0.rpc(GetRoutingTable).await
    }

    pub async fn lookup(
        &self,
        id: Id,
        seed: Option<NonZeroU64>,
        n: Option<NonZeroU64>,
    ) -> irpc::Result<irpc::channel::mpsc::Receiver<Id>> {
        self.0.server_streaming(Lookup { id, seed, n }, 32).await
    }

    pub async fn get_immutable(&self, hash: blake3::Hash) -> irpc::Result<Option<Vec<u8>>> {
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

    pub async fn put_immutable(&self, value: &[u8]) -> irpc::Result<(blake3::Hash, Vec<Id>)> {
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

    pub async fn find_node(&self, id: Id) -> irpc::Result<Vec<Id>> {
        self.0.rpc(FindNode { id }).await
    }
}

/// A pool that can efficiently provide clients given a node id, and knows its
/// own identity.
///
/// For tests, this is just a map from id to client. For production, this will
/// wrap an iroh Endpoint and have some sort of connection cache.
pub trait ClientPool: Send + Sync + Clone + Sized + 'static {
    /// Our own node id
    fn id(&self) -> Id;

    /// Use the client to perform an operation.
    ///
    /// You must not clone the client out of the closure. If you do, this client
    /// can become unusable at any time!
    fn with_client<F, Fut, R, E>(&self, id: Id, f: F) -> impl Future<Output = Result<R, E>> + Send
    where
        F: FnOnce(RpcClient) -> Fut + Send + 'static,
        Fut: Future<Output = Result<R, E>> + Send + 'static,
        R: Send + 'static,
        E: From<PoolError>;
}

/// Error when a pool can not obtain a client.
#[derive(Debug, Snafu)]
pub struct PoolError {
    message: &'static str,
}

pub mod api {
    //! RPC protocol for an user to talk to a DHT node.
    //!
    //! These are operations that affect the entire network, such as storing or retrieving a value.
    use std::{collections::BTreeMap, num::NonZeroU64};

    use irpc::{
        channel::{mpsc, none::NoSender, oneshot},
        rpc_requests,
    };
    use serde::{Deserialize, Serialize};

    use crate::{
        proto::{Id, Kind, Value},
        routing::NodeInfo,
    };

    #[rpc_requests(message = ApiMessage)]
    #[derive(Debug, Serialize, Deserialize)]
    pub enum ApiProto {
        #[rpc(wrap, tx = NoSender)]
        NodesSeen { ids: Vec<Id> },
        #[rpc(wrap, tx = NoSender)]
        NodesDead { ids: Vec<Id> },
        #[rpc(wrap, tx = mpsc::Sender<Id>)]
        Lookup {
            id: Id,
            seed: Option<NonZeroU64>,
            n: Option<NonZeroU64>,
        },
        #[rpc(wrap, tx = mpsc::Sender<Id>)]
        NetworkPut { id: Id, value: Value },
        #[rpc(wrap, tx = mpsc::Sender<(Id, Value)>)]
        NetworkGet {
            id: Id,
            kind: Kind,
            seed: Option<NonZeroU64>,
            n: Option<NonZeroU64>,
        },
        /// Get the routing table for testing
        #[rpc(wrap, tx = oneshot::Sender<Vec<Vec<NodeInfo>>>)]
        GetRoutingTable,
        /// Get storage stats for testing
        #[rpc(wrap, tx = oneshot::Sender<BTreeMap<Id, BTreeMap<Kind, usize>>>)]
        GetStorageStats,
    }
}
use api::ApiProto;

/// State of the actor that is required in the async handlers
#[derive(Debug, Clone)]
struct State<P> {
    /// ability to send messages to ourselves, e.g. to update the routing table
    api: ApiClient,
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

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(transparent)]
    Client { source: PoolError },
    #[snafu(transparent)]
    Irpc { source: irpc::Error },
}

impl From<irpc::channel::SendError> for Error {
    fn from(source: irpc::channel::SendError) -> Self {
        Self::Irpc {
            source: irpc::Error::from(source),
        }
    }
}

impl<P> Actor<P>
where
    P: ClientPool,
{
    fn new(node: Node, rx: tokio::sync::mpsc::Receiver<RpcMessage>, pool: P) -> (Self, ApiClient) {
        let (api_tx, internal_rx) = tokio::sync::mpsc::channel(32);
        let api = ApiClient(api_tx.into());
        (
            Self {
                node,
                rpc_rx: rx,
                api_rx: internal_rx,
                tasks: JoinSet::new(),
                state: State {
                    api: api.clone(),
                    pool,
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
            ApiMessage::NodesSeen(msg) => {
                let now = now();
                for id in msg.ids.iter().copied() {
                    self.node
                        .routing_table
                        .add_node(NodeInfo { id, last_seen: now });
                }
            }
            ApiMessage::NodesDead(msg) => {
                for id in msg.ids.iter() {
                    self.node.routing_table.remove_node(id);
                }
            }
            ApiMessage::Lookup(msg) => {
                let initial = self.node.routing_table.find_closest_nodes(&msg.id, K);
                self.tasks
                    .spawn(self.state.clone().lookup(initial, msg.inner, msg.tx));
            }
            ApiMessage::NetworkGet(msg) => {
                // perform a network get by calling the iterative search using the closest
                // nodes from the local routing table, then performing individual requests
                // for the resulting k closest live nodes.
                let initial = self.node.routing_table.find_closest_nodes(&msg.id, K);
                self.tasks
                    .spawn(self.state.clone().network_get(initial, msg.inner, msg.tx));
            }
            ApiMessage::NetworkPut(msg) => {
                // perform a network put by calling the iterative search using the closest
                // nodes from the local routing table, then performing individual requests
                // for the resulting k closest live nodes.
                let initial = self.node.routing_table.find_closest_nodes(&msg.id, K);
                self.tasks
                    .spawn(self.state.clone().network_put(initial, msg.inner, msg.tx));
            }
            ApiMessage::GetRoutingTable(msg) => {
                let table = self
                    .node
                    .routing_table
                    .buckets
                    .iter()
                    .map(|bucket| bucket.nodes().to_vec())
                    .collect();
                msg.tx.send(table).await.ok();
            }
            ApiMessage::GetStorageStats(msg) => {
                // Collect storage stats, mapping Id to Kind to count of values
                let mut stats = BTreeMap::new();
                for (key, kinds) in &self.node.storage.data {
                    let kind_stats = kinds
                        .iter()
                        .map(|(kind, values)| (kind.clone(), values.len()))
                        .collect();
                    stats.insert(*key, kind_stats);
                }
                msg.tx.send(stats).await.ok();
            }
        }
    }

    async fn handle_rpc(&mut self, message: RpcMessage) {
        match message {
            RpcMessage::Set(msg) => {
                // just set the value in the local storage
                //
                // TODO: check if the data is expired or invalid and return the
                // appropriate error response.
                //
                // Sanity check that this node is a good node to store
                // the data at, using the local routing table, and if not return
                // a SetResponse::ErrDistance.
                let ids = self
                    .node
                    .routing_table
                    .find_closest_nodes(&msg.key, self.state.config.k);
                let self_dist = Distance::between(&self.node.id, &msg.key);
                if ids
                    .iter()
                    .all(|id| Distance::between(&self.node.id, id) < self_dist)
                {
                    msg.tx.send(SetResponse::ErrDistance).await.ok();
                    return;
                }
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
                let ids = self
                    .node
                    .routing_table
                    .find_closest_nodes(&msg.id, self.state.config.k);
                msg.tx.send(ids).await.ok();
            }
        }
    }
}

impl<P: ClientPool> State<P> {
    async fn lookup(self, initial: Vec<Id>, msg: Lookup, tx: mpsc::Sender<Id>) {
        let ids = self.clone().iterative_find_node(msg.id, initial).await;
        for id in ids {
            if tx.send(id).await.is_err() {
                break; // Stop sending if the receiver is closed
            }
        }
    }

    async fn network_put(self, initial: Vec<Id>, msg: NetworkPut, tx: mpsc::Sender<Id>) {
        let ids = self.clone().iterative_find_node(msg.id, initial).await;
        stream::iter(ids)
            .for_each_concurrent(self.config.parallelism, |id| {
                let pool = self.pool.clone();
                let value = msg.value.clone();
                let tx = tx.clone();
                async move {
                    pool.with_client(id, move |client| async move {
                        if client.set(msg.id, value).await.is_ok() {
                            tx.send(id).await?;
                        }
                        std::result::Result::<(), Error>::Ok(())
                    })
                    .await
                    .ok();
                }
            })
            .await;
    }

    async fn network_get(self, initial: Vec<Id>, msg: NetworkGet, tx: mpsc::Sender<(Id, Value)>) {
        let ids = self.clone().iterative_find_node(msg.id, initial).await;
        stream::iter(ids)
            .for_each_concurrent(self.config.parallelism, |id| {
                let pool = self.pool.clone();
                let tx = tx.clone();
                let msg = NetworkGet {
                    id: msg.id,
                    kind: msg.kind,
                    seed: msg.seed,
                    n: msg.n,
                };
                async move {
                    pool.with_client(id, move |client| async move {
                        // Get all values of the specified kind for the key
                        let mut rx = client.get_all(msg.id, msg.kind, msg.seed, msg.n).await?;
                        while let Ok(Some(value)) = rx.recv().await {
                            tx.send((id, value)).await?;
                        }
                        std::result::Result::<(), Error>::Ok(())
                    })
                    .await
                    .ok();
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
            let ids = self
                .pool
                .with_client(id, move |client| async move {
                    let mut ids = client.find_node(target).await?;
                    std::result::Result::<Vec<Id>, Error>::Ok(ids)
                })
                .await
                .map_err(|_| "Failed to query node")?;
            Ok(ids)
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
            let mut tasks = FuturesUnordered::new();
            let mut result = BTreeSet::new();
            let mut i = 0;
            queried.insert(self.pool.id());
            result.insert((Distance::between(&self.pool.id(), &target), self.pool.id()));

            loop {
                for _ in 0..self.config.alpha {
                    let Some(pair @ (_, id)) = candidates.pop_first() else {
                        break;
                    };
                    queried.insert(id);
                    let fut = self.query_one(id, target, self.config.k);
                    tasks.push(async move { (pair, fut.await) });
                }

                while let Some((pair @ (_, id), cands)) = tasks.next().await {
                    let Ok(cands) = cands else {
                        self.api.nodes_dead(&[id]).await.ok();
                        continue;
                    };
                    for cand in cands {
                        let dist = Distance::between(&target, &cand);
                        if !queried.contains(&cand) {
                            candidates.insert((dist, cand));
                        }
                    }
                    self.api.nodes_seen(&[id]).await.ok();
                    result.insert(pair);
                }

                // truncate the result to k.
                while result.len() > self.config.k {
                    result.pop_last();
                }

                // find the k-th best distance
                let kth_best_distance = result
                    .iter()
                    .nth(self.config.k - 1)
                    .map(|(dist, _)| *dist)
                    .unwrap_or(Distance::MAX);

                // true if we candidates that are better than distance for result[k-1].
                let has_closer_candidates = candidates
                    .first()
                    .map(|(dist, _)| *dist < kth_best_distance)
                    .unwrap_or_default();

                if !has_closer_candidates {
                    break;
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

/// Creates a DHT node
pub fn create_node<P: ClientPool>(id: Id, pool: P, bootstrap: Vec<Id>) -> (RpcClient, ApiClient) {
    create_node_impl(id, pool, bootstrap, None)
}

/// Create a node, given an id, a set of bootstrap nodes, a
fn create_node_impl<P: ClientPool>(
    id: Id,
    pool: P,
    bootstrap: Vec<Id>,
    buckets: Option<Box<Buckets>>,
) -> (RpcClient, ApiClient) {
    let mut node = Node {
        id,
        routing_table: RoutingTable::new(id, buckets),
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
    let (actor, api) = Actor::<P>::new(node, rx, pool);
    tokio::spawn(actor.run());
    (RpcClient(irpc::Client::local(tx)), api)
}
