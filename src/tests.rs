//! In memory integration style tests
//!
//! These are long running tests that spawn a lot of nodes and observe the
//! behaviour of an entire swarm. Most tests use in-memory nodes.
use std::sync::{Arc, Mutex};

use iroh::{
    Endpoint, SecretKey, Watcher, discovery::static_provider::StaticProvider, endpoint::BindError,
    protocol::Router,
};
use iroh_connection_pool::connection_pool::ConnectionPool;
use rand::{Rng, rngs::StdRng, seq::SliceRandom};
use testresult::TestResult;
use textplots::{Chart, Plot, Shape};

use super::*;
use crate::{pool::IrohPool, rpc::Blake3Immutable};

#[derive(Debug, Clone)]
struct TestPool {
    clients: Arc<Mutex<BTreeMap<NodeId, RpcClient>>>,
    node_id: NodeId,
}

impl ClientPool for TestPool {
    async fn client(&self, id: NodeId) -> Result<RpcClient, String> {
        let client = self
            .clients
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("client not found: {id}"))?;
        Ok(client)
    }

    fn id(&self) -> NodeId {
        self.node_id
    }
}

fn expected_ids(ids: &[NodeId], key: Id, n: usize) -> Vec<NodeId> {
    let mut expected = ids
        .iter()
        .cloned()
        .map(|id| (Distance::between(id.as_bytes(), &key), id))
        .collect::<Vec<_>>();
    // distances are unique!
    expected.sort_unstable();
    expected.dedup();
    expected.truncate(n);
    expected.into_iter().map(|(_, id)| id).collect()
}

type Nodes = Vec<(NodeId, (RpcClient, ApiClient))>;

fn rng(seed: u64) -> StdRng {
    let mut expanded = [0; 32];
    expanded[..8].copy_from_slice(&seed.to_le_bytes());
    StdRng::from_seed(expanded)
}

/// Choose boostrap nodes.
///
/// Selection indexes will be wrapped around.
/// The node itself will never be considered.
/// Duplicates will be removed.
fn apply_selection(this: usize, ids: &[NodeId], selection: &[usize]) -> Vec<NodeId> {
    let mut res = Vec::new();
    for i in selection {
        if *i == this {
            continue;
        }
        let offset = i % ids.len();
        let id = ids[offset];
        if !res.contains(&id) {
            res.push(id);
        }
    }
    res
}

type Clients = Arc<Mutex<BTreeMap<NodeId, RpcClient>>>;

async fn create_nodes(
    ids: &[NodeId],
    select_bootstrap: impl Fn(usize) -> Vec<usize>,
    config: Config,
) -> Nodes {
    create_nodes_and_clients(ids, select_bootstrap, config)
        .await
        .0
}

/// Creates n nodes with the given seed, and at most n_bootstrap bootstrap nodes.
///
/// Bootstrap nodes are just the n_bootstrap next nodes in the ring.
async fn create_nodes_and_clients(
    ids: &[NodeId],
    select_bootstrap: impl Fn(usize) -> Vec<usize>,
    config: Config,
) -> (Nodes, Clients) {
    let clients = Arc::new(Mutex::new(BTreeMap::new()));
    // create n nodes
    let nodes = ids
        .iter()
        .enumerate()
        .map(|(offfset, id)| {
            let pool = TestPool {
                clients: clients.clone(),
                node_id: *id,
            };
            let bootstrap = apply_selection(offfset, ids, &select_bootstrap(offfset));
            (
                *id,
                create_node_impl(*id, pool, bootstrap, None, config.clone()),
            )
        })
        .collect::<Vec<_>>();
    clients
        .lock()
        .unwrap()
        .extend(nodes.iter().map(|(id, (rpc, _))| (*id, rpc.clone())));
    (nodes, clients)
}

/// Brute force init of the routing table of all nodes using a set of ids, that could be the full set.
///
/// Provide a seed to shuffle the ids for each node.
async fn init_routing_tables(nodes: &Nodes, ids: &[NodeId], seed: Option<u64>) -> irpc::Result<()> {
    let mut rng = seed.map(rng);
    let ids = ids.to_vec();
    stream::iter(nodes.iter().enumerate())
        .for_each_concurrent(4096, |(index, (_, (_, api)))| {
            if ids.len() > 10000 {
                println!("{index}");
            }
            let mut ids = ids.clone();
            if let Some(rng) = &mut rng {
                ids.shuffle(rng);
            }
            async move {
                api.nodes_seen(&ids).await.ok();
            }
        })
        .await;
    Ok(())
}

fn make_histogram(data: &[usize]) -> Vec<usize> {
    let max = data.iter().max().cloned().unwrap_or(0);
    let mut histogram = vec![0usize; max + 1];
    for value in data.iter().cloned() {
        histogram[value] += 1;
    }
    histogram
}

fn plot(title: &str, data: &[usize]) {
    let data: Vec<(f32, f32)> = data
        .iter()
        .enumerate()
        .map(|(items_stored, num_nodes)| (items_stored as f32, *num_nodes as f32))
        .collect();

    println!("{title}");
    Chart::new(100, 40, 0.0, (data.len() - 1) as f32)
        .lineplot(&Shape::Bars(&data))
        .nice();
}

/// Let each node do a random lookup
async fn random_lookup(nodes: &Nodes, rng: &mut StdRng) -> irpc::Result<()> {
    stream::iter(nodes.iter())
        .for_each_concurrent(4096, |(_, (_, api))| {
            let key = Id::from(rng.r#gen::<[u8; 32]>());
            async move {
                // perform a random lookup
                api.lookup(key, None).await.ok();
            }
        })
        .await;
    Ok(())
}

async fn random_lookup_n(nodes: &Nodes, n: usize, seed: u64) -> irpc::Result<()> {
    let mut rng = rng(seed);
    for _ in 0..n {
        random_lookup(nodes, &mut rng).await?;
    }
    Ok(())
}

async fn store_random_values(nodes: &Nodes, n: usize) -> irpc::Result<()> {
    let (_, (_, api)) = nodes[nodes.len() / 2].clone();
    let ids = nodes.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let mut common_count = vec![0usize; n];
    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        if nodes.len() > 10000 {
            println!("Value {i}");
        }
        let text = format!("Item {i}");
        let expected_ids = expected_ids(&ids, Id::blake3_hash(text.as_bytes()), 20);
        let (hash, ids) = api.put_immutable(text.as_bytes()).await.unwrap();
        let mut common = expected_ids.clone();
        common.retain(|id| ids.contains(id));
        common_count[i] = common.len();
        let data = api.get_immutable(hash).await.unwrap();
        assert_eq!(
            data,
            Some(text.as_bytes().to_vec()),
            "Data mismatch for item {i}"
        );
    }

    let mut storage_count = vec![0usize; nodes.len()];
    let mut routing_table_size = vec![0usize; nodes.len()];
    for (index, (_, (_, api))) in nodes.iter().enumerate() {
        let stats = api.get_storage_stats().await?;
        if !stats.is_empty() {
            let n = stats
                .values()
                .map(|kinds| kinds.values().sum::<usize>())
                .sum::<usize>();
            storage_count[index] = n;
            // println!("Storage stats for node {index}: {n}");
        }
    }

    for (index, (_, (_, api))) in nodes.iter().enumerate() {
        let routing_table = api.get_routing_table().await?;
        let count = routing_table.iter().map(|peers| peers.len()).sum::<usize>();
        // println!("Routing table {index}: {count} nodes");
        routing_table_size[index] = count;
    }

    plot(
        "Histogram - Commonality with perfect set of 20 ids",
        &make_histogram(&common_count),
    );
    plot("Storage usage per node", &storage_count);
    plot(
        "Histogram - Storage usage per node",
        &make_histogram(&storage_count),
    );
    plot("Routing table size per node", &routing_table_size);
    plot(
        "Histogram - Routing table size per node",
        &make_histogram(&routing_table_size),
    );
    Ok(())
}

/// Performs n random lookups without storing anything, then plots stats
async fn plot_random_lookup_stats(nodes: &Nodes, n: usize) -> irpc::Result<()> {
    let (_, (_, api)) = nodes[nodes.len() / 2].clone();
    let ids = nodes.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let mut common_count = vec![0usize; n];
    let mut storage_count = vec![0usize; nodes.len()];
    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        if nodes.len() > 10000 {
            println!("{i}");
        }
        let text = format!("Item {i}");
        let id = Id::from(blake3::hash(text.as_bytes()));
        let storage_ids = api.lookup(id, None).await.unwrap();
        let expected_ids = expected_ids(&ids, Id::blake3_hash(text.as_bytes()), 20);
        let mut common = expected_ids.clone();
        common.retain(|id| storage_ids.contains(id));
        common_count[i] = common.len();
        for id in &storage_ids {
            let idx = ids.iter().position(|x| *x == *id).unwrap();
            storage_count[idx] += 1;
        }
    }

    let mut routing_table_size = vec![0usize; nodes.len()];
    for (index, (_, (_, api))) in nodes.iter().enumerate() {
        let routing_table = api.get_routing_table().await?;
        let count = routing_table.iter().map(|peers| peers.len()).sum::<usize>();
        // println!("Routing table {index}: {count} nodes");
        routing_table_size[index] = count;
    }

    plot(
        "Histogram - Commonality with perfect set of 20 ids",
        &make_histogram(&common_count),
    );
    plot("Storage usage per node", &storage_count);
    plot(
        "Histogram - Storage usage per node",
        &make_histogram(&storage_count),
    );
    plot("Routing table size per node", &routing_table_size);
    plot(
        "Histogram - Routing table size per node",
        &make_histogram(&routing_table_size),
    );
    Ok(())
}

/// Create routing table buckets for the given ids.
///
/// Note that if there are a lot of ids, they won't all fit.
#[allow(dead_code)]
fn create_buckets(ids: &[NodeId]) -> Box<Buckets> {
    let secret = SecretKey::from_bytes(&[0; 32]);
    let node_id = secret.public();
    let mut routing_table = RoutingTable::new(node_id, None);
    for id in ids {
        routing_table.add_node(NodeInfo {
            id: *id,
            last_seen: now(),
        });
    }
    routing_table.buckets
}

fn next_n(n: usize) -> impl Fn(usize) -> Vec<usize> {
    move |offset| (1..=n).map(|i| offset + i).collect::<Vec<_>>()
}

#[tokio::test(flavor = "multi_thread")]
async fn no_routing_1k() {
    let n = 1000;
    let seed = 0;
    let bootstrap = next_n(0);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let nodes = create_nodes(&ids, bootstrap, Config::default()).await;
    let clients = nodes.iter().cloned().collect::<BTreeMap<_, _>>();

    for i in 0..100 {
        let text = format!("Item {i}");
        let key = Id::blake3_hash(text.as_bytes());
        for id in expected_ids(&ids, key, 20) {
            let (rpc, _) = clients.get(&id).expect("Node not found");
            rpc.set(
                key,
                Value::Blake3Immutable(Blake3Immutable {
                    timestamp: now(),
                    data: text.as_bytes().to_vec(),
                }),
            )
            .await
            .ok();
        }
    }

    let mut storage_count = vec![0usize; nodes.len()];
    for (index, (_, (_, api))) in nodes.iter().enumerate() {
        let stats: BTreeMap<Id, BTreeMap<Kind, usize>> = api.get_storage_stats().await.unwrap();
        if !stats.is_empty() {
            let n = stats
                .values()
                .map(|kinds| kinds.values().sum::<usize>())
                .sum::<usize>();
            storage_count[index] = n;
        }
    }
    plot("Storage usage per node", &storage_count);
    plot(
        "Histogram - Storage usage per node",
        &make_histogram(&storage_count),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn perfect_routing_tables_1k() {
    let n = 1000;
    let seed = 0;
    let bootstrap = next_n(0);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let nodes = create_nodes(&ids, bootstrap, Config::default()).await;
    init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    store_random_values(&nodes, 100).await.ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn perfect_routing_tables_10k() {
    let n = 10000;
    let seed = 0;
    let bootstrap = next_n(0);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let nodes = create_nodes(&ids, bootstrap, Config::default()).await;

    // tell all nodes about all ids, shuffled for each node
    println!("init routing tables");
    init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    println!("store random values");
    store_random_values(&nodes, 100).await.ok();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs very long and takes ~20GiB"]
async fn perfect_routing_tables_100k() {
    let n = 100000;
    let seed = 0;
    let bootstrap = next_n(0);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let nodes = create_nodes(&ids, bootstrap, Config::default()).await;

    println!("init routing tables");
    init_routing_tables(&nodes, &ids, Some(seed)).await.ok();

    println!("store random values");
    store_random_values(&nodes, 100).await.ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn just_bootstrap_1k() {
    let n = 1000;
    let seed = 0;
    let bootstrap = next_n(20);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let nodes = create_nodes(&ids, bootstrap, Config::default()).await;

    // tell all nodes about all ids, shuffled for each node
    // init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    store_random_values(&nodes, 100).await.ok();
}

async fn random_lookup_test(n: usize, seed: u64, lookups: usize) {
    // bootstrap must be set so the random lookups have a chance to work!
    let bootstrap = next_n(20);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let nodes = create_nodes(&ids, bootstrap, Config::default()).await;

    random_lookup_n(&nodes, lookups, seed).await.ok();

    // tell all nodes about all ids, shuffled for each node
    // init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    store_random_values(&nodes, 100).await.ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn random_lookup_1k() {
    for lookups in 0..10 {
        random_lookup_test(1000, 0, lookups).await;
    }
}

const DHT_TEST_ALPN: &[u8] = b"iroh/dht/test-0";

type IrohNodes = Vec<(Endpoint, (RpcClient, ApiClient))>;

/// Creates n nodes with the given seed, and at most n_bootstrap bootstrap nodes.
///
/// Bootstrap nodes are just the n_bootstrap next nodes in the ring.
///
/// These will be full iroh nodes with static discovery configured in such a way that they can find each other without bothering
/// the discovery service!
async fn iroh_create_nodes(
    secrets: &[SecretKey],
    mut n_bootstrap: usize,
    buckets: Option<Box<Buckets>>,
) -> std::result::Result<IrohNodes, BindError> {
    let n = secrets.len();
    let node_ids = secrets.iter().map(|s| s.public()).collect::<Vec<_>>();
    let node_ids = Arc::new(node_ids);
    let buckets = Arc::new(buckets);
    let discovery = StaticProvider::new();
    n_bootstrap = n_bootstrap.min(n - 1);
    // create n nodes
    stream::iter(secrets.iter().zip(node_ids.iter()).enumerate())
        .map(|(offfset, (secret, node_id))| {
            let buckets = buckets.clone();
            let node_ids = node_ids.clone();
            let discovery = discovery.clone();
            async move {
                let endpoint = Endpoint::builder()
                    .secret_key(secret.clone())
                    .relay_mode(iroh::RelayMode::Disabled)
                    .discovery(discovery.clone())
                    .bind()
                    .await?;
                let addr = endpoint.node_addr().initialized().await;
                discovery.add_node_info(addr.clone());
                let pool = ConnectionPool::new(
                    endpoint.clone(),
                    DHT_TEST_ALPN,
                    iroh_connection_pool::connection_pool::Options {
                        max_connections: 32,
                        idle_timeout: Duration::from_secs(1),
                        connect_timeout: Duration::from_secs(1),
                    },
                );
                let pool = IrohPool::new(endpoint.clone(), pool);
                let bootstrap = (0..n_bootstrap)
                    .map(|i| node_ids[(offfset + i + 1) % n])
                    .collect::<Vec<_>>();
                let (rpc, api) = create_node_impl(
                    *node_id,
                    pool.clone(),
                    bootstrap,
                    (*buckets).clone(),
                    Default::default(),
                );
                pool.set_self_client(Some(rpc.downgrade()));
                Ok((endpoint, (rpc, api)))
            }
        })
        .buffered_unordered(32)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect()
}

fn create_secrets(seed: u64, n: usize) -> Vec<SecretKey> {
    // std rng is good enough for tests!
    let mut rng = rng(seed);
    (0..n)
        .map(|_| SecretKey::from_bytes(&rng.r#gen::<[u8; 32]>()))
        .collect()
}

fn create_node_ids(secrets: &[SecretKey]) -> Vec<NodeId> {
    secrets.iter().map(|s| s.public()).collect()
}

// todo: we need a special protocol handler that validates the requester id of
// incoming FindNode messages to be the remote node id. This is pretty
// straightforward, but I can't write it right now because of some
// dependency weirdness due to all the patching.
fn spawn_routers(iroh_nodes: &IrohNodes) -> Vec<Router> {
    iroh_nodes
        .iter()
        .map(|(endpoint, (rpc, _))| {
            let sender = rpc.0.as_local().unwrap();
            Router::builder(endpoint.clone())
                .accept(DHT_TEST_ALPN, irpc_iroh::IrohProtocol::with_sender(sender))
                .spawn()
        })
        .collect()
}
async fn iroh_perfect_routing_tables(n: usize) -> TestResult<()> {
    let seed = 0;
    let bootstrap = 0;
    let secrets = create_secrets(seed, n);
    println!("Creating {n} nodes");
    let iroh_nodes = iroh_create_nodes(&secrets, bootstrap, None).await?;
    let nodes = iroh_nodes
        .iter()
        .map(|(ep, x)| (ep.node_id(), x.clone()))
        .collect::<Vec<_>>();
    let ids = nodes.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    println!("Initializing routing tables");
    init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    println!("Spawning {n} routers");
    let _routers = spawn_routers(&iroh_nodes);
    println!("Storing random values");
    store_random_values(&nodes, 100).await.ok();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn iroh_perfect_routing_tables_500() -> TestResult<()> {
    iroh_perfect_routing_tables(500).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs very long and takes a lot of mem"]
async fn iroh_perfect_routing_tables_10k() -> TestResult<()> {
    iroh_perfect_routing_tables(10000).await
}

#[tokio::test(flavor = "multi_thread")]
async fn random_lookup_strategy() {
    let n = 1000;
    let seed = 0;
    let bootstrap = next_n(20);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let config = Config::default().random_lookup_strategy(RandomLookupStrategy {
        interval: Duration::from_secs(1),
        blended: false,
    });
    let nodes = create_nodes(&ids, bootstrap, config).await;
    for _i in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        plot_random_lookup_stats(&nodes, 100).await.ok();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn self_lookup_strategy() {
    let n = 1000;
    let seed = 0;
    let bootstrap = next_n(20);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let config = Config::default().self_lookup_strategy(SelfLookupStrategy {
        interval: Duration::from_secs(1),
    });
    let nodes = create_nodes(&ids, bootstrap, config).await;
    for _i in 0..20 {
        plot_random_lookup_stats(&nodes, 100).await.ok();
        tokio::time::sleep(Duration::from_secs(1)).await;
        println!();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn self_and_random_lookup_strategy() {
    let n = 1000;
    let seed = 0;
    let bootstrap = next_n(20);
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let config = Config::default()
        .self_lookup_strategy(SelfLookupStrategy {
            interval: Duration::from_secs(1),
        })
        .random_lookup_strategy(RandomLookupStrategy {
            interval: Duration::from_secs(1),
            blended: false,
        });
    let nodes = create_nodes(&ids, bootstrap, config).await;
    for _i in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        plot_random_lookup_stats(&nodes, 100).await.ok();
        println!();
    }
}

use std::{fs::File, path::Path};

use gif::{Encoder, Frame, Repeat};

struct Frames {
    data: Vec<Vec<bool>>,
    stride: usize,
}

impl Frames {
    fn new(stride: usize) -> Self {
        Frames {
            data: Vec::new(),
            stride,
        }
    }

    fn height(&self) -> Option<usize> {
        let first = self.data.first()?;
        assert!(
            self.data.iter().all(|f| f.len() == first.len()),
            "All frames must have the same length"
        );
        assert!(self.stride > 0, "Stride must be greater than zero");
        assert!(
            first.len().is_multiple_of(self.stride),
            "Size must be a multiple of stride"
        );
        Some(first.len() / self.stride)
    }

    fn side_by_side(frames: &[&Frames], gap: usize) -> TestResult<Frames> {
        let first = frames.first().unwrap();
        let height = first.height().unwrap();
        let n_frames = first.data.len();
        assert!(
            frames.iter().all(|f| f.stride > 0),
            "Stride must be greater than zero"
        );
        assert!(
            frames.iter().all(|f| f.height() == Some(height)),
            "All frames must have the same height"
        );
        assert!(
            frames.iter().all(|f| f.data.len() == n_frames),
            "All frames must have the same number of frames"
        );
        // width of the resulting frames
        let width = frames.iter().map(|f| f.stride).sum::<usize>() + gap * (frames.len() - 1);
        let mut res = Frames::new(width);
        for n_frame in 0..n_frames {
            let mut frame = Vec::new();
            // iterate each frame line by line. We know these iters will have the same size!
            let mut iters = frames
                .iter()
                .map(|f| f.data[n_frame].chunks(f.stride))
                .collect::<Vec<_>>();
            for _y in 0..height {
                for (i, iter) in iters.iter_mut().enumerate() {
                    let line = iter.next().unwrap();
                    if i > 0 {
                        // add gap between frames
                        frame.extend(std::iter::repeat_n(false, gap));
                    }
                    frame.extend_from_slice(line);
                }
            }
            res.data.push(frame);
        }
        Ok(res)
    }

    fn make_gif(&self, delay_ms: u64, target: impl AsRef<Path>) -> TestResult<()> {
        if self.data.is_empty() {
            return Ok(());
        }
        let size = self.data[0].len();
        assert!(self.stride > 0, "Stride must be greater than zero");
        assert!(
            size.is_multiple_of(self.stride),
            "Height must be a multiple of stride"
        );
        assert!(
            self.data.iter().all(|f| f.len() == size),
            "All frames must have the same length"
        );

        let width = self.stride;
        let height = size / self.stride;

        // Create output file
        let mut output = File::create(target)?;

        // Create encoder with a simple black/white palette
        let palette = [0, 0, 0, 255, 255, 255]; // Black and white
        let mut encoder = Encoder::new(&mut output, width as u16, height as u16, &palette)?;
        encoder.set_repeat(Repeat::Infinite)?;

        // Convert each bool array to a frame
        for frame_data in &self.data {
            // Convert bool array to indexed pixel data
            let mut pixels = Vec::with_capacity(frame_data.len());
            for &pixel in frame_data {
                pixels.push(if pixel { 1u8 } else { 0 }); // 0 = black, 1 = white
            }

            // Create frame with 100ms delay (10/100 seconds)
            let mut frame = Frame::from_indexed_pixels(width as u16, height as u16, pixels, None);
            frame.delay = (delay_ms / 10) as u16; // Convert ms to 1/100 seconds

            encoder.write_frame(&frame)?;
        }

        Ok(())
    }
}

async fn make_frame(ids: &[NodeId], nodes: &Nodes) -> TestResult<Vec<bool>> {
    let mut res = Vec::new();
    for (_, (_, api)) in nodes.iter() {
        let routing_table = api.get_routing_table().await?;
        let node_ids = routing_table
            .iter()
            .flat_map(|peers| peers.iter().map(|x| x.id))
            .collect::<HashSet<_>>();
        res.extend(ids.iter().map(|id| node_ids.contains(id)));
    }
    Ok(res)
}

#[tokio::test(flavor = "multi_thread")]
async fn partition_1k() -> TestResult<()> {
    let n = 1000;
    let k = 900;
    let seed = 0;
    let bootstrap = |i| {
        if i < k {
            // nodes below k form a ring
            (1..=20).map(|j| (i + j) % k).collect::<Vec<_>>()
        } else {
            // nodes above k don't have bootstrap peers
            vec![]
        }
    };
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    // all nodes have all the strategies enabled
    let config = Config::persistent()
        .self_lookup_strategy(SelfLookupStrategy {
            interval: Duration::from_secs(1),
        })
        .random_lookup_strategy(RandomLookupStrategy {
            interval: Duration::from_secs(1),
            blended: false,
        })
        .candidate_lookup_strategy(CandidateLookupStrategy {
            max_lookups: 1,
            interval: Duration::from_secs(1),
        });
    let (nodes, _clients) = create_nodes_and_clients(&ids, bootstrap, config).await;
    let mut frames = Vec::new();
    for _i in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        plot_random_lookup_stats(&nodes, 100).await.ok();
        frames.push(make_frame(&ids, &nodes).await?);
        println!();
    }
    let id0 = nodes[0].0;
    // tell the partitioned nodes about id0
    for i in k..n {
        let (_, (_, api)) = &nodes[i];
        api.nodes_seen(&[id0]).await.ok();
    }
    let mut frames = Frames::new(n);
    for _i in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        plot_random_lookup_stats(&nodes, 100).await.ok();
        let last_id = nodes.last().unwrap().0;
        let mut knows_last_id = 0;
        for (_, (_, api)) in nodes.iter() {
            let routing_table = api.get_routing_table().await?;
            knows_last_id += routing_table
                .iter()
                .map(|peers| peers.iter().filter(|x| x.id == last_id).count())
                .sum::<usize>();
        }
        frames.data.push(make_frame(&ids, &nodes).await?);
        println!("Nodes that know about last_id: {knows_last_id}");
    }
    frames.make_gif(100, "partition_1k.gif")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_1k() -> TestResult<()> {
    let n = 1000;
    let k = 900;
    let seed = 0;
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    // all nodes have all the strategies enabled
    let config = Config::persistent()
        .self_lookup_strategy(SelfLookupStrategy {
            interval: Duration::from_secs(1),
        })
        .random_lookup_strategy(RandomLookupStrategy {
            interval: Duration::from_secs(1),
            blended: false,
        })
        .candidate_lookup_strategy(CandidateLookupStrategy {
            max_lookups: 1,
            interval: Duration::from_secs(1),
        });
    let (nodes, clients) = create_nodes_and_clients(&ids, next_n(20), config).await;
    let mut frames = Frames {
        data: Vec::new(),
        stride: n,
    };
    for _i in 0..10 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        frames.data.push(make_frame(&ids, &nodes).await?);
        println!();
    }
    for i in k..n {
        clients.lock().unwrap().remove(&ids[i]);
    }
    for _i in 0..40 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        frames.data.push(make_frame(&ids, &nodes).await?);
        println!();
    }
    frames.make_gif(100, "remove_1k.gif")?;
    Ok(())
}

async fn trigger_random_lookups(nodes: &Nodes) {
    stream::iter(nodes.iter())
        .for_each_concurrent(512, |(_, (_, api))| async move {
            api.random_lookup().await;
        })
        .await;
}

/// Compares random and blended random lookups with 1000 nodes over 60 seconds
#[tokio::test(flavor = "multi_thread")]
async fn random_vs_blended_1k() -> TestResult<()> {
    let n = 1000;
    let seed = 0;
    let n_frames = 50;
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let random = {
        // all nodes have all the strategies enabled
        let config = Config::persistent().random_lookup_strategy(RandomLookupStrategy {
            // disable time based lookups
            interval: Duration::MAX,
            blended: false,
        });
        let nodes = create_nodes(&ids, next_n(20), config).await;
        let mut frames = Frames {
            data: Vec::new(),
            stride: n,
        };
        for _i in 0..n_frames {
            frames.data.push(make_frame(&ids, &nodes).await?);
            trigger_random_lookups(&nodes).await;
            println!();
        }
        frames
    };
    let blended = {
        // all nodes have all the strategies enabled
        let config = Config::persistent()
            // .self_lookup_strategy(SelfLookupStrategy {
            //     interval: Duration::from_secs(1),
            // })
            .random_lookup_strategy(RandomLookupStrategy {
                // disable time based lookups
                interval: Duration::MAX,
                blended: true,
            });
        let nodes = create_nodes(&ids, next_n(20), config).await;
        let mut frames = Frames {
            data: Vec::new(),
            stride: n,
        };
        for _i in 0..n_frames {
            frames.data.push(make_frame(&ids, &nodes).await?);
            trigger_random_lookups(&nodes).await;
            println!();
        }
        frames
    };
    let perfect = {
        // all nodes have all the strategies enabled
        let config = Config::persistent()
            // .self_lookup_strategy(SelfLookupStrategy {
            //     interval: Duration::from_secs(1),
            // })
            .random_lookup_strategy(RandomLookupStrategy {
                // disable time based lookups
                interval: Duration::MAX,
                blended: true,
            });
        let nodes = create_nodes(&ids, next_n(20), config).await;
        init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
        let mut frames = Frames {
            data: Vec::new(),
            stride: n,
        };
        for _i in 0..n_frames {
            frames.data.push(make_frame(&ids, &nodes).await?);
            // trigger_random_lookups(&nodes).await;
            println!();
        }
        frames
    };
    let frames = Frames::side_by_side(&[&random, &blended, &perfect], 20)?;
    frames.make_gif(100, "random_vs_blended_1k.gif")?;
    Ok(())
}
