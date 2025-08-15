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
    async fn with_client<F, Fut, R, E>(&self, id: NodeId, f: F) -> Result<R, E>
    where
        F: FnOnce(RpcClient) -> Fut + Send + 'static,
        Fut: Future<Output = Result<R, E>> + Send + 'static,
        R: Send + 'static,
        E: From<PoolError>,
    {
        let client = self
            .clients
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(E::from(PoolError {
                message: "client not found".into(),
            }))?;
        f(client).await
    }

    fn id(&self) -> NodeId {
        self.node_id
    }
}

fn expected_ids(ids: &[NodeId], key: Id, n: usize) -> Vec<NodeId> {
    let mut expected = ids
        .iter()
        .cloned()
        .map(|id| (Distance::between(&id.as_bytes(), &key), id))
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

/// Creates n nodes with the given seed, and at most n_bootstrap bootstrap nodes.
///
/// Bootstrap nodes are just the n_bootstrap next nodes in the ring.
async fn create_nodes(ids: &[NodeId], mut n_bootstrap: usize, config: Config) -> Nodes {
    let n = ids.len();
    n_bootstrap = n_bootstrap.min(n - 1);
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
            let bootstrap = (0..n_bootstrap)
                .map(|i| ids[(offfset + i + 1) % n])
                .collect::<Vec<_>>();
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
    nodes
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
            println!("{i}");
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

#[tokio::test(flavor = "multi_thread")]
async fn no_routing_1k() {
    let n = 1000;
    let seed = 0;
    let bootstrap = 0;
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
    let bootstrap = 0;
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
    let bootstrap = 0;
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
    let metrics = tokio::runtime::Handle::current().metrics();
    println!("{metrics:?}");
    let n = 100000;
    let seed = 0;
    let bootstrap = 0;
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
    let bootstrap = 20;
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let nodes = create_nodes(&ids, bootstrap, Config::default()).await;

    // tell all nodes about all ids, shuffled for each node
    // init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    store_random_values(&nodes, 100).await.ok();
}

async fn random_lookup_test(n: usize, seed: u64, lookups: usize) {
    // bootstrap must be set so the random lookups have a chance to work!
    let bootstrap = 20;
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
                let pool = ConnectionPool::new(endpoint.clone(), DHT_TEST_ALPN, Default::default());
                let pool = IrohPool::new(endpoint.clone(), pool);
                let bootstrap = (0..n_bootstrap)
                    .map(|i| node_ids[(offfset + i + 1) % n])
                    .collect::<Vec<_>>();
                Ok((
                    endpoint,
                    create_node_impl(
                        *node_id,
                        pool,
                        bootstrap,
                        (*buckets).clone(),
                        Default::default(),
                    ),
                ))
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

#[tokio::test(flavor = "multi_thread")]
async fn iroh_perfect_routing_tables_500() -> TestResult<()> {
    let n = 500;
    let seed = 0;
    let bootstrap = 0;
    let secrets = create_secrets(seed, n);
    println!("Creating {} nodes", n);
    let iroh_nodes = iroh_create_nodes(&secrets, bootstrap, None).await?;
    let nodes = iroh_nodes
        .iter()
        .map(|(ep, x)| (ep.node_id(), x.clone()))
        .collect::<Vec<_>>();
    let ids = nodes.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    println!("Initializing routing tables");
    init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    println!("Spawning {} routers", n);
    let _routers = spawn_routers(&iroh_nodes);
    println!("Storing random values");
    store_random_values(&nodes, 100).await.ok();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn random_lookup_strategy() {
    let n = 1000;
    let seed = 0;
    let bootstrap = 20;
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let config = Config::default().random_lookup_strategy(RandomLookupStrategy {
        interval: Duration::from_secs(1),
    });
    let nodes = create_nodes(&ids, bootstrap, config).await;
    for i in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        println!("\nAfter {i}s");
        plot_random_lookup_stats(&nodes, 100).await.ok();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn self_lookup_strategy() {
    let n = 1000;
    let seed = 0;
    let bootstrap = 20;
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let config = Config::default().self_lookup_strategy(SelfLookupStrategy {
        interval: Duration::from_secs(1),
    });
    let nodes = create_nodes(&ids, bootstrap, config).await;
    for i in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        println!("\nAfter {i}s");
        plot_random_lookup_stats(&nodes, 100).await.ok();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn self_and_random_lookup_strategy() {
    let n = 1000;
    let seed = 0;
    let bootstrap = 20;
    let secrets = create_secrets(seed, n);
    let ids = create_node_ids(&secrets);
    let config = Config::default()
        .self_lookup_strategy(SelfLookupStrategy {
            interval: Duration::from_secs(1),
        })
        .random_lookup_strategy(RandomLookupStrategy {
            interval: Duration::from_secs(1),
        });
    let nodes = create_nodes(&ids, bootstrap, config).await;
    for i in 0..20 {
        println!("\nAfter {i}s");
        plot_random_lookup_stats(&nodes, 100).await.ok();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
