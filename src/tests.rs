use std::{
    num::NonZeroU64,
    sync::{Arc, Mutex},
};

use rand::{Rng, rngs::StdRng, seq::SliceRandom};
use textplots::{Chart, Plot, Shape};

use super::*;
use crate::proto::Blake3Immutable;

#[derive(Debug, Clone)]
struct TestPool {
    clients: Arc<Mutex<BTreeMap<Id, RpcClient>>>,
    id: Id,
}

impl ClientPool for TestPool {
    async fn with_client<F, Fut, R, E>(&self, id: Id, f: F) -> Result<R, E>
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
                message: "client not found",
            }))?;
        f(client).await
    }

    fn id(&self) -> Id {
        self.id
    }
}

fn expected_ids(ids: &[Id], key: Id, n: usize) -> Vec<Id> {
    let mut expected = ids
        .iter()
        .cloned()
        .map(|id| (Distance::between(&id, &key), id))
        .collect::<Vec<_>>();
    expected.sort();
    expected.truncate(n);
    expected.into_iter().map(|(_, id)| id).collect()
}

type Nodes = Vec<(Id, (RpcClient, ApiClient))>;

fn rng(seed: u64) -> StdRng {
    let mut expanded = [0; 32];
    expanded[..8].copy_from_slice(&seed.to_le_bytes());
    StdRng::from_seed(expanded)
}

fn create_ids(seed: u64, n: usize) -> Vec<Id> {
    let mut rng = rng(seed);
    (0..n).map(|_| Id::from(rng.r#gen::<[u8; 32]>())).collect()
}

/// Creates n nodes with the given seed, and at most n_bootstrap bootstrap nodes.
///
/// Bootstrap nodes are just the n_bootstrap next nodes in the ring.
async fn create_nodes(ids: &[Id], mut n_bootstrap: usize, buckets: Option<Box<Buckets>>) -> Nodes {
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
                id: *id,
            };
            let bootstrap = (0..n_bootstrap)
                .map(|i| ids[(offfset + i + 1) % n])
                .collect::<Vec<_>>();
            (*id, create_node_impl(*id, pool, bootstrap, buckets.clone()))
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
async fn init_routing_tables(nodes: &Nodes, ids: &[Id], seed: Option<u64>) -> irpc::Result<()> {
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
                api.lookup(key, None, Some(NonZeroU64::new(20).unwrap()))
                    .await
                    .ok();
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

/// Create routing table buckets for the given ids.
///
/// Note that if there are a lot of ids, they won't all fit.
#[allow(dead_code)]
fn create_buckets(ids: &[Id]) -> Box<Buckets> {
    let mut routing_table = RoutingTable::new(Id::from([0; 32]), None);
    for id in ids {
        routing_table.add_node(NodeInfo {
            id: *id,
            last_seen: now(),
        });
    }
    routing_table.buckets
}

#[tokio::test]
async fn no_routing() {
    let n = 1000;
    let seed = 0;
    let bootstrap = 0;
    let ids = create_ids(seed, n);
    let nodes = create_nodes(&ids, bootstrap, None).await;
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

#[tokio::test]
async fn perfect_routing_tables_1k() {
    let n = 1000;
    let seed = 0;
    let bootstrap = 0;
    let ids = create_ids(seed, n);
    let nodes = create_nodes(&ids, bootstrap, None).await;
    init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    store_random_values(&nodes, 100).await.ok();
}

#[tokio::test]
async fn perfect_routing_tables_10k() {
    let n = 10000;
    let seed = 0;
    let bootstrap = 0;
    let ids = create_ids(seed, n);
    let nodes = create_nodes(&ids, bootstrap, None).await;

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
    let ids = create_ids(seed, n);
    let nodes = create_nodes(&ids, bootstrap, None).await;

    println!("init routing tables");
    init_routing_tables(&nodes, &ids, Some(seed)).await.ok();

    println!("store random values");
    store_random_values(&nodes, 100).await.ok();
}

#[tokio::test]
async fn just_bootstrap_1k() {
    let n = 1000;
    let seed = 0;
    let bootstrap = 20;
    let ids = create_ids(seed, n);
    let nodes = create_nodes(&ids, bootstrap, None).await;

    // tell all nodes about all ids, shuffled for each node
    // init_routing_tables(&nodes, &ids, Some(seed)).await.ok();
    store_random_values(&nodes, 100).await.ok();
}

async fn random_lookup_test(n: usize, seed: u64, lookups: usize) {
    // bootstrap must be set so the random lookups have a chance to work!
    let bootstrap = 20;
    let ids = create_ids(seed, n);
    let nodes = create_nodes(&ids, bootstrap, None).await;

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
