use criterion::{Criterion, criterion_group, criterion_main};
use iroh_dht_experiment::bench_exports::{self, Id, RoutingTable};
use rand::Rng;

fn random_node_id(rng: &mut impl Rng) -> iroh::PublicKey {
    loop {
        if let Ok(key) = iroh::PublicKey::from_bytes(&rng.r#gen()) {
            return key;
        }
    }
}

fn random_key(rng: &mut impl Rng) -> Id {
    Id::from(rng.r#gen::<[u8; 32]>())
}

/// Create a full routing table with 256 buckets, each containing 20 nodes.
///
/// This is not a correct routing table, since we don't take the level into account.
/// But it will do for bechnarking find_node, since find_node does a full scan anyway.
fn create_full_rt(rng: &mut impl Rng) -> bench_exports::RoutingTable {
    let local_id = random_node_id(rng);
    let mut rt = RoutingTable {
        buckets: Default::default(),
        local_id,
    };
    for i in 0..256 {
        for _j in 0..20 {
            rt.buckets[i].add_node(random_node_id(rng));
        }
    }

    assert_eq!(rt.nodes().count(), 256 * 20);
    rt
}

/// Create a more realistic routing table with 256 buckets, where you just give it n nodes
/// to remember (it won't remember all of them since buckets will fill up!).
fn create_realistic_rt(rng: &mut impl Rng, n: usize) -> bench_exports::RoutingTable {
    let local_id = random_node_id(rng);
    let mut rt = RoutingTable {
        buckets: Default::default(),
        local_id,
    };
    for _i in 0..n {
        rt.add_node(random_node_id(rng));
    }
    rt
}

fn bench_rt(c: &mut Criterion) {
    let mut group = c.benchmark_group("RoutingTable::find_closest_nodes"); // Groups related benchmarks for reporting

    let mut rng = rand::thread_rng();
    let full_rt = create_full_rt(&mut rng);
    let key = random_key(&mut rng);

    // Benchmark for a routing table where every single k-bucket is full. This is the worst case, but will only happen with absolutely
    // gigantic networks.
    group.bench_function("full".to_string(), |b| {
        b.iter(|| full_rt.find_closest_nodes(std::hint::black_box(&key), std::hint::black_box(20)));
    });

    // Benchmark for more realistic routing tables with varying sizes. The buckets near the local node will rarely be full.
    for n in [10000, 100000, 1000000] {
        let rt = create_realistic_rt(&mut rng, n);
        let size = rt.nodes().count();
        group.bench_function(format!("realistic {n}/{size}"), |b| {
            b.iter(|| rt.find_closest_nodes(std::hint::black_box(&key), std::hint::black_box(20)));
        });
    }

    group.finish(); // End the group
}

criterion_group!(benches, bench_rt); // Register the benchmark group
criterion_main!(benches); // The main harness function
