use criterion::{Criterion, criterion_group, criterion_main};
use dht2::bench_exports::{Id, NodeInfo, RoutingTable};
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
fn create_full_rt(rng: &mut impl Rng) -> dht2::bench_exports::RoutingTable {
    let local_id = random_node_id(rng);
    let mut rt = RoutingTable {
        buckets: Default::default(),
        local_id,
    };
    for i in 0..256 {
        for _j in 0..20 {
            rt.buckets[i].add_node(NodeInfo {
                id: random_node_id(rng),
                last_seen: 0,
            });
        }
    }

    assert_eq!(
        rt.buckets.iter().map(|x| x.nodes().len()).sum::<usize>(),
        256 * 20
    );
    rt
}

fn bench_fib(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_closest_nodes"); // Groups related benchmarks for reporting

    let mut rng = rand::thread_rng();
    let rt = create_full_rt(&mut rng);
    let key = random_key(&mut rng);

    // Benchmark the function for different inputs
    {
        let n = &1;
        group.bench_function(format!("iter_{n}"), |b| {
            b.iter(|| rt.find_closest_nodes(std::hint::black_box(&key), std::hint::black_box(20)));
        });
    }

    group.finish(); // End the group
}

criterion_group!(benches, bench_fib); // Register the benchmark group
criterion_main!(benches); // The main harness function
