use futures::future::join_all;
use iroh::{
    Endpoint, SecretKey, address_lookup::memory::MemoryLookup, endpoint::presets::Minimal,
    protocol::Router,
};
use iroh_blobs::{
    BlobsProtocol,
    protocol::{ChunkRanges, ChunkRangesExt, GetRequest},
    store::mem::MemStore,
};
use irpc_iroh::IrohProtocol;
use std::{cell::RefCell, time::Duration};
use wasm_bindgen::prelude::*;

use crate::{ApiClient, create_node_impl, pool::IrohPool};

const DHT_TEST_ALPN: &[u8] = crate::rpc::ALPN;
thread_local! {
    static LOGGER: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

fn log(message: impl AsRef<str>) {
    let message = message.as_ref();
    web_sys::console::log_1(&JsValue::from_str(message));
    let callback = LOGGER.with(|logger| logger.borrow().clone());
    if let Some(callback) = callback {
        let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(message));
    }
}

struct DemoNode {
    endpoint: Endpoint,
    api: ApiClient,
    store: MemStore,
    _router: Router,
}

async fn make_node(
    secret: SecretKey,
    bootstrap: Vec<iroh::EndpointId>,
    discovery: MemoryLookup,
) -> Result<DemoNode, JsValue> {
    log(format!("creating endpoint for {}", secret.public()));
    let relay = "https://use1-1.relay.n0.iroh.link"
        .parse::<iroh::RelayUrl>()
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    // Browser demo has all endpoint addresses in shared memory; avoid N0's
    // DNS/Pkarr discovery, which adds slow and failure-prone network requests.
    let endpoint = Endpoint::builder(Minimal)
        .secret_key(secret)
        .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter([
            relay.clone()
        ])))
        .address_lookup(discovery.clone())
        .bind()
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    // Publish the relay-backed address only after the endpoint has contacted
    // the relay; the pre-online address may contain no usable relay address.
    n0_future::time::timeout(Duration::from_secs(30), endpoint.online())
        .await
        .map_err(|_| JsValue::from_str("relay connection timed out"))?;
    discovery.add_endpoint_info(endpoint.addr().with_relay_url(relay));
    log(format!(
        "endpoint {} online and address published",
        endpoint.id()
    ));

    let pool = iroh_blobs::util::connection_pool::ConnectionPool::new(
        endpoint.clone(),
        DHT_TEST_ALPN,
        Default::default(),
    );
    let pool = IrohPool::new(endpoint.clone(), pool, discovery);
    let (rpc, api) = create_node_impl(
        endpoint.id(),
        pool.clone(),
        bootstrap,
        None,
        Default::default(),
    );
    pool.set_self_client(Some(rpc.downgrade()));

    let store = MemStore::new();
    let router = Router::builder(endpoint.clone())
        .accept(
            DHT_TEST_ALPN,
            IrohProtocol::with_sender(rpc.0.as_local().unwrap()),
        )
        .accept(iroh_blobs::ALPN, BlobsProtocol::new(&store, None))
        .spawn();
    log(format!("endpoint {} router ready", endpoint.id()));
    Ok(DemoNode {
        endpoint,
        api,
        store,
        _router: router,
    })
}

async fn wait_online(endpoint: &Endpoint) {
    let _ = n0_future::time::timeout(Duration::from_secs(10), endpoint.online()).await;
}

#[wasm_bindgen]
pub async fn run_demo(log_callback: js_sys::Function) -> Result<JsValue, JsValue> {
    console_error_panic_hook::set_once();
    LOGGER.with(|logger| *logger.borrow_mut() = Some(log_callback));
    log("demo start: creating 16 endpoints");
    let discovery = MemoryLookup::new();
    let first_secret = SecretKey::from_bytes(&[1; 32]);
    let second_secret = SecretKey::from_bytes(&[2; 32]);
    let first_id = first_secret.public();
    let second_id = second_secret.public();
    let first = make_node(second_secret, vec![first_id], discovery.clone()).await?;
    let second = make_node(first_secret, vec![second_id], discovery.clone()).await?;
    join_all([wait_online(&first.endpoint), wait_online(&second.endpoint)]).await;
    let bootstrap_ids = vec![first.endpoint.id(), second.endpoint.id()];
    // Keep all 16 endpoints in the browser DHT exercise.
    let extra_results = join_all((3u8..=16).map(|seed| {
        let discovery = discovery.clone();
        let bootstrap_ids = bootstrap_ids.clone();
        async move {
            let secret = SecretKey::from_bytes(&[seed; 32]);
            make_node(secret, bootstrap_ids, discovery).await
        }
    }))
    .await;
    let mut extra = Vec::new();
    for result in extra_results {
        extra.push(result?);
    }
    join_all(extra.iter().map(|node| wait_online(&node.endpoint))).await;
    log("all endpoints online; populating routing tables");
    let ids = std::iter::once(first.endpoint.id())
        .chain(std::iter::once(second.endpoint.id()))
        .chain(extra.iter().map(|node| node.endpoint.id()))
        .collect::<Vec<_>>();
    join_all([first.api.nodes_seen(&ids), second.api.nodes_seen(&ids)])
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    join_all(extra.iter().map(|node| node.api.nodes_seen(&ids)))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    log(format!(
        "routing tables populated with {} node IDs",
        ids.len()
    ));

    let data: Vec<u8> = (0..2048).map(|index| (index % 251) as u8).collect();
    let tag = first
        .store
        .add_slice(&data)
        .temp_tag()
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let blob_hash = tag.hash();
    let dht_hash = blake3::Hash::from_bytes(*blob_hash.as_bytes());
    log(format!("blob created: {blob_hash}"));
    for (index, node) in extra.iter_mut().enumerate() {
        if index < 6 {
            continue;
        }
        let mut tag = node
            .store
            .add_slice(&data)
            .temp_tag()
            .await
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        tag.leak();
    }
    let provider_ids = std::iter::once(first.endpoint.id())
        .chain(
            extra
                .iter()
                .enumerate()
                .filter(|(index, _)| *index >= 6)
                .map(|(_, node)| node.endpoint.id()),
        )
        .collect::<Vec<_>>();
    let mut replication = first
        .api
        .publish_providers(dht_hash, &provider_ids)
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let stored = replication
        .recv()
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    log("provider replication started");
    if stored.is_none() {
        return Err(JsValue::from_str("DHT stored no provider"));
    }
    let mut providers = second
        .api
        .get_providers(dht_hash)
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    providers.sort();
    providers.dedup();
    log(format!("decoded {} unique providers", providers.len()));
    let provider_count = providers.len();

    let full = second.store.downloader(&second.endpoint);
    full.download(GetRequest::blob(blob_hash), providers.clone())
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    log("full blob download complete");
    let fetched = second
        .store
        .blobs()
        .get_bytes(blob_hash)
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    if fetched.as_ref() != data.as_slice() {
        return Err(JsValue::from_str("full blob verification failed"));
    }

    let ranged_store = MemStore::new();
    let ranged = ranged_store.downloader(&second.endpoint);
    ranged
        .download(
            GetRequest::builder()
                .root(ChunkRanges::bytes(1024..2048))
                .build(blob_hash),
            providers,
        )
        .await
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    log("ranged blob download complete");

    Ok(JsValue::from_str(&format!(
        "providers published: {}\nproviders returned: {}\nprovider: {}\nfull blob: {} bytes\nranged blob: verified bytes 1024..2048",
        provider_ids.len(),
        provider_count,
        first.endpoint.id(),
        fetched.len(),
    )))
}
