# DHT -> blobs browser demo

Single page. Two iroh endpoints run inside one WebAssembly instance. Browser relay WebSockets carry DHT and blob traffic.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129
cargo build --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/debug/iroh_dht_experiment.wasm \
  --out-dir web/wasm --target web --weak-refs
python3 -m http.server 8080 --directory web
```

Open <http://localhost:8080>, click **Run browser demo**.

Demo verifies DHT provider discovery, full blob fetch, and ranged fetch (`1024..2048`).
