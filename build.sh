#!/bin/bash

#cargo build --release --target wasm32-unknown-unknown
filename=.
result=ogq
RUSTFLAGS="-C link-arg=-zstack-size=32768" cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/${result}.wasm  ${result}.wasm
ontio-wasm-build ${result}.wasm ogq-opt.wasm
