# Kalypso-Symbiotic Data Bridge

Kalypso-Symbiotic Data Bridge is an integral part of the Kalypso ecosystem used to request proofs from hardware operators via a marketplace composed of smart contracts. The Data bridge is used to transfer the stakes and slash data of the operators and jobs from the main L1 chain symbiotic contracts to the L2 chain Kalypso contracts. It is meant to run inside on-chain verified (Oyster-verification protocol) enclave ensuring that any message signed by it will be treated as truth and smart contracts can execute based on that signed message. The transmitter entity is responsible for spawning the data bridge enclave, retrieving signed stakes/slash data from the enclave and submitting it on L2 chain. Core data bridge application is built using Rust, Actix web framework and ethers library whereas Docker, supervisord and shell is used to generate the enclave docker image.   

## Tools and setup required for building bridge locally 

<b> Install the following packages : </b>

* build-essential 
* libc++1
* libssl-dev
* musl-tools
* make
* pkg-config

<b> Signer file setup</b>

A signer secret is required to run the data bridge applicaton. It'll also be the identity of the bridge enclave on chain i.e, the enclave address will be derived from the corresponding public key. The signer must be a `secp256k1` binary secret.
The <a href="https://github.com/marlinprotocol/keygen">Keygen repo</a> can be used to generate this.

<b> RPC and smart contracts configuration</b>

To run the data bridge, details related to RPC like the HTTP URLs, Chain ID and relevant smart contract addresses will be needed through which the bridge will communicate with the L1 chain.

<b> Build the bridge binary </b>

Default build target is `x86_64-unknown-linux-musl`. Can be changed in the `.cargo/config.toml` file or in the build command itself. Add the required build target first like: 
```
rustup target add x86_64-unknown-linux-musl
```
Build the binary executable: 
```
cargo build --release
```
OR (for custom targets)
```
cargo build --release --target aarch64-unknown-linux-musl
```

## Running data bridge application

<b> Run the data bridge application :</b>

```
./target/x86_64-unknown-linux-musl/release/kalypso-symbiotic-data-bridge --help
Usage: kalypso-symbiotic-data-bridge [OPTIONS]

Options:
      --port <PORT>                [default: 6005]
        Server port
      --config-file <CONFIG_FILE>  [default: ./kalypso_symbiotic_data_bridge_config.json]
        Path to the bridge configuration parameters file
  -h, --help                       Print help
  -V, --version                    Print version
```
Configuration file parameters required for running a bridge node:
```
{
    "chain_id": // L1 chain ID,
    "kalypso_subnetwork": // Kalypso subnetwork ID on the L1 chain
    "http_rpc_urls": // Http urls of the RPC endpoints (Default 3 are added:- Public Url, Infura Url, Alchemy Url)
    "kalypso_middleware_addr": // KalypsoMiddleware smart contract address on the L1 chain,
    "enclave_signer_file": // path to enclave secp256k1 private key file,
}
``` 
Example command to run the bridge locally:
```
sudo ./target/x86_64-unknown-linux-musl/release/kalypso-symbiotic-data-bridge --port 6005 --config-file ./kalypso_symbiotic_data_bridge_config.json
```

<b> Exporting stakes data from the bridge node: </b>

The transmitter can hit the below endpoint to get the stakes details required to submit on the L2 'SymbioticStaking' contract. The endpoint will fetch the data from the block number mentioned in the request or the latest block if nothing provided.
```
$ curl -X POST -H "Content-Type: application/json" -d '{"rpc_api_keys": ["", "{INFURA_API_KEY}", "{ALCHEMY_API_KEY}"], "no_of_txs": 3}' http://localhost:6005/sign-stake-data
{"capture_timestamp":1732782432,"no_of_txs":3,"signed_data":[{"data":"0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c6de583b87716e351e4fb60d687b9330877dbaf4000000000000000000000000470696186e679b46632ef9702f077d6848bf1bd10000000000000000000000005e478cb7576906fe2a443684adcd9a0dfc547abd000000000000000000000000000000000000000000000549a05c8f45201f69c8000000000000000000000000c9ea0136436db9a68e719766501a3531ec14f382000000000000000000000000470696186e679b46632ef9702f077d6848bf1bd10000000000000000000000005e478cb7576906fe2a443684adcd9a0dfc547abd000000000000000000000000000000000000000000000549a05c8f45201f69c8","signature":"0xe8d5285e251ad149cf375013d94ad3b7fe9af7276789773c92aa04939d47c7356814ff94c52b4676a4beb8f09ce431616c9da7a1a4edb4d342f1751363fdf4911b"},{"data":"0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000edcf251b8c777e8fb5a1887e7841fbcecce2a6bd000000000000000000000000470696186e679b46632ef9702f077d6848bf1bd10000000000000000000000005e478cb7576906fe2a443684adcd9a0dfc547abd0000000000000000000000000000000000000000000000000000000000000000","signature":"0x267037c9fe860f8fe26ef5104556c236ea667499586f9ed35a8dbbb19850b20b4f44038e079671443fb6aa3fa38112f41ca11d8d31ca5f073816a09d1a206b5f1c"},{"data":"0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000005ed0f82f5a12b2fc91b639b05ea394b66e060989000000000000000000000000470696186e679b46632ef9702f077d6848bf1bd10000000000000000000000005e478cb7576906fe2a443684adcd9a0dfc547abd00000000000000000000000000000000000000000000032c2d0455f646793f78","signature":"0xf0d960981df41c42ceb180281e3837eac7d025b57a836f65f959a9480da15ee43c3b7185a202d864e47b898fd9998bc448fbb457bf9c389d927f88eba39432ce1c"}]}
```

```
$ curl -X POST -H "Content-Type: application/json" -d '{"rpc_api_keys": ["", "{INFURA_API_KEY}", "{ALCHEMY_API_KEY}"], "no_of_txs": 1, "block_number": 2598500}' http://localhost:6005/sign-stake-data
{"capture_timestamp":1729777812,"no_of_txs":1,"signed_data":[{"data":"0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000c9ea0136436db9a68e719766501a3531ec14f382000000000000000000000000470696186e679b46632ef9702f077d6848bf1bd10000000000000000000000005e478cb7576906fe2a443684adcd9a0dfc547abd0000000000000000000000000000000000000000000000000000000000000000","signature":"0x6bed5eca38633bb433a11f1080b959c5ae3526eeec15d0a2a8e48707b9cb713a0a7c9b03fb9f7f33fb9c247eaed1a73b08361447fee06e463da2cd5993e020c61b"}]}
```

<b> Exporting slash data from the bridge node: </b>

The transmitter can hit the below endpoint to get the slash details required to submit on the L2 'SymbioticStaking' contract. The endpoint will fetch the data from the block number mentioned in the request or the latest block if nothing provided.
```
$ curl -X POST -H "Content-Type: application/json" -d '{"rpc_api_keys": ["", "{INFURA_API_KEY}", "{ALCHEMY_API_KEY}"], "no_of_txs": 1, "from_block_number": 2598500}' http://localhost:6005/sign-slash-data
{"capture_timestamp":1732782828,"no_of_txs":1,"signed_data":[{"data":"0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000","signature":"0x531c288b2630e0e2f581879999f41e29e5f95909bcbd12cad5bbb80d2c9551824794fdc97b1f243731b386891628eb6906280146b19224b399ed889dbcd6ad451c"}]}
```

