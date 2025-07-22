<h1 align="center">Depermissioning Web3: a Permissionless Accountable RPC Protocol for Blockchain Networks</h1>

## About this Repository

This repository contains a prototype implementation of our paper, [Depermissioning Web3: a **P**ermissionless **A**ccountable **R**PC **P**rotocol for Blockchain Networks](https://www.arxiv.org/abs/2506.03940), accepted to [ICDCS'25](https://icdcs2025.icdcs.org/). You can access [my presentation slides here](https://github.com/podiumdesu/parp-dev/blob/main/parp-icdcs-slides.pdf).

Some implementation details are simplified, however, the core components necessary to evaluate the **feasibility** and **efficiency** of the protocol are included.

## Why this exists

The internet kind of sucks these days. It is flooded with ads, riddled with privacy leaks, and built on endless tracking and fingerprinting. Web3 (once a popular buzzword) claimed to offer a more decentralized alternative. Sounds promising, right?

On the user side, web3 tries to remove the middlemen. But is that really happening? Are we switching to decentralized services or are we switching to new middlemen with different names and shinier marketing?

In our paper, we focus on one layer of the Web3 stack that often goes unnoticed, the **serving layer**, where users actually get their data. Most blockchain users today don't talk to the network directly. They rely on RPC endpoints (node providers) run by centralized services, like Infura and Alchemy (see the figure below). They often require you to hand over your name, email address, and credit card just to query a public blockchain. They have become the new middlemen guarding blockchain data. That doesn't sound very decentralized to me.

![Current web3 infrastructure](./assets/web3-ps2.jpg)

We have robust protocols to compensate miners and validators, but what about the RPC endpoints that serve data to users?

This repository is a prototype of **PARP**, a protocol enabling **permissionless** and **accountable** access to blockchain RPC, with fair monetary compensation. More technical details can be found in the [paper](https://www.arxiv.org/abs/2506.03940). It is not a finished solution 🤔, but a starting point, something to get people thinking, discussing, and building! 🎉

## Directory Structure

Below are the most relevant directories and files.

```text
.
├── contracts/               # Solidity smart contracts (deposit, payment channels, fraud proofs)
├── dependencies/            # External dependencies and modified clients
│   ├── geth-parp/             # Geth client with PARP modifications
│   │   └── parp/                # PARP-specific logic
│   ├── go-ethereum/           # Unmodified Geth client (v1.13.12)
│   └── prysm/                 # Prysm client (v4.2.1)
├── poc-client/              # Prototype light client written in Go
├── *.sh                     # Shell scripts to build and launch the network
├── genesis.json             # Genesis file with pre-funded accounts
└── README.md                # This file

```

## Overview

The prototype sets up a local Ethereum test network with two standard Geth nodes and one PARP-compatible Geth node.

A light client connects to the PARP-compatible Geth node, sets up a payment channel, and then sends several requests.

Below are the step-by-step instructions for running a PARP node, connecting to it, using and closing the service, and submitting a fraud proof.

## Prerequisites

First clone this repository:

```
git clone git@github.com:podiumdesu/parp-dev.git

cd parp-dev
```

Before setting up the test network, ensure the following dependencies are installed:

- Go (v 1.20)
- JQ
- Bazel

For more details about setting up the local test network, follow this GitHub repository, [rzmahmood/ethereum-pos-testnet](https://github.com/rzmahmood/ethereum-pos-testnet/tree/0ec8c8f1b409fbca26cf58c1e40b9252d99c04b4).

## Network Setup

1. Build all submodules for **a network with unmodified nodes** (Geth v1.13.12 and Prysm v4.2.1).

   ```bash
   ./build-dependencies.sh
   ```

2. Start the testnet with unmodified nodes

   ```bash
   ./testnet.sh
   ```

3. Build all submodules for **PARP-compatible** Geth nodes.

   ```bash
   ./build-dependencies-parp.sh
   ```

4. Run a PARP full node (in three separate terminal tabs)

   ```bash
   ./parp.sh

   ./parp-pry.sh

   ./parp-pryv.sh
   ```

After Step 4, the PARP node will be up and connected to the rest of the network. The relevant ports are defined in the respective bash scripts. Moreover, the PARP node will expose a WebSocket service on port `8888` for handling PARP requests.

Once the above four steps are done and the network begins generating blocks, a local Ethereum network will be running with two standard Geth nodes and one PARP-compatible Geth node.

In the [`genesis.json`](https://github.com/podiumdesu/parp-dev/blob/main/genesis.json) file, we have pre-allocated tokens to several wallet addresses.

You can use MetaMask to import and manage these addresses (signing transactions, viewing transaction history, and monitoring token balances).

| role           | wallet address                             | private key                                                      |
| -------------- | ------------------------------------------ | ---------------------------------------------------------------- |
| PARP full node | 0xC8A7ae3f6Ae079c20BA19164089143F48F7B965f | bcd5c542c981dbb7cee1f3352fcee082581b4a323bf5cbff105aa84fa718f690 |
| light client   | 0xD25a31702b7b86B2e953Baf9ff88Ef716A5306Cc | f39985d76a9bf831c3a3fe19cfbe7d038ad25b5de2ceffd4a1cf15191808b396 |

### Interacting with the Network via Terminal

To interact with the running Ethereum testnet, open a new terminal tab in the project root and attach to one of the execution nodes:

```bash
geth attach network/node-1/execution/geth.ipc

```

Once connected, you can run the following commands:

```
# Check the current block number
eth.blockNumber

# Retrieve a transaction by its hash
eth.getTransaction("`txHash`")

# Retrieve block info by block number
eth.getBlock(0x3)
```

## Deploying the Smart Contracts

1. Open [Remix IDE](https://remix.ethereum.org/) and upload the `./contracts` folder.
2. Install the MetaMask Chrome extension and import the above wallet addresses using their private keys.
3. In Remix, select **Injected Provider** as the environment to interact with your local network via MetaMask.

### Contract Deployment Steps

1. `Full Nodes Deposit Module`.

Deploy `deposit.sol`. This contract allows full node to deposit funds into the blockchain.

2. `Channels Management Module`

Deploy `paychan.sol`. This is to manage the states of payment channels.

- While deploying, the address of the previously deployed `_depositContract` is needed as a constructor parameter to deploy `paychan.sol`.

3. `Fraud Detection Module`

Finally, deploy `fraudProofDetector.sol`, which handles fraud detection and resolution.

- This contract requires the addresses of both `_paychanContractAddress` and `_depositContract` during deployment.

> ⚠️ !! Important: After deploying `paychan.sol`, copy its address and paste it into the `contractAddress` field in [`./poc-client/localConfig.json`](https://github.com/podiumdesu/parp-dev/blob/main/poc-client/localConfig.json).

## Preparing the PARP Full Node

To be eligible to serve requests as a PARP full node, the full node MUST deposit at least 1 ETH on-chain into the `DepositContract` smart contract. This interaction can be done through Remix IDE.

> ⚠️ !! Important: If this step is skipped, a light client **will not** be able to open a channel with this full node.

## Running the Light Client

Now it's time to run the light client.

```bash
cd poc-client

go run main.go
```

The configuration metadata can be found in `./poc-client/localConfig.json`.

Currently, the client workflow is hard-coded, as shown in [`./poc-client/client/client.go`](https://github.com/podiumdesu/parp-dev/blob/main/poc-client/client/client.go#L35). Once connected, the light client performs the following steps:

1. Handshakes with the server (`ws://127.0.0.1:8888/ws/`) and retrieve the wallet address of the server.
2. Signs an `openChanTx` transaction and sends it to the full node (which forwards it to the network).
3. If the transaction is successfully executed, the light client receives a channel ID from the full node and verifies the response.
4. Signs a `sendTokenTx` transaction to send tokens to another address.
5. (Commented out) Sends an RPC call to check its balance.

The most recent `amount` is stored locally by the light client.

![Terminal output until step 3.](./assets/channelID.gif)

## Closing a Channel

Any party can submit a `closeChan` transaction to the `paychan` smart contract.

In order to claim the funds and close the channel, one needs to submit:

- Payment body bytes
  > e.g.: 0xf866a0a4b84f7d4dfdd3edefef35f2f75f3a966da2dc24232e57e1fd658b01b634ed9581c8b84100393d4e0b8fea6c778fadab0aa895deec3f67096518ed25440a10893ee015a83d732efd7666ba19da5d8ebe5dc226eb3165967c555ee2b10224203fd25390401b

This value is printed in the terminal tab running `./parp.sh`.

## Submitting Fraud Proofs

To submit a valid fraud proof, one needs to provide the following information:

1. Request body bytes
2. Response message bytes
3. Block header bytes
4. Address of a witness node

For ease of use, the first three values are printed in the terminal tab running the light client. You can copy and paste them into the `fraudProofDetector` function of the `fraudProofDecoder` smart contract using Remix.

## Acknowledgement

A huge thanks to all the open-source projects that made this work possible!

1. For the Ethereum test network setup, we relied heavily on [github.com/rzmahmood/ethereum-pos-testnet](https://github.com/rzmahmood/ethereum-pos-testnet), which saved us a lot of time. Thanks!
2. The Merkle tree logic was inspired by [github.com/zhangchiqing/merkle-patricia-trie](https://github.com/zhangchiqing/merkle-patricia-trie). It was a great resource to learn from!
3. For on-chain Merkle proof verification, [polytope-labs/solidity-merkle-trees](https://github.com/polytope-labs/solidity-merkle-trees/tree/main) was very insightful and helpful!
4. ChatGPT helped with debugging along the way. Thanks!

## Contact

If you have any questions about running the implementation, please feel free to reach out to me at [weihong.wang@kuleuven.be](mailto:weihong.wang@kuleuven.be).

I am more than happy to help with the reproduction, and I am always open to suggestions, feedback, or discussion of any kind!
