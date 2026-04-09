//! Complete E2E test proving the payment protocol works on live nodes.
//!
//! **All payment tests in this file previously used `QuantumClient` which has been
//! removed.** Tests will be re-implemented using `ant-client::Client` once
//! the migration is complete.
//!
//! ## Original Test Flow
//!
//! 1. **Network Setup**: Spawn 10 live ant nodes + Anvil EVM testnet
//! 2. **Quote Collection**: Client requests quotes from 5 closest DHT peers
//! 3. **Price Calculation**: Sort quotes by price, select median
//! 4. **Payment**: Make on-chain payment (median node 3x, others 0 atto)
//! 5. **Chunk Storage**: Send chunk + `ProofOfPayment` to network
//! 6. **Verification**: Nodes verify payment on-chain before storing
//! 7. **Retrieval**: Retrieve chunk from storing node to prove storage succeeded
//! 8. **Cross-Node**: Retrieve chunk from a DIFFERENT node (tests replication)
