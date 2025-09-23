# Core Blockchain Rust 🦀

A complete blockchain implementation in Rust demonstrating core blockchain concepts including transactions, mining, digital signatures, and chain validation.

## 🚀 What We've Built

### ✅ Core Features Implemented

**🔐 Cryptographic Security**
- Ed25519 digital signatures for transaction security
- Public/private key pairs for user identities
- Secure transaction signing and verification functions

**💰 Transaction System**
- **Coinbase Transactions**: Mining rewards for creating new coins
- **Transfer Transactions**: Person-to-person payments with digital signatures
- Proper signature validation for transfer transactions

**⛏️ Mining & Proof-of-Work**
- SHA256 hashing for block creation
- Configurable mining difficulty (find nonce where hash starts with N zeros)
- Genesis block creation (no mining required) vs regular blocks (mining required)

**🔗 Blockchain Structure**
- Immutable chain via cryptographic hash linking (`prev_hash` → `current_hash`)
- Timestamp validation ensuring blocks are created sequentially
- Block validation with hash integrity checks

**✅ Validation System**
- Individual block validation (hash matches computed hash)
- Chain integrity validation (prev_hash links are valid)
- Orphan block detection
- Timestamp ordering verification

## 🏗️ Architecture

### Key Components

1. **Transaction Types**:
   ```rust
   enum Transaction {
       Coinbase { to: String, amount: u64 },        // Mining rewards
       Transfer { from: String, to: String, amount: u64, signature: Vec<u8> }
   }
   ```

2. **Block Structure**:
   ```rust
   struct Block {
       prev_hash: [u8; 32],     // Links to previous block
       timestamp: u64,          // Block creation time
       data: Vec<Transaction>,  // Transaction data
       nonce: u64,              // Mining solution
       hash: [u8; 32],          // Block hash
   }
   ```

3. **Blockchain**:
   ```rust
   struct Blockchain {
       blocks: Vec<Block>,      // Chain of blocks
   }
   ```

### Security Features

- **Digital Signatures**: Transactions are cryptographically signed
- **Hash Chains**: Blocks are immutably linked via hashes
- **Proof-of-Work**: Mining prevents spam and ensures chain security
- **Validation**: Multiple layers of integrity checking

## 🚀 Running the Project

### Prerequisites
- Rust (latest stable version)
- Cargo package manager

### Dependencies
```toml
[dependencies]
bincode = "1.3.3"        # Serialization
ring = "0.17.14"         # Cryptography
serde = { version = "1.0.226", features = ["derive"] }
sha2 = "0.10.9"          # Hashing
thiserror = "2.0.16"     # Error handling
```

### How to Run
```bash
# Clone and navigate to the project
cd core-blockchain-rust

# Build the project
cargo build

# Run the blockchain demo
cargo run
```

### Example Output
```
Initial chain valid? Ok(())
Added block! Len: 2
Chain valid? Ok(())
Last block txs: [Transfer { from: "sender", to: "receiver", amount: 10, signature: [...] }]
Last block in Chain: Some(Block { prev_hash: [...], timestamp: 1758630008, data: [...], nonce: 170, hash: [0, 41, ...] })
```

## 🔑 Key Concepts Demonstrated

### 1. Digital Signatures
- **Private Key**: Used to sign transactions (keep secret!)
- **Public Key**: Used to verify signatures (share publicly)
- **Signature**: Cryptographic proof of transaction authenticity

### 2. Hash Chains
- **Genesis Block**: `prev_hash = [0; 32]` (first block)
- **Regular Blocks**: `prev_hash = previous_block.hash`
- **Immutability**: Changing one block breaks all subsequent links

### 3. Proof-of-Work Mining
- Find `nonce` where `SHA256(prev_hash + timestamp + data + nonce)` starts with N zeros
- Difficulty controls how hard it is to mine blocks
- Prevents spam and ensures fair block creation

### 4. Transaction Validation
- Coinbase transactions: Always valid (mining rewards)
- Transfer transactions: Must have valid signature from sender

## 🧪 Current Status

✅ **Working Features**:
- Complete blockchain with mining
- Digital signature system
- Transaction types (coinbase + transfer)
- Block and chain validation
- Genesis block creation
- Configurable mining difficulty

⚠️ **Known Warnings** (non-blocking):
- Some unused imports and variables (can be cleaned up)
- `verify_tx` function defined but not used in main demo

## 🔮 Future Enhancements

- [ ] **Network Layer**: Peer-to-peer communication
- [ ] **UTXO Model**: Unspent Transaction Outputs
- [ ] **Merkle Trees**: Efficient transaction verification
- [ ] **Consensus**: Multiple miners, longest chain rule
- [ ] **Wallet System**: Address generation, balance tracking
- [ ] **Smart Contracts**: Programmable transactions
- [ ] **Token Standards**: ERC-20 style tokens

## 📚 Learning Outcomes

This project demonstrates fundamental blockchain concepts:
- **Cryptography**: Public-key cryptography and digital signatures
- **Distributed Systems**: Chain validation and consensus
- **Data Structures**: Hash-linked immutable chains
- **Proof-of-Work**: Mining and difficulty adjustment
- **Security**: Transaction integrity and chain immutability

## 🤝 Contributing

This is a learning project showcasing core blockchain principles in Rust. Feel free to:
- Add new features
- Improve code quality
- Add comprehensive tests
- Create documentation

---

**Built with ❤️ in Rust** - A journey from zero to blockchain! 🚀
