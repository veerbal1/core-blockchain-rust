use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type THash = [u8; 32];
type TTimestamp = u64;
type TData = Vec<Transaction>;
type TNonce = u64;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Transaction {
    Coinbase {
        to: String,
        amount: u64,
    },
    Transfer {
        from: String,
        to: String,
        amount: u64,
        signature: Vec<u8>,
    },
}

fn sign_tx(tx: &Transaction, keypair: &Ed25519KeyPair) -> Vec<u8> {
    // Create a transaction without signature for signing
    let tx_for_signing = match tx {
        Transaction::Coinbase { to, amount } => {
            // Coinbase transactions don't need signing
            Transaction::Coinbase {
                to: to.clone(),
                amount: *amount,
            }
        }
        Transaction::Transfer {
            from, to, amount, ..
        } => {
            // Sign only the core data: from, to, amount
            // Exclude the signature field to avoid circular dependency
            Transaction::Transfer {
                from: from.clone(),
                to: to.clone(),
                amount: *amount,
                signature: Vec::new(), // Empty signature for signing
            }
        }
    };

    let tx_bytes = bincode::serialize(&tx_for_signing).unwrap();
    let sig = keypair.sign(&tx_bytes);
    sig.as_ref().to_vec()
}

pub fn verify_tx(tx: &Transaction, pub_key: &[u8; 32]) -> bool {
    match tx {
        Transaction::Coinbase { .. } => true, // Coinbase doesn't need verification
        Transaction::Transfer {
            from,
            to,
            amount,
            signature,
        } => {
            // Recreate the transaction data as it was signed (without signature)
            let tx_for_verification = Transaction::Transfer {
                from: from.clone(),
                to: to.clone(),
                amount: *amount,
                signature: Vec::new(),
            };

            // Serialize to bytes (same as during signing)
            let tx_bytes = bincode::serialize(&tx_for_verification).unwrap();

            // Verify the signature using the public key
            let public_key =
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pub_key);
            public_key.verify(&tx_bytes, signature).is_ok()
        }
    }
}

fn hash_block(block: &mut Block) {
    let mut hasher = Sha256::new();

    // Fields ko bytes mai serialize
    hasher.update(&block.prev_hash);
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(bincode::serialize(&block.data).unwrap());
    hasher.update(&block.nonce.to_le_bytes());

    let result = hasher.finalize();
    block.hash = result.into();
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Block {
    prev_hash: THash,      // Previous Block Hash
    timestamp: TTimestamp, // Current time in seconds.
    data: TData,           // Transaction's raw data
    nonce: TNonce,         // Puzzle solution for mining
    hash: THash,           // Apna calculated hash.
}

#[derive(Debug, Serialize, Deserialize)]
struct Blockchain {
    blocks: Vec<Block>,
}

impl Blockchain {
    fn new() -> Self {
        let mut chain = Blockchain { blocks: Vec::new() };
        let genesis_data = Transaction::Coinbase {
            to: "genesis_miner".to_string(),
            amount: 100,
        };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut genesis_block = Block {
            prev_hash: [0u8; 32],
            timestamp,
            data: vec![genesis_data],
            nonce: 0,
            hash: [0u8; 32],
        };

        hash_block(&mut genesis_block);
        chain.blocks.push(genesis_block);

        chain
    }
}

// BlockError enum: Validation ke liye custom errors.
#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Block is an orphan: prev_hash doesn't match previous block")]
    OrphanBlock,
    #[error("Invalid hash: doesn't match computed body hash")]
    InvalidHash,
    #[error("Invalid timestamp: must be after previous")]
    InvalidTimestamp,
}

// Helper: Result type alias for clean code.
pub type Result<T> = std::result::Result<T, BlockError>;

pub trait Mineable {
    fn mine(&mut self, difficulty: u32) -> Result<()>;
}

impl Mineable for Block {
    fn mine(&mut self, difficulty: u32) -> Result<()> {
        if difficulty == 0 || difficulty > 4 {
            return Err(BlockError::InvalidHash);
        }

        let mut nonce = 0u64;

        loop {
            self.nonce = nonce;
            hash_block(self);

            let mut is_valid = true;
            for i in 0..difficulty as usize {
                if self.hash[i] != 0 {
                    is_valid = false;
                    break;
                }
            }
            if is_valid {
                return Ok(());
            }

            nonce += 1;

            if nonce > 1_000_000 {
                return Err(BlockError::InvalidHash);
            }
        }
    }
}

impl Block {
    fn validate(&self) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(&self.prev_hash);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(bincode::serialize(&self.data).unwrap());
        hasher.update(&self.nonce.to_le_bytes());

        let computed: THash = hasher.finalize().into();
        if computed != self.hash {
            return Err(BlockError::InvalidHash);
        }
        Ok(())
    }
}

impl Blockchain {
    fn validate(&self) -> Result<()> {
        if self.blocks.is_empty() {
            return Ok(()); // Empty chain ok.
        }

        // Genesis check.
        if self.blocks[0].prev_hash != [0u8; 32] {
            return Err(BlockError::OrphanBlock);
        }
        self.blocks[0].validate()?;

        // Baaki blocks: Prev hash, timestamp, self-validate.
        for i in 1..self.blocks.len() {
            let block = &self.blocks[i];
            if block.prev_hash != self.blocks[i - 1].hash {
                return Err(BlockError::OrphanBlock);
            }
            if block.timestamp <= self.blocks[i - 1].timestamp {
                return Err(BlockError::InvalidTimestamp);
            }
            block.validate()?;
        }
        Ok(())
    }

    fn add_block(&mut self, data: TData, difficulty: u32) -> Result<()> {
        if self.blocks.is_empty() {
            return Err(BlockError::OrphanBlock); // No genesis, can't add.
        }

        let last_hash = self.blocks.last().unwrap().hash;
        let mut timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Ensure timestamp is after previous block
        let prev_timestamp = self.blocks.last().unwrap().timestamp;
        if timestamp <= prev_timestamp {
            timestamp = prev_timestamp + 1;
        }

        let mut new_block = Block {
            prev_hash: last_hash,
            timestamp,
            data,
            nonce: 0,
            hash: [0u8; 32],
        };

        // Mine AFTER setting the correct timestamp
        new_block.mine(difficulty).unwrap();

        self.blocks.push(new_block);

        self.validate().unwrap();
        Ok(())
    }
}

fn main() {
    let mut chain = Blockchain::new();
    println!("Initial chain valid? {:?}", chain.validate());

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    // let pk: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();

    let transfer_data = Transaction::Transfer {
        from: "sender".to_string(),
        to: "receiver".to_string(),
        amount: 10,
        signature: Vec::new(),
    };
    let signature = sign_tx(&transfer_data, &keypair);
    let transfer = Transaction::Transfer {
        from: "sender".to_string(),
        to: "receiver".to_string(),
        amount: 10,
        signature,
    };

    // Add block with tx.
    if let Err(e) = chain.add_block(vec![transfer], 1) {
        println!("Add failed: {}", e);
    } else {
        println!("Added block! Len: {}", chain.blocks.len()); // Should 2.
        println!("Chain valid? {:?}", chain.validate());
        println!("Last block txs: {:?}", chain.blocks[1].data);
        println!("Last block in Chain: {:?}", chain.blocks.last());
    }
}
