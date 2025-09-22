use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type THash = [u8; 32];
type TTimestamp = u64;
type TData = Vec<u8>;
type TNonce = u64;

fn hash_block(block: &mut Block) {
    let mut hasher = Sha256::new();

    // Fields ko bytes mai serialize
    hasher.update(&block.prev_hash);
    hasher.update(&block.timestamp.to_le_bytes());
    hasher.update(&block.data);
    hasher.update(&block.nonce.to_le_bytes());

    let result = hasher.finalize();
    block.hash = result.into();
}

fn serialize_chain(chain: &Blockchain) -> String {
    serde_json::to_string_pretty(chain).unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
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
        let genesis_data = String::from("Genesis Block");
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut genesis_block = Block {
            prev_hash: [0u8; 32],
            timestamp,
            data: genesis_data.into_bytes(),
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
fn main() {
    let chain = Blockchain::new();
    let json_str = serialize_chain(&chain);
    println!("Chain as JSON:\n{}", json_str);

    let deserialized: Blockchain = serde_json::from_str(&json_str).unwrap();
    println!("Deserialized len: {:?}", deserialized.blocks);
}
