use serde::{Deserialize, Serialize};
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
        hasher.update(&self.data);
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

    fn add_block(&mut self, data: Vec<u8>, difficulty: u32) -> Result<()> {
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

    // Naya block add: Data, difficulty.
    let new_data = b"Second Block: Hello from Veerbal!".to_vec();
    if let Err(e) = chain.add_block(new_data, 1) {
        println!("Add failed: {}", e);
    } else {
        println!("Added block! New len: {}", chain.blocks.len()); // Should 2.
        println!("Full chain valid? {:?}", chain.validate());
        println!("Last block hash: {:?}", &chain.blocks[1].hash[0..4]); // Zeros.
    }
}
