use std::time::{SystemTime, UNIX_EPOCH};

type THash = [u8; 32];
type TTimestamp = u64;
type TData = Vec<u8>;
type TNonce = u64;

#[derive(Debug)]
struct Block {
    prev_hash: THash,      // Previous Block Hash
    timestamp: TTimestamp, // Current time in seconds.
    data: TData,           // Transaction's raw data
    nonce: TNonce,         // Puzzle solution for mining
    hash: THash,           // Apna calculated hash.
}

fn main() {
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

    println!("{:?}", genesis_block);
}
