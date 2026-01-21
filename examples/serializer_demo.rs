use peanut_task::core::serializer::Serializer;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Canonical JSON Serializer Demo ===\n");

    // Example 1: Basic serialization with key ordering
    println!("1. Basic Serialization (demonstrates key sorting):");
    let data1 = json!({"name": "Alice", "age": 30, "city": "New York"});
    let bytes1 = Serializer::serialize(&data1)?;
    println!("   Input:  {}", data1);
    println!("   Output: {}", String::from_utf8_lossy(&bytes1));
    println!("   (Note: keys are sorted alphabetically)\n");

    // Example 2: Order independence
    println!("2. Order Independence (different input order, same output):");
    let data2a = json!({"name": "Bob", "age": 25});
    let data2b = json!({"age": 25, "name": "Bob"});
    let bytes2a = Serializer::serialize(&data2a)?;
    let bytes2b = Serializer::serialize(&data2b)?;
    println!("   Input A: {}", data2a);
    println!("   Input B: {}", data2b);
    println!("   Output A: {}", String::from_utf8_lossy(&bytes2a));
    println!("   Output B: {}", String::from_utf8_lossy(&bytes2b));
    println!("   Equal: {}\n", bytes2a == bytes2b);

    // Example 3: Hashing JSON data
    println!("3. Keccak-256 Hashing:");
    let data3 = json!({"transaction": "send", "amount": 100, "to": "0x123..."});
    let hash = Serializer::hash(&data3)?;
    println!("   Input: {}", data3);
    println!("   Hash (hex): 0x{}", hex::encode(&hash));
    println!("   Hash length: {} bytes\n", hash.len());

    // Example 4: Nested objects
    println!("4. Nested Objects:");
    let data4 = json!({
        "user": {
            "name": "Charlie",
            "address": {
                "street": "Main St",
                "city": "Boston"
            }
        },
        "id": 42
    });
    let bytes4 = Serializer::serialize(&data4)?;
    println!("   Input: {}", data4);
    println!("   Output: {}", String::from_utf8_lossy(&bytes4));
    println!("   (All nested keys are sorted)\n");

    // Example 5: Determinism verification
    println!("5. Determinism Verification:");
    let data5 = json!({"data": "test", "nonce": 123});
    match Serializer::verify_determinism(&data5, Some(1000)) {
        Ok(()) => println!("   ✓ Verified: Serialization is deterministic over 1000 iterations"),
        Err(e) => println!("   ✗ Failed: {}", e),
    }

    // Example 6: Hash consistency (same data = same hash)
    println!("\n6. Hash Consistency:");
    let data6a = json!({"z": 3, "y": 2, "x": 1});
    let data6b = json!({"x": 1, "y": 2, "z": 3});
    let hash6a = Serializer::hash(&data6a)?;
    let hash6b = Serializer::hash(&data6b)?;
    println!("   Input A: {}", data6a);
    println!("   Input B: {}", data6b);
    println!("   Hash A: 0x{}", hex::encode(&hash6a[..8]));
    println!("   Hash B: 0x{}", hex::encode(&hash6b[..8]));
    println!("   Hashes match: {}", hash6a == hash6b);

    println!("\n=== Demo Complete ===");
    Ok(())
}
