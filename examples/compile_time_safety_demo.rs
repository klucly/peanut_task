// This example demonstrates compile-time type safety with associated types
// Uncomment the "broken" examples to see compile-time errors!

use peanut_task::core::signature_algorithms::{
    Eip191Hasher, Eip712Hasher, SignatureHasher, TypedData
};
use peanut_task::core::basic_structs::Message;
use serde_json::json;

fn main() {
    println!("=== Compile-Time Type Safety Demo ===\n");
    
    // ✅ CORRECT: Eip191Hasher with Message
    println!("✅ Using Eip191Hasher with Message (correct type):");
    let eip191_hasher = Eip191Hasher;
    let message = Message("Hello, Ethereum!".to_string());
    match eip191_hasher.compute_hash(&message) {
        Ok(hash) => println!("   Hash computed successfully: 0x{}", hex::encode(&hash[..8])),
        Err(e) => println!("   Error: {}", e),
    }
    
    // ✅ CORRECT: Eip712Hasher with TypedData
    println!("\n✅ Using Eip712Hasher with TypedData (correct type):");
    let eip712_hasher = Eip712Hasher;
    let typed_data = TypedData::new(
        json!({"name": "MyApp"}),
        json!({"Person": [{"name": "name", "type": "string"}]}),
        json!({"name": "Alice"})
    );
    match eip712_hasher.compute_hash(&typed_data) {
        Ok(hash) => println!("   Hash computed successfully: 0x{}", hex::encode(&hash[..8])),
        Err(e) => println!("   Error: {}", e),
    }
    
    println!("\n=== Compile-Time Protection Examples ===\n");
    println!("The following code would NOT compile if uncommented:\n");
    
    // ❌ WRONG TYPE: This would cause a COMPILE ERROR
    println!("// ❌ Trying to use Eip191Hasher with TypedData:");
    println!("// let eip191_hasher = Eip191Hasher;");
    println!("// let typed_data = TypedData::new(...);");
    println!("// eip191_hasher.compute_hash(&typed_data); // ← COMPILE ERROR!");
    println!("//");
    println!("// error[E0308]: mismatched types");
    println!("//   expected `Message`, found `TypedData`");
    
    // Uncomment to see the error:
    // let eip191_hasher = Eip191Hasher;
    // let typed_data = TypedData::new(
    //     json!({"name": "Test"}),
    //     json!({}),
    //     json!({})
    // );
    // eip191_hasher.compute_hash(&typed_data);
    
    println!("\n// ❌ Trying to use Eip712Hasher with Message:");
    println!("// let eip712_hasher = Eip712Hasher;");
    println!("// let message = Message(String::from(\"Hello\"));");
    println!("// eip712_hasher.compute_hash(&message); // ← COMPILE ERROR!");
    println!("//");
    println!("// error[E0308]: mismatched types");
    println!("//   expected `TypedData`, found `Message`");
    
    // Uncomment to see the error:
    // let eip712_hasher = Eip712Hasher;
    // let message = String::from("Hello");
    // eip712_hasher.compute_hash(&message);
    
    println!("\n=== Key Benefits ===\n");
    println!("1. ✅ Errors caught at compile time, not runtime");
    println!("2. ✅ Zero runtime overhead - no type checking needed");
    println!("3. ✅ Self-documenting - type signature tells the story");
    println!("4. ✅ IDE support - autocomplete knows the exact type needed");
    println!("5. ✅ Refactoring safety - type changes break at compile time");
    
    println!("\n=== Before vs After ===\n");
    println!("BEFORE (runtime check):");
    println!("  fn compute_hash(&self, data: &SignatureData) -> Result<...> {{");
    println!("      match data {{");
    println!("          SignatureData::Message(msg) => ...,  // ← Runtime check");
    println!("          _ => Err(...),  // ← Can fail at runtime");
    println!("      }}");
    println!("  }}");
    println!();
    println!("AFTER (compile-time type safety):");
    println!("  impl SignatureHasher for Eip191Hasher {{");
    println!("      type Data = Message;  // ← Compiler enforces this!");
    println!("      fn compute_hash(&self, message: &Message) -> Result<...> {{");
    println!("          // No runtime check needed - compiler guarantees type!");
    println!("      }}");
    println!("  }}");
}
