#!/usr/bin/env python3
"""
Basic Usage Examples

Demonstrates basic usage of the Hash Audit Tool for common scenarios.
These examples are for educational purposes and authorized testing only.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.hashes import MD5Hash, SHA256Hash, NTLMHash
from core.attacks import DictionaryAttack, BruteForceAttack, HybridAttack
from core.engine import CrackingEngine


def example_single_hash_crack():
    """Example: Crack a single hash using dictionary attack."""
    print("=== Single Hash Dictionary Attack ===")
    
    # Target hash (MD5 of "password")
    target_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    
    # Create hash algorithm
    hash_algorithm = MD5Hash()
    
    # Create simple wordlist
    wordlist = ["password", "123456", "admin", "test", "qwerty", "hello"]
    
    # Create temporary wordlist file
    with open("temp_wordlist.txt", "w") as f:
        for word in wordlist:
            f.write(word + "\n")
    
    try:
        # Create dictionary attack
        attack = DictionaryAttack(hash_algorithm, "temp_wordlist.txt", apply_rules=True)
        attack.set_target(target_hash)
        
        # Create cracking engine
        engine = CrackingEngine(max_workers=2)
        
        # Perform cracking
        result = engine.crack_hash(target_hash, hash_algorithm, attack)
        
        # Display results
        if result.success:
            print(f"✅ Password found: {result.password}")
            print(f"   Attempts: {result.attempts:,}")
            print(f"   Time: {result.elapsed_time:.2f}s")
            print(f"   Rate: {result.hashes_per_second:,.0f} H/s")
        else:
            print("❌ Password not found")
            print(f"   Attempts: {result.attempts:,}")
            print(f"   Time: {result.elapsed_time:.2f}s")
    
    finally:
        # Clean up
        if os.path.exists("temp_wordlist.txt"):
            os.remove("temp_wordlist.txt")


def example_brute_force_attack():
    """Example: Brute-force attack with mask."""
    print("\n=== Brute-Force Attack with Mask ===")
    
    # Target hash (SHA-256 of "test123")
    target_hash = "ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc7025a7a0f905b2c6a63c"
    
    # Create hash algorithm
    hash_algorithm = SHA256Hash()
    
    # Create brute-force attack with mask
    # ?l = lowercase, ?d = digits
    mask = "?l?l?l?l?d?d"  # 4 lowercase letters + 2 digits
    attack = BruteForceAttack(hash_algorithm, mask)
    attack.set_target(target_hash)
    
    # Display attack info
    info = attack.get_info()
    print(f"Mask: {info['mask']}")
    print(f"Total combinations: {info['total_combinations']:,}")
    print(f"Estimated time: {info['estimated_time_hours']:.2f} hours")
    
    # Create cracking engine with timeout
    engine = CrackingEngine(max_workers=2)
    
    # Perform cracking with timeout (30 seconds)
    result = engine.crack_hash(target_hash, hash_algorithm, attack, timeout=30)
    
    # Display results
    if result.success:
        print(f"✅ Password found: {result.password}")
        print(f"   Attempts: {result.attempts:,}")
        print(f"   Time: {result.elapsed_time:.2f}s")
    else:
        print("❌ Password not found (timeout or not in search space)")
        print(f"   Attempts: {result.attempts:,}")
        print(f"   Time: {result.elapsed_time:.2f}s")


def example_hybrid_attack():
    """Example: Hybrid attack combining dictionary and mask."""
    print("\n=== Hybrid Attack ===")
    
    # Target hash (NTLM of "admin2024")
    target_hash = "5fa386a1c6e42b9a1c8e0e8e8e8e8e8e"
    
    # Create hash algorithm
    hash_algorithm = NTLMHash()
    
    # Create wordlist
    wordlist = ["admin", "user", "root", "test", "guest"]
    
    # Create temporary wordlist file
    with open("temp_wordlist.txt", "w") as f:
        for word in wordlist:
            f.write(word + "\n")
    
    try:
        # Create hybrid attack
        # Dictionary words + 4 digits
        attack = HybridAttack(hash_algorithm, "temp_wordlist.txt", "?d?d?d?d", "dictionary_mask")
        attack.set_target(target_hash)
        
        # Create cracking engine
        engine = CrackingEngine(max_workers=2)
        
        # Perform cracking
        result = engine.crack_hash(target_hash, hash_algorithm, attack)
        
        # Display results
        if result.success:
            print(f"✅ Password found: {result.password}")
            print(f"   Attempts: {result.attempts:,}")
            print(f"   Time: {result.elapsed_time:.2f}s")
        else:
            print("❌ Password not found")
            print(f"   Attempts: {result.attempts:,}")
            print(f"   Time: {result.elapsed_time:.2f}s")
    
    finally:
        # Clean up
        if os.path.exists("temp_wordlist.txt"):
            os.remove("temp_wordlist.txt")


def example_hash_verification():
    """Example: Hash verification for different algorithms."""
    print("\n=== Hash Verification Examples ===")
    
    test_passwords = ["password", "admin", "test123", "HelloWorld"]
    
    algorithms = {
        "MD5": MD5Hash(),
        "SHA-256": SHA256Hash(),
        "NTLM": NTLMHash()
    }
    
    for algo_name, algorithm in algorithms.items():
        print(f"\n{algo_name} Examples:")
        
        for password in test_passwords:
            # Generate hash
            hash_value = algorithm.hash(password)
            
            # Verify hash
            is_valid = algorithm.verify(password, hash_value)
            
            print(f"  Password: {password:<12} | Hash: {hash_value[:16]}... | Valid: {is_valid}")


def example_algorithm_info():
    """Example: Display algorithm information."""
    print("\n=== Algorithm Information ===")
    
    algorithms = [MD5Hash(), SHA256Hash(), NTLMHash()]
    
    for algorithm in algorithms:
        info = algorithm.get_info()
        
        print(f"\n{info['name']}:")
        print(f"  Output Length: {info['output_length']} bits")
        print(f"  Security Status: {info['security_status']}")
        print(f"  Recommended: {info['recommended_for_new_systems']}")
        
        if 'use_case' in info:
            print(f"  Use Case: {info['use_case']}")


def example_performance_benchmark():
    """Example: Performance benchmarking."""
    print("\n=== Performance Benchmark ===")
    
    from core.utils.helpers import benchmark_performance
    
    algorithms = [MD5Hash(), SHA256Hash()]
    
    print("Benchmarking hash algorithms...")
    print("-" * 50)
    
    for algorithm in algorithms:
        benchmark = benchmark_performance(algorithm)
        
        print(f"{algorithm.name}:")
        print(f"  Hashes/Second: {benchmark['hashes_per_second']:,.0f}")
        print(f"  Time per Hash: {benchmark['time_per_hash']*1000000:.2f} μs")
        print(f"  Performance: {benchmark['performance_rating']}")


def main():
    """Run all examples."""
    print("Hash Audit Tool - Basic Usage Examples")
    print("=" * 50)
    print("These examples demonstrate basic functionality for authorized testing only.")
    print("Never use these tools on systems without explicit permission.")
    print("=" * 50)
    
    try:
        # Run examples
        example_single_hash_crack()
        example_brute_force_attack()
        example_hybrid_attack()
        example_hash_verification()
        example_algorithm_info()
        example_performance_benchmark()
        
        print("\n" + "=" * 50)
        print("All examples completed successfully!")
        print("=" * 50)
        
    except KeyboardInterrupt:
        print("\nExamples interrupted by user.")
    except Exception as e:
        print(f"\nError running examples: {e}")


if __name__ == "__main__":
    main()
