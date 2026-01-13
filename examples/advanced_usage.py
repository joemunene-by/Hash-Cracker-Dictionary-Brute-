#!/usr/bin/env python3
"""
Advanced Usage Examples

Demonstrates advanced features of the Hash Audit Tool including
custom rules, performance optimization, and complex scenarios.
"""

import sys
import os
import time
from typing import Iterator

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.hashes import SHA256Hash
from core.attacks import DictionaryAttack
from core.engine import CrackingEngine
from core.rules.engine import RuleEngine
from core.rules.common_rules import CommonPasswordRules
from core.performance.optimizer import PerformanceOptimizer
from core.masks.generator import MaskGenerator
from core.wordlists.manager import WordlistManager
from core.utils.validators import validate_attack_parameters


def example_custom_rules():
    """Example: Create and use custom mutation rules."""
    print("=== Custom Mutation Rules ===")
    
    # Create rule engine
    rule_engine = RuleEngine()
    
    # Add custom rule for company-specific patterns
    def company_suffix_rule(word: str) -> Iterator[str]:
        """Add company-specific suffixes."""
        company_suffixes = ['2024', 'corp', 'inc', 'llc', ' ltd']
        for suffix in company_suffixes:
            yield word + suffix
    
    rule_engine.add_custom_rule(
        'company_suffix',
        company_suffix_rule,
        'Add company-specific suffixes'
    )
    
    # Add custom rule for keyboard patterns
    def keyboard_adjacent_rule(word: str) -> Iterator[str]:
        """Add keyboard adjacent character substitutions."""
        substitutions = {
            'a': 's', 's': 'a', 'd': 'f', 'f': 'd',
            'z': 'x', 'x': 'z', 'c': 'v', 'v': 'c'
        }
        
        for char, sub in substitutions.items():
            if char in word.lower():
                yield word.replace(char, sub)
                yield word.replace(char.upper(), sub.upper())
    
    rule_engine.add_custom_rule(
        'keyboard_adjacent',
        keyboard_adjacent_rule,
        'Keyboard adjacent character substitutions'
    )
    
    # Test custom rules
    test_word = "password"
    print(f"Original word: {test_word}")
    
    print("\nCustom rule mutations:")
    for rule_name in ['company_suffix', 'keyboard_adjacent']:
        mutations = list(rule_engine.apply_single_rule(test_word, rule_name))
        print(f"  {rule_name}: {mutations[:5]}")  # Show first 5
    
    # Load common rules
    rule_engine.load_common_rules()
    
    print(f"\nAvailable rules: {list(rule_engine.get_available_rules().keys())}")


def example_mask_generation():
    """Example: Generate masks from cracked passwords."""
    print("\n=== Mask Generation from Passwords ===")
    
    # Sample cracked passwords
    cracked_passwords = [
        "password123",
        "admin2024",
        "test!@#",
        "user001",
        "qwerty",
        "Password1",
        "hello123",
        "root2024"
    ]
    
    # Create mask generator
    generator = MaskGenerator()
    
    # Generate masks from passwords
    generated_masks = generator.generate_masks_from_passwords(cracked_passwords)
    
    print("Generated masks from cracked passwords:")
    for i, mask in enumerate(generated_masks[:10]):  # Show first 10
        print(f"  {i+1}. {mask}")
    
    # Generate common masks
    common_masks = generator.generate_common_masks(min_length=6, max_length=8)
    print(f"\nCommon masks (6-8 chars): {len(common_masks)} generated")
    for mask in common_masks[:5]:  # Show first 5
        print(f"  {mask}")
    
    # Rank masks by effectiveness
    ranked_masks = generator.rank_masks_by_effectiveness(generated_masks)
    print(f"\nTop 5 ranked masks:")
    for mask_info in ranked_masks[:5]:
        print(f"  {mask_info['mask']} (score: {mask_info['score']})")


def example_performance_optimization():
    """Example: Performance optimization and benchmarking."""
    print("\n=== Performance Optimization ===")
    
    # Create performance optimizer
    optimizer = PerformanceOptimizer()
    
    # Benchmark algorithms
    print("Benchmarking algorithms...")
    benchmark_results = optimizer.benchmark_algorithms()
    
    print("\nAlgorithm Performance:")
    for algo_name, benchmark in benchmark_results['benchmarks'].items():
        if 'error' not in benchmark:
            print(f"  {algo_name}: {benchmark['hashes_per_second']:,.0f} H/s "
                  f"({benchmark['performance_rating']})")
    
    # Get optimization recommendations
    from core.hashes import MD5Hash
    algorithm = MD5Hash()
    workload_size = 1000000
    
    recommendations = optimizer.get_optimization_recommendations(algorithm, workload_size)
    
    print(f"\nOptimization Recommendations for {workload_size:,} candidates:")
    print(f"  Optimal workers: {recommendations['worker_optimization']['optimal_workers']}")
    print(f"  Max workers: {recommendations['worker_optimization']['max_workers']}")
    print(f"  Optimal chunk size: {recommendations['chunk_optimization']['optimized_chunk_size']}")
    
    print("\nReasoning:")
    for reason in recommendations['worker_optimization']['reasoning']:
        print(f"  - {reason}")
    
    print("\nGeneral Recommendations:")
    for rec in recommendations['general_recommendations']:
        print(f"  - {rec}")


def example_wordlist_management():
    """Example: Advanced wordlist management."""
    print("\n=== Advanced Wordlist Management ===")
    
    # Create sample wordlist
    sample_words = [
        "password", "123456", "admin", "test", "qwerty",
        "hello", "world", "user", "login", "pass",
        "the", "and", "for", "are", "but",  # Common words to filter
        "a", "b", "c", "d", "e",  # Too short
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # Too long
        "password1", "Password", "PASSWORD", "passWord123"
    ]
    
    # Create temporary wordlist
    with open("sample_wordlist.txt", "w") as f:
        for word in sample_words:
            f.write(word + "\n")
    
    try:
        # Create wordlist manager with validation and optimization
        manager = WordlistManager("sample_wordlist.txt", validate=True, optimize=True)
        
        # Get wordlist statistics
        stats = manager.get_stats()
        print("Wordlist Statistics:")
        print(f"  Total lines: {stats['total_lines']}")
        print(f"  Unique words: {stats['unique_words']}")
        print(f"  Duplicates: {stats['duplicates']}")
        print(f"  Min length: {stats['min_length']}")
        print(f"  Max length: {stats['max_length']}")
        print(f"  File size: {stats['file_size_mb']:.2f} MB")
        
        # Get sample of optimized words
        sample = manager.get_sample(10)
        print(f"\nOptimized sample (first 10):")
        for i, word in enumerate(sample):
            print(f"  {i+1}. {word}")
        
        # Create filtered wordlist
        manager.create_filtered_wordlist(
            "filtered_wordlist.txt",
            min_length=4,
            max_length=12
        )
        
        # Check filtered wordlist
        if os.path.exists("filtered_wordlist.txt"):
            with open("filtered_wordlist.txt", "r") as f:
                filtered_words = [line.strip() for line in f if line.strip()]
            print(f"\nFiltered wordlist: {len(filtered_words)} words")
            print(f"Sample: {filtered_words[:5]}")
    
    finally:
        # Clean up
        for file in ["sample_wordlist.txt", "filtered_wordlist.txt"]:
            if os.path.exists(file):
                os.remove(file)


def example_attack_validation():
    """Example: Attack parameter validation."""
    print("\n=== Attack Parameter Validation ===")
    
    # Test valid parameters
    valid_params = {
        'algorithm': 'sha256',
        'mode': 'dictionary',
        'wordlist': 'test_wordlist.txt',
        'workers': 4,
        'timeout': 300
    }
    
    validation = validate_attack_parameters(valid_params)
    print("Valid Parameters:")
    print(f"  Valid: {validation['is_valid']}")
    print(f"  Errors: {len(validation['errors'])}")
    print(f"  Warnings: {len(validation['warnings'])}")
    
    # Test invalid parameters
    invalid_params = {
        'algorithm': 'invalid_algo',
        'mode': 'invalid_mode',
        'wordlist': '',
        'workers': -1,
        'timeout': 0
    }
    
    validation = validate_attack_parameters(invalid_params)
    print("\nInvalid Parameters:")
    print(f"  Valid: {validation['is_valid']}")
    print(f"  Errors: {len(validation['errors'])}")
    for error in validation['errors']:
        print(f"    - {error}")
    print(f"  Warnings: {len(validation['warnings'])}")
    for warning in validation['warnings']:
        print(f"    - {warning}")


def example_progress_tracking():
    """Example: Progress tracking during cracking."""
    print("\n=== Progress Tracking Example ===")
    
    # Create progress callback
    def progress_callback(stats):
        """Custom progress callback."""
        attempts = stats.get('attempts', 0)
        elapsed = stats.get('elapsed_time', 0)
        workers = stats.get('workers_active', 0)
        
        if elapsed > 0:
            rate = attempts / elapsed
            print(f"\rProgress: {attempts:,} attempts | {rate:,.0f} H/s | {workers} workers | {elapsed:.1f}s", 
                  end='', flush=True)
    
    # Set up attack
    target_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # SHA-256 of "password"
    algorithm = SHA256Hash()
    
    # Create simple wordlist
    wordlist = ["wrong1", "wrong2", "wrong3", "password", "wrong4"]
    
    with open("temp_wordlist.txt", "w") as f:
        for word in wordlist:
            f.write(word + "\n")
    
    try:
        # Create attack and engine with progress tracking
        attack = DictionaryAttack(algorithm, "temp_wordlist.txt", apply_rules=False)
        engine = CrackingEngine(max_workers=2, progress_callback=progress_callback)
        
        print("Starting attack with progress tracking...")
        
        # Perform cracking
        result = engine.crack_hash(target_hash, algorithm, attack)
        
        print(f"\n\nResult: {'SUCCESS' if result.success else 'FAILED'}")
        if result.success:
            print(f"Password: {result.password}")
        print(f"Total attempts: {result.attempts:,}")
        print(f"Total time: {result.elapsed_time:.2f}s")
    
    finally:
        # Clean up
        if os.path.exists("temp_wordlist.txt"):
            os.remove("temp_wordlist.txt")


def example_complex_scenario():
    """Example: Complex multi-stage attack scenario."""
    print("\n=== Complex Multi-Stage Attack ===")
    
    # Target hash
    target_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # "password"
    algorithm = SHA256Hash()
    
    # Stage 1: Quick dictionary attack
    print("Stage 1: Quick Dictionary Attack")
    quick_words = ["password", "123456", "admin", "test", "qwerty"]
    
    with open("quick_dict.txt", "w") as f:
        for word in quick_words:
            f.write(word + "\n")
    
    try:
        attack1 = DictionaryAttack(algorithm, "quick_dict.txt", apply_rules=False)
        engine = CrackingEngine(max_workers=2)
        
        result1 = engine.crack_hash(target_hash, algorithm, attack1, timeout=10)
        
        if result1.success:
            print(f"✅ Stage 1 SUCCESS: {result1.password}")
            return
        else:
            print(f"❌ Stage 1 failed: {result1.attempts:,} attempts")
        
        # Stage 2: Dictionary with mutations
        print("\nStage 2: Dictionary with Mutations")
        attack2 = DictionaryAttack(algorithm, "quick_dict.txt", apply_rules=True)
        
        result2 = engine.crack_hash(target_hash, algorithm, attack2, timeout=15)
        
        if result2.success:
            print(f"✅ Stage 2 SUCCESS: {result2.password}")
            return
        else:
            print(f"❌ Stage 2 failed: {result2.attempts:,} attempts")
        
        # Stage 3: Hybrid attack
        print("\nStage 3: Hybrid Attack")
        attack3 = HybridAttack(algorithm, "quick_dict.txt", "?d?d", "dictionary_mask")
        
        result3 = engine.crack_hash(target_hash, algorithm, attack3, timeout=20)
        
        if result3.success:
            print(f"✅ Stage 3 SUCCESS: {result3.password}")
            return
        else:
            print(f"❌ Stage 3 failed: {result3.attempts:,} attempts")
        
        print("\n❌ All stages failed")
    
    finally:
        # Clean up
        if os.path.exists("quick_dict.txt"):
            os.remove("quick_dict.txt")


def main():
    """Run all advanced examples."""
    print("Hash Audit Tool - Advanced Usage Examples")
    print("=" * 60)
    print("These examples demonstrate advanced features for authorized testing only.")
    print("Never use these tools on systems without explicit permission.")
    print("=" * 60)
    
    try:
        # Run examples
        example_custom_rules()
        example_mask_generation()
        example_performance_optimization()
        example_wordlist_management()
        example_attack_validation()
        example_progress_tracking()
        example_complex_scenario()
        
        print("\n" + "=" * 60)
        print("All advanced examples completed successfully!")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\nExamples interrupted by user.")
    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
