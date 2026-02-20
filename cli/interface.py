"""
Hash Audit Tool CLI Interface

Professional command-line interface for hash cracking and password auditing
with built-in safety controls and ethical usage enforcement.
"""

import argparse
import json
import csv
import sys
import time
import os
from typing import Optional, Dict, Any
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.hashes import *
from core.attacks import *
from core.engine import CrackingEngine


class LegalDisclaimer:
    """Handles legal disclaimer and authorization confirmation."""
    
    DISCLAIMER_TEXT = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    HASH AUDIT TOOL - LEGAL DISCLAIMER                        ║
║                                                                              ║
║  This tool is designed for AUTHORIZED security testing, password auditing,    ║
║  forensics, and compliance testing ONLY.                                      ║
║                                                                              ║
║  By using this tool, you confirm that:                                        ║
║  • You have explicit, written authorization to test the target systems       ║
║  • You are using this tool for legitimate security purposes                  ║
║  • You comply with all applicable laws and regulations                       ║
║  • You accept full responsibility for your actions                           ║
║                                                                              ║
║  Unauthorized use of this tool may violate criminal and civil laws.           ║
║  The authors assume no liability for misuse or unauthorized use.              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    @classmethod
    def display_disclaimer(cls):
        """Display the legal disclaimer."""
        print(cls.DISCLAIMER_TEXT)
    
    @classmethod
    def get_authorization(cls, force: bool = False) -> bool:
        """
        Get user authorization confirmation.
        
        Args:
            force: Skip confirmation if True (requires --authorized flag)
            
        Returns:
            True if authorized, False otherwise
        """
        if force:
            print("[INFO] Authorization confirmed via --authorized flag")
            return True
        
        print("\n" + "="*80)
        print("AUTHORIZATION REQUIRED")
        print("="*80)
        print("I confirm that I have explicit authorization to use this tool")
        print("for legitimate security testing purposes only.")
        print("="*80)
        
        while True:
            response = input("Type 'AUTHORIZED' to continue, or 'quit' to exit: ").strip().upper()
            
            if response == 'AUTHORIZED':
                print("[INFO] Authorization confirmed. Proceeding with audit...")
                return True
            elif response in ['QUIT', 'EXIT', 'Q']:
                print("[INFO] Exiting Hash Audit Tool.")
                return False
            else:
                print("[ERROR] Invalid response. Please type 'AUTHORIZED' or 'quit'.")


class ProgressTracker:
    """Tracks and displays progress during cracking operations."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.start_time = None
        self.last_update = 0
    
    def start(self):
        """Start progress tracking."""
        self.start_time = time.time()
        if self.verbose:
            print("[INFO] Starting password cracking operation...")
    
    def update(self, stats: Dict[str, Any]):
        """Update progress display."""
        if not self.verbose:
            return
        
        current_time = time.time()
        if current_time - self.last_update < 1.0:  # Update every second
            return
        
        elapsed = current_time - self.start_time
        attempts = stats.get('attempts', 0)
        workers = stats.get('workers_active', 0)
        
        hashes_per_sec = attempts / elapsed if elapsed > 0 else 0
        
        print(f"\r[PROGRESS] Attempts: {attempts:,} | Rate: {hashes_per_sec:,.0f} H/s | "
              f"Workers: {workers} | Time: {elapsed:.1f}s", end='', flush=True)
        
        self.last_update = current_time
    
    def finish(self):
        """Finish progress tracking."""
        if self.verbose:
            print()  # New line after progress


class OutputFormatter:
    """Formats and saves cracking results."""
    
    @staticmethod
    def format_result(result: Dict[str, Any], format_type: str = 'text') -> str:
        """
        Format cracking result for display.
        
        Args:
            result: Cracking result dictionary
            format_type: Output format ('text', 'json', 'csv')
            
        Returns:
            Formatted result string
        """
        if format_type == 'json':
            return json.dumps(result, indent=2)
        elif format_type == 'csv':
            if result['success']:
                return f"success,password,attempts,time,rate,strategy,algorithm\n" \
                       f"True,{result['password']},{result['attempts']},{result['elapsed_time']:.2f}," \
                       f"{result['hashes_per_second']:.0f},{result['strategy']},{result['algorithm']}"
            else:
                return f"success,password,attempts,time,rate,strategy,algorithm\n" \
                       f"False,,{result['attempts']},{result['elapsed_time']:.2f}," \
                       f"{result['hashes_per_second']:.0f},{result['strategy']},{result['algorithm']}"
        else:  # text format
            if result['success']:
                return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           CRACKING SUCCESSFUL                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Password Found:    {result['password']:<40} ║
║ Attempts:          {result['attempts']:<40,} ║
║ Time Taken:        {result['elapsed_time']:.2f} seconds{'':<28} ║
║ Hash Rate:         {result['hashes_per_second']:,.0f} H/s{'':<26} ║
║ Strategy:          {result['strategy']:<40} ║
║ Algorithm:         {result['algorithm']:<40} ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
            else:
                return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           CRACKING FAILED                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Password not found in the searched space.                                   ║
║ Attempts:          {result['attempts']:<40,} ║
║ Time Taken:        {result['elapsed_time']:.2f} seconds{'':<28} ║
║ Hash Rate:         {result['hashes_per_second']:,.0f} H/s{'':<26} ║
║ Strategy:          {result['strategy']:<40} ║
║ Algorithm:         {result['algorithm']:<40} ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    @staticmethod
    def save_result(result: Dict[str, Any], output_file: str, format_type: str = 'text'):
        """
        Save result to file.
        
        Args:
            result: Cracking result dictionary
            output_file: Output file path
            format_type: Output format
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(OutputFormatter.format_result(result, format_type))
            print(f"[INFO] Results saved to: {output_file}")
        except IOError as e:
            print(f"[ERROR] Failed to save results: {e}")


class HashAuditCLI:
    """Main CLI application class."""
    
    def __init__(self):
        self.parser = self._create_parser()
        self.progress_tracker = None
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog='hashcracker',
            description='Professional Hash Cracking & Password Audit Tool',
            epilog='Use responsibly and only on systems you have authorization to test.',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Add subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Crack command
        crack_parser = subparsers.add_parser('crack', help='Crack a hash')
        self._add_crack_arguments(crack_parser)
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Display algorithm and attack information')
        self._add_info_arguments(info_parser)
        
        # Global arguments
        parser.add_argument('--authorized', action='store_true',
                          help='Skip authorization confirmation (use with caution)')
        parser.add_argument('--verbose', '-v', action='store_true',
                          help='Enable verbose output')
        parser.add_argument('--version', action='version', version='Hash Audit Tool 1.0.0')
        
        return parser
    
    def _add_crack_arguments(self, parser: argparse.ArgumentParser):
        """Add arguments for the crack command."""
        # Target specification
        target_group = parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument('--hash', help='Single hash to crack')
        target_group.add_argument('--hash-file', help='File containing hashes (one per line)')
        
        # Algorithm specification
        parser.add_argument('--type', required=True,
                          choices=['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'bcrypt', 'pbkdf2'],
                          help='Hash algorithm type')
        
        # Attack mode specification
        parser.add_argument('--mode', required=True,
                          choices=['dictionary', 'brute', 'hybrid'],
                          help='Attack mode')
        
        # Dictionary attack arguments
        parser.add_argument('--wordlist', help='Wordlist file for dictionary attack')
        parser.add_argument('--no-rules', action='store_true',
                          help='Disable mutation rules for dictionary attack')
        
        # Brute-force attack arguments
        parser.add_argument('--mask', help='Mask pattern for brute-force attack')
        parser.add_argument('--min-length', type=int, default=1,
                          help='Minimum password length for brute-force')
        parser.add_argument('--max-length', type=int, default=12,
                          help='Maximum password length for brute-force')
        
        # Hybrid attack arguments
        parser.add_argument('--hybrid-mode', choices=['dictionary_mask', 'mask_dictionary', 'rules_brute'],
                          default='dictionary_mask', help='Hybrid attack mode')
        
        # Performance arguments
        parser.add_argument('--workers', type=int,
                          help='Number of worker processes (default: CPU count)')
        parser.add_argument('--timeout', type=float,
                          help='Maximum time to attempt (seconds)')
        
        # Output arguments
        parser.add_argument('--output', help='Output file for results')
        parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text',
                          help='Output format')
    
    def _add_info_arguments(self, parser: argparse.ArgumentParser):
        """Add arguments for the info command."""
        parser.add_argument('--algorithm', 
                          choices=['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'bcrypt', 'pbkdf2'],
                          help='Display algorithm information')
        parser.add_argument('--attack-mode',
                          choices=['dictionary', 'brute', 'hybrid'],
                          help='Display attack mode information')
        parser.add_argument('--masks', action='store_true',
                          help='Display available mask patterns')
    
    def run(self, args=None):
        """Run the CLI application."""
        # Parse arguments
        parsed_args = self.parser.parse_args(args)
        
        # Display disclaimer
        LegalDisclaimer.display_disclaimer()
        
        # Get authorization
        if not LegalDisclaimer.get_authorization(parsed_args.authorized):
            sys.exit(1)
        
        # Initialize progress tracker
        self.progress_tracker = ProgressTracker(parsed_args.verbose)
        
        # Execute command
        if parsed_args.command == 'crack':
            self._handle_crack_command(parsed_args)
        elif parsed_args.command == 'info':
            self._handle_info_command(parsed_args)
        else:
            self.parser.print_help()
    
    def _handle_crack_command(self, args):
        """Handle the crack command."""
        # Get hash algorithm
        hash_algorithm = self._get_hash_algorithm(args.type)
        
        # Get attack strategy
        attack_strategy = self._get_attack_strategy(args, hash_algorithm)
        
        # Initialize cracking engine
        engine = CrackingEngine(
            max_workers=args.workers,
            progress_callback=self.progress_tracker.update if args.verbose else None
        )
        
        # Process targets
        if args.hash:
            # Single hash
            self._crack_single_hash(args.hash, hash_algorithm, attack_strategy, engine, args)
        else:
            # Multiple hashes from file
            self._crack_hash_file(args.hash_file, hash_algorithm, attack_strategy, engine, args)
    
    # Map algorithm names to their classes so we only instantiate the one
    # that is actually requested, instead of eagerly constructing all seven.
    _ALGORITHM_CLASSES = {
        'md5': MD5Hash,
        'sha1': SHA1Hash,
        'sha256': SHA256Hash,
        'sha512': SHA512Hash,
        'ntlm': NTLMHash,
        'bcrypt': BcryptHash,
        'pbkdf2': PBKDF2Hash,
    }

    def _get_hash_algorithm(self, algorithm_type: str):
        """Get hash algorithm instance."""
        cls = self._ALGORITHM_CLASSES.get(algorithm_type)
        if cls is None:
            raise ValueError(f"Unsupported algorithm: {algorithm_type}")
        return cls()
    
    def _get_attack_strategy(self, args, hash_algorithm):
        """Get attack strategy instance."""
        if args.mode == 'dictionary':
            if not args.wordlist:
                raise ValueError("Dictionary attack requires --wordlist argument")
            return DictionaryAttack(hash_algorithm, args.wordlist, not args.no_rules)
        
        elif args.mode == 'brute':
            if not args.mask:
                raise ValueError("Brute-force attack requires --mask argument")
            return BruteForceAttack(hash_algorithm, args.mask, args.min_length, args.max_length)
        
        elif args.mode == 'hybrid':
            if not args.wordlist:
                raise ValueError("Hybrid attack requires --wordlist argument")
            return HybridAttack(hash_algorithm, args.wordlist, args.mask, args.hybrid_mode)
        
        else:
            raise ValueError(f"Unsupported attack mode: {args.mode}")
    
    def _crack_single_hash(self, target_hash, hash_algorithm, attack_strategy, engine, args):
        """Crack a single hash."""
        print(f"[INFO] Starting attack on {args.type.upper()} hash: {target_hash}")
        print(f"[INFO] Using {args.mode} attack strategy")
        
        if args.verbose:
            print(f"[INFO] Attack strategy info: {attack_strategy.get_info()}")
        
        self.progress_tracker.start()
        
        # Perform cracking
        result = engine.crack_hash(
            target_hash=target_hash,
            hash_algorithm=hash_algorithm,
            attack_strategy=attack_strategy,
            timeout=args.timeout
        )
        
        self.progress_tracker.finish()
        
        # Display and save results
        output = OutputFormatter.format_result(result.to_dict(), args.format)
        print(output)
        
        if args.output:
            OutputFormatter.save_result(result.to_dict(), args.output, args.format)
    
    def _crack_hash_file(self, hash_file, hash_algorithm, attack_strategy, engine, args):
        """Crack multiple hashes from file."""
        print(f"[INFO] Processing hashes from file: {hash_file}")
        
        try:
            with open(hash_file, 'r', encoding='utf-8') as f:
                hashes = [line.strip() for line in f if line.strip()]
        except IOError as e:
            print(f"[ERROR] Failed to read hash file: {e}")
            return
        
        print(f"[INFO] Found {len(hashes)} hashes to process")
        
        results = []
        for i, target_hash in enumerate(hashes, 1):
            print(f"\n[INFO] Processing hash {i}/{len(hashes)}: {target_hash}")
            
            self.progress_tracker.start()
            
            # Perform cracking
            result = engine.crack_hash(
                target_hash=target_hash,
                hash_algorithm=hash_algorithm,
                attack_strategy=attack_strategy,
                timeout=args.timeout
            )
            
            self.progress_tracker.finish()
            
            # Display result
            output = OutputFormatter.format_result(result.to_dict(), args.format)
            print(output)
            
            results.append(result.to_dict())
        
        # Save all results if output file specified
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    if args.format == 'json':
                        json.dump(results, f, indent=2)
                    else:
                        for result in results:
                            f.write(OutputFormatter.format_result(result, args.format) + '\n')
                print(f"[INFO] All results saved to: {args.output}")
            except IOError as e:
                print(f"[ERROR] Failed to save results: {e}")
    
    def _handle_info_command(self, args):
        """Handle the info command."""
        if args.algorithm:
            # Display algorithm information
            hash_algorithm = self._get_hash_algorithm(args.algorithm)
            info = hash_algorithm.get_info()
            
            print(f"\n{args.algorithm.upper()} Algorithm Information:")
            print("=" * 50)
            for key, value in info.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
        
        if args.attack_mode:
            # Display attack mode information
            if args.attack_mode == 'dictionary':
                info = DictionaryAttack(MD5Hash(), 'dummy').get_info()
            elif args.attack_mode == 'brute':
                info = BruteForceAttack(MD5Hash(), '?l?l?l?l').get_info()
            elif args.attack_mode == 'hybrid':
                info = HybridAttack(MD5Hash(), 'dummy').get_info()
            
            print(f"\n{args.attack_mode.title()} Attack Information:")
            print("=" * 50)
            for key, value in info.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
        
        if args.masks:
            # Display mask patterns
            from core.masks.parser import MaskParser
            parser = MaskParser()
            
            print("\nAvailable Mask Patterns:")
            print("=" * 50)
            for placeholder, description in parser.get_available_placeholders().items():
                print(f"{placeholder:<8} : {description}")


def main():
    """Main entry point."""
    try:
        cli = HashAuditCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
