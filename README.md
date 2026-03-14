# Hash Audit Tool

A professional, enterprise-grade hash-cracking and password auditing framework designed for defensive security, forensics, and compliance testing.

## Overview

Hash Audit Tool is a modular, extensible framework that supports multiple hash algorithms and attack strategies. Built with security professionals in mind, it provides powerful capabilities for authorized password auditing while maintaining strict ethical standards and safety controls.

## Features

### 🔑 Hash Algorithm Support
- **MD5** - Legacy compatibility (cryptographically broken)
- **SHA-1** - Legacy compatibility (cryptographically broken) 
- **SHA-256** - Secure hash algorithm
- **SHA-512** - High-security hash algorithm
- **NTLM** - Windows authentication hashes
- **bcrypt** - Verification-only (properly salted)
- **PBKDF2** - Verification-only (properly salted)

### ⚔️ Attack Modes
- **Dictionary Attack** - Wordlist-based cracking with mutation rules
- **Brute-Force Attack** - Mask-based systematic cracking
- **Hybrid Attack** - Combined dictionary and mask approaches

### 🚀 Performance Features
- **Multiprocessing** - CPU-based parallel processing
- **Memory Optimization** - Efficient wordlist streaming
- **Progress Tracking** - Real-time progress and performance metrics
- **Intelligent Chunking** - Optimized work distribution

### 🛡️ Safety & Ethics
- **Legal Disclaimer** - Mandatory authorization confirmation
- **Ethical Controls** - Built-in compliance features
- **Audit Logging** - Comprehensive activity tracking
- **Professional Interface** - Enterprise-grade CLI

## Architecture

```
Hash-Cracker-Dictionary-Brute-/
│
├── core/
│   ├── hashes/              # Hash algorithm implementations
│   ├── attacks/             # Attack strategies
│   ├── engine/              # Cracking engine & scheduler
│   ├── wordlists/           # Dictionary handling
│   ├── masks/               # Brute-force masks
│   ├── rules/               # Mutation rules
│   ├── performance/         # Optimization & benchmarking
│   └── utils/               # Helper utilities
│
├── cli/
│   └── interface.py         # Command-line interface
│
├── tests/                   # Comprehensive test suite
├── docs/                    # Documentation
├── examples/                # Usage examples
│
├── main.py                  # Entry point
├── requirements.txt         # Dependencies
├── pyproject.toml          # Project configuration
└── README.md               # This file
```

## Installation

### Prerequisites
- Python 3.8 or higher
- Multiple CPU cores recommended for optimal performance

### Setup
```bash
# Clone the repository
git clone https://github.com/joemunene-by/Hash-Cracker-Dictionary-Brute-.git
cd Hash-Cracker-Dictionary-Brute-

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Optional Dependencies
```bash
# For enhanced memory monitoring
pip install psutil

# For better file encoding detection
pip install chardet

# For bcrypt support
pip install bcrypt
```

## Usage

### Basic Commands

#### Dictionary Attack
```bash
# Single hash
python main.py crack --hash "5f4dcc3b5aa765d61d8327deb882cf99" --type md5 --mode dictionary --wordlist wordlist.txt

# Multiple hashes from file
python main.py crack --hash-file hashes.txt --type sha256 --mode dictionary --wordlist rockyou.txt --output results.json --format json
```

#### Brute-Force Attack
```bash
# Mask-based attack
python main.py crack --hash "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" --type sha256 --mode brute --mask "?l?l?l?l?d?d"

# Variable length brute force
python main.py crack --hash target --type md5 --mode brute --mask "?l" --min-length 6 --max-length 10
```

#### Hybrid Attack
```bash
# Dictionary + mask combination
python main.py crack --hash target --type sha1 --mode hybrid --wordlist wordlist.txt --mask "?d?d" --hybrid-mode dictionary_mask

# Rules + brute force
python main.py crack --hash target --type md5 --mode hybrid --wordlist wordlist.txt --hybrid-mode rules_brute
```

### Advanced Options

#### Performance Tuning
```bash
# Specify worker count
python main.py crack --hash target --type md5 --mode dictionary --wordlist wordlist.txt --workers 8

# Set timeout
python main.py crack --hash target --type sha256 --mode brute --mask "?l?l?l?l" --timeout 300

# Verbose output
python main.py crack --hash target --type md5 --mode dictionary --wordlist wordlist.txt --verbose
```

#### Output Formats
```bash
# JSON output
python main.py crack --hash target --type md5 --mode dictionary --wordlist wordlist.txt --format json --output results.json

# CSV output
python main.py crack --hash target --type md5 --mode dictionary --wordlist wordlist.txt --format csv --output results.csv

# Text output (default)
python main.py crack --hash target --type md5 --mode dictionary --wordlist wordlist.txt --output results.txt
```

### Information Commands

#### Algorithm Information
```bash
python main.py info --algorithm md5
python main.py info --algorithm bcrypt
```

#### Attack Mode Information
```bash
python main.py info --attack-mode dictionary
python main.py info --attack-mode brute
```

#### Mask Patterns
```bash
python main.py info --masks
```

## Mask Patterns

Hash Audit Tool supports comprehensive mask patterns for brute-force attacks:

| Pattern | Description | Character Set |
|---------|-------------|---------------|
| `?l` | Lowercase letters | a-z |
| `?u` | Uppercase letters | A-Z |
| `?d` | Digits | 0-9 |
| `?s` | Special symbols | !@#$%^&*... |
| `?a` | All characters | All printable ASCII |
| `?b` | Binary digits | 0-1 |
| `?h` | Hex (lowercase) | 0-9, a-f |
| `?H` | Hex (uppercase) | 0-9, A-F |

### Examples
- `?l?l?l?l` - 4 lowercase letters
- `?u?l?l?l?d?d` - Title case + 3 lowercase + 2 digits
- `?l?l?l?l?l?l?d?d` - 6 lowercase + 2 digits
- `?l?l?l?l?s` - 4 lowercase + 1 symbol

## Performance

### Benchmarks
Typical performance on modern hardware (8-core CPU):

| Algorithm | Hashes/Second | Relative Speed |
|-----------|---------------|----------------|
| MD5 | ~50M H/s | 100% |
| SHA-1 | ~35M H/s | 70% |
| SHA-256 | ~20M H/s | 40% |
| SHA-512 | ~15M H/s | 30% |
| NTLM | ~45M H/s | 90% |
| bcrypt | ~50K H/s | 0.1% |
| PBKDF2 | ~30K H/s | 0.06% |

### Optimization Tips
- Use SSD storage for wordlists
- Allocate sufficient RAM for large wordlists
- Use appropriate worker counts (typically CPU count)
- Choose optimal chunk sizes for your workload

## Safety & Ethics

### Legal Compliance
This tool is designed exclusively for authorized security testing. Users must:

- Have explicit, written authorization to test target systems
- Use the tool only for legitimate security purposes
- Comply with all applicable laws and regulations
- Accept full responsibility for their actions

### Built-in Controls
- **Authorization Confirmation** - Mandatory legal disclaimer
- **Audit Logging** - Comprehensive activity tracking
- **Rate Limiting** - Prevents accidental abuse
- **Professional Interface** - Enterprise-grade presentation

### Responsible Use
- Never use on systems without explicit permission
- Respect privacy and data protection laws
- Use only for authorized security audits
- Report vulnerabilities responsibly

## Examples

### Password Security Audit
```bash
# Test common passwords against your hash database
python main.py crack --hash-file company_hashes.txt --type sha256 --mode dictionary --wordlist rockyou.txt --verbose --output audit_results.json
```

### Compliance Testing
```bash
# Verify password strength compliance
python main.py crack --hash-file test_hashes.txt --type sha256 --mode brute --mask "?l?l?l?l?l?l?l?l" --timeout 60 --output compliance_report.csv
```

### Forensic Analysis
```bash
# Analyze acquired password hashes
python main.py crack --hash-file evidence_hashes.txt --type ntlm --mode hybrid --wordlist forensic_wordlist.txt --mask "?d?d?d?d" --output forensic_findings.json
```

## Development

### Running Tests
```bash
# Run all tests
python tests/run_tests.py

# Run specific test module
python -m unittest tests.test_hashes
python -m unittest tests.test_attacks
python -m unittest tests.test_utils
```

### Code Style
The project follows PEP 8 standards and uses professional coding practices:
- Type hints for better code documentation
- Comprehensive error handling
- Extensive unit test coverage
- Professional documentation

### Contributing
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Documentation

- [Hash Algorithms](docs/hash-algorithms.md) - Detailed algorithm information
- [Attack Modes](docs/attack-modes.md) - Attack strategy documentation
- [Ethics and Legal](docs/ethics-and-legal.md) - Usage guidelines and compliance

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for authorized security testing only. The authors assume no liability for misuse or unauthorized use. Users are responsible for complying with all applicable laws and regulations.

## Support

For questions, issues, or contributions:
- GitHub Issues: Report bugs and request features
- Documentation: Check the docs/ directory for detailed guides
- Security Issues: Report vulnerabilities responsibly

## Roadmap

### Version 1.1
- GPU acceleration support
- Additional hash algorithms
- Enhanced mutation rules
- Web interface

### Version 1.2
- Distributed cracking
- Advanced reporting
- Machine learning optimizations
- Cloud integration

### Version 2.0
- Real-time collaboration
- Advanced analytics
- Custom rule engine
- Enterprise features

---

**Hash Audit Tool** - Professional password auditing for security professionals.
