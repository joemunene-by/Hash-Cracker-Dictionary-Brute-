# Attack Modes Documentation

This document provides detailed information about the attack modes supported by Hash Audit Tool, including their strategies, use cases, and optimization techniques.

## Overview

Hash Audit Tool implements three primary attack modes, each designed for different scenarios and password patterns. Understanding these modes is essential for effective password auditing and security testing.

## Attack Modes

### Dictionary Attack

**Purpose**: Efficiently test common and likely passwords  
**Best For**: Systems with weak password policies, common user behavior patterns  
**Complexity**: Low to Medium (depends on wordlist size)

#### Strategy
The dictionary attack uses pre-compiled wordlists to systematically test password candidates. It's the most efficient attack mode when users likely choose common or dictionary-based passwords.

#### Features
- **Streaming Processing**: Handles large wordlists without loading entire files into memory
- **Mutation Rules**: Applies common password variations and transformations
- **Validation**: Filters out invalid or unlikely candidates
- **Optimization**: Removes duplicates and optimizes character composition

#### Mutation Rules
When enabled, the dictionary attack applies these transformations:

1. **Case Variations**
   - Lowercase: `password` → `password`
   - Uppercase: `password` → `PASSWORD`
   - Title case: `password` → `Password`
   - Capitalized: `password` → `Password`

2. **Number Appending**
   - Common suffixes: `1`, `12`, `123`, `1234`, `2023`, `2024`, `2025`
   - Common prefixes: `1`, `12`, `123`

3. **Leetspeak Substitutions**
   - `a` → `@`, `e` → `3`, `i` → `1`, `o` → `0`, `s` → `$`
   - `t` → `7`, `l` → `1`, `g` → `9`, `b` → `8`, `z` → `2`

4. **Symbol Appending**
   - Common symbols: `!`, `@`, `#`, `$`, `%`, `&`, `*`

#### Usage Examples
```bash
# Basic dictionary attack
python main.py crack --hash target --type md5 --mode dictionary --wordlist rockyou.txt

# Dictionary attack without mutations
python main.py crack --hash target --type sha256 --mode dictionary --wordlist wordlist.txt --no-rules

# Dictionary attack with output
python main.py crack --hash target --type sha1 --mode dictionary --wordlist rockyou.txt --output results.json --format json
```

#### Optimization Tips
- **Use quality wordlists**: Start with common passwords, expand to comprehensive lists
- **Enable mutations**: Most passwords include common variations
- **Filter wordlists**: Remove duplicates and invalid entries
- **Monitor progress**: Large wordlists can take considerable time

#### Wordlist Recommendations
- **Small/Fast**: Top 10,000 common passwords for quick assessments
- **Medium**: RockYou (14 million passwords) for general auditing
- **Large**: Combined wordlists (100+ million) for comprehensive testing

### Brute-Force Attack

**Purpose**: Systematically test all possible combinations  
**Best For**: Short passwords, unknown patterns, completeness requirements  
**Complexity**: High (exponential growth with length)

#### Strategy
The brute-force attack uses mask-based patterns to systematically generate all possible password combinations within defined constraints. This guarantees finding the password if it matches the pattern.

#### Mask Patterns
Masks define the character sets and structure for password generation:

| Pattern | Description | Character Set | Size |
|---------|-------------|---------------|------|
| `?l` | Lowercase letters | a-z | 26 |
| `?u` | Uppercase letters | A-Z | 26 |
| `?d` | Digits | 0-9 | 10 |
| `?s` | Special symbols | !@#$%^&*... | 32 |
| `?a` | All characters | All printable ASCII | 95 |
| `?b` | Binary digits | 0-1 | 2 |
| `?h` | Hex (lowercase) | 0-9, a-f | 16 |
| `?H` | Hex (uppercase) | 0-9, A-F | 16 |

#### Complexity Analysis
The total combinations for a mask is the product of each character set size:

```
?l?l?l?l = 26^4 = 456,976 combinations
?l?l?l?d?d = 26^3 × 10^2 = 1,757,600 combinations
?u?l?l?l?d?d = 26 × 26^3 × 10^2 = 45,697,600 combinations
```

#### Usage Examples
```bash
# 4 lowercase letters
python main.py crack --hash target --type md5 --mode brute --mask "?l?l?l?l"

# 6 lowercase + 2 digits
python main.py crack --hash target --type sha256 --mode brute --mask "?l?l?l?l?l?l?d?d"

# Variable length brute force
python main.py crack --hash target --type sha1 --mode brute --mask "?l" --min-length 6 --max-length 10

# Complex pattern
python main.py crack --hash target --type ntlm --mode brute --mask "?u?l?l?l?d?d?s"
```

#### Optimization Tips
- **Start simple**: Begin with short, simple patterns
- **Use intelligence**: Apply knowledge of password policies
- **Estimate time**: Calculate combinations before starting
- **Set timeouts**: Prevent excessive run times

#### Time Estimates
Approximate time required (assuming 1M hashes/second):

| Pattern | Combinations | Time |
|---------|-------------|------|
| `?l?l?l?l` | 456,976 | < 1 second |
| `?l?l?l?l?l?l` | 308,915,776 | ~5 minutes |
| `?l?l?l?l?l?l?l?l` | 208,827,064,576 | ~58 hours |
| `?a?a?a?a?a?a` | 735,091,890,625 | ~8.5 days |

### Hybrid Attack

**Purpose**: Combine dictionary and brute-force approaches  
**Best For**: Complex passwords, mixed patterns, targeted attacks  
**Complexity**: Medium to High (depends on combination)

#### Strategy
Hybrid attacks combine the efficiency of dictionary attacks with the completeness of brute-force attacks. They're particularly effective against passwords that combine dictionary words with patterns.

#### Hybrid Modes

##### Dictionary + Mask (`dictionary_mask`)
Combines dictionary words with mask patterns:
- Word + mask: `password` + `123` → `password123`
- Mask + word: `123` + `password` → `123password`

##### Mask + Dictionary (`mask_dictionary`)
Inserts dictionary words into mask patterns:
- Insert at different positions in mask
- More targeted combinations
- Higher success rate for structured passwords

##### Rules + Brute (`rules_brute`)
Applies dictionary mutation rules first, then brute-force:
- Exhaustive dictionary mutations
- Falls back to brute-force if dictionary fails
- Comprehensive approach

#### Usage Examples
```bash
# Dictionary + mask hybrid
python main.py crack --hash target --type md5 --mode hybrid --wordlist rockyou.txt --mask "?d?d" --hybrid-mode dictionary_mask

# Mask + dictionary hybrid
python main.py crack --hash target --type sha256 --mode hybrid --wordlist wordlist.txt --mask "?l?l?l?l" --hybrid-mode mask_dictionary

# Rules + brute hybrid
python main.py crack --hash target --type sha1 --mode hybrid --wordlist rockyou.txt --hybrid-mode rules_brute
```

#### Optimization Tips
- **Choose appropriate mode**: Match mode to expected password pattern
- **Limit mask complexity**: Keep masks simple for hybrid attacks
- **Use quality wordlists**: Better wordlists improve hybrid effectiveness
- **Monitor progress**: Hybrid attacks can generate many candidates

## Attack Strategy Selection

### Decision Matrix

| Scenario | Recommended Attack | Rationale |
|----------|-------------------|-----------|
| Weak password policy | Dictionary | High probability of common passwords |
| Unknown password patterns | Brute-force | Guarantees coverage of defined space |
| Complex requirements | Hybrid | Balances efficiency and completeness |
| Short passwords (≤6 chars) | Brute-force | Manageable complexity |
| Long passwords (≥8 chars) | Dictionary/Hybrid | Brute-force impractical |
| Known patterns | Hybrid | Leverages pattern intelligence |

### Progressive Strategy

1. **Phase 1**: Dictionary attack with mutations
2. **Phase 2**: Hybrid attack (dictionary + simple mask)
3. **Phase 3**: Targeted brute-force (based on findings)
4. **Phase 4**: Comprehensive brute-force (if necessary)

### Success Rate Analysis

Based on typical password datasets:

| Attack Mode | Typical Success Rate | Time Investment |
|-------------|---------------------|-----------------|
| Dictionary | 30-60% | Low |
| Hybrid | 60-80% | Medium |
| Brute-force | 80-95% | High |

## Performance Considerations

### Hardware Optimization
- **CPU Cores**: Use all available cores for fast algorithms
- **Memory**: Sufficient RAM for wordlist streaming
- **Storage**: SSD for faster wordlist access
- **Parallel Processing**: Multiprocessing for candidate distribution

### Algorithm Impact
- **Fast algorithms** (MD5, SHA-1, SHA-256): Benefit from parallelization
- **Slow algorithms** (bcrypt, PBKDF2): Limited by computation time
- **Memory-bound**: Consider memory bandwidth limitations

### Workload Distribution
- **Chunk sizing**: Optimize for worker count and algorithm
- **Load balancing**: Even distribution across processes
- **Progress tracking**: Monitor worker performance

## Advanced Techniques

### Mask Generation
```python
# Generate masks from cracked passwords
masks = generate_masks_from_passwords(cracked_passwords)

# Rank masks by effectiveness
ranked_masks = rank_masks_by_effectiveness(masks)
```

### Rule Customization
```python
# Add custom mutation rules
rule_engine.add_custom_rule('company_suffix', lambda word: [word + '2024'])
```

### Targeted Attacks
```python
# Create targeted wordlists
targeted_wordlist = create_targeted_wordlist(target_info)

# Generate targeted masks
targeted_masks = generate_targeted_masks(target_info)
```

## Troubleshooting

### Common Issues

#### Dictionary Attack Problems
- **Wordlist not found**: Verify file path and permissions
- **Encoding issues**: Use UTF-8 encoding for wordlists
- **Memory issues**: Enable streaming for large files
- **No mutations**: Check if `--no-rules` flag is set

#### Brute-Force Attack Problems
- **Invalid mask**: Verify mask syntax and placeholders
- **Excessive time**: Estimate combinations before starting
- **Memory issues**: Reduce chunk size for large workloads
- **Worker issues**: Adjust worker count for system

#### Hybrid Attack Problems
- **Complex combinations**: Reduce mask complexity
- **Wordlist issues**: Verify wordlist quality and size
- **Mode selection**: Choose appropriate hybrid mode
- **Performance**: Monitor system resources

### Performance Issues
- **Slow progress**: Check worker utilization
- **Memory usage**: Monitor RAM consumption
- **Disk I/O**: Use SSD for wordlist storage
- **CPU usage**: Verify all cores are utilized

## Best Practices

### Planning
1. **Gather intelligence**: Password policies, user behavior
2. **Estimate complexity**: Calculate time requirements
3. **Choose strategy**: Select appropriate attack mode
4. **Set limits**: Define timeouts and resource constraints

### Execution
1. **Start simple**: Begin with dictionary attacks
2. **Monitor progress**: Track success rates and performance
3. **Adjust strategy**: Modify approach based on findings
4. **Document results**: Record all attempts and outcomes

### Analysis
1. **Success patterns**: Identify common password characteristics
2. **Failure analysis**: Understand why attacks failed
3. **Recommendations**: Suggest security improvements
4. **Reporting**: Create comprehensive audit reports

---

This documentation is intended for security professionals conducting authorized password audits and security testing.
