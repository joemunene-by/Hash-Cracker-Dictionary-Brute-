# Hash Algorithms Documentation

This document provides detailed information about the hash algorithms supported by Hash Audit Tool, including their characteristics, security status, and appropriate use cases.

## Overview

Hash Audit Tool supports a comprehensive range of hash algorithms commonly encountered in password auditing and security testing. Each algorithm is implemented with careful attention to cryptographic best practices and security considerations.

## Supported Algorithms

### MD5

**Status**: Cryptographically Broken  
**Output Length**: 128 bits (32 hex characters)  
**Use Case**: Legacy system compatibility only

#### Characteristics
- Fast computation speed
- Widely deployed in legacy systems
- Vulnerable to collision attacks
- No salt (rainbow table vulnerable)

#### Security Considerations
- **NOT RECOMMENDED** for new systems
- Collision resistance broken since 2004
- Preimage resistance theoretically weakened
- Should be replaced with SHA-256 or better

#### Implementation Notes
```python
# Example MD5 hash
hash_value = "5f4dcc3b5aa765d61d8327deb882cf99"  # "password"
```

### SHA-1

**Status**: Cryptographically Broken  
**Output Length**: 160 bits (40 hex characters)  
**Use Case**: Legacy system compatibility only

#### Characteristics
- Moderate computation speed
- Previously widely used (Git, SSL certificates)
- Practical collision attacks demonstrated
- No salt (rainbow table vulnerable)

#### Security Considerations
- **NOT RECOMMENDED** for new systems
- Collision attacks demonstrated in 2017
- Preimage resistance still considered strong
- Being phased out industry-wide

#### Implementation Notes
```python
# Example SHA-1 hash
hash_value = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"  # "password"
```

### SHA-256

**Status**: Secure  
**Output Length**: 256 bits (64 hex characters)  
**Use Case**: General purpose hashing, digital signatures

#### Characteristics
- Good computation speed
- Strong security margin
- Widely supported
- No salt in basic implementation

#### Security Considerations
- **RECOMMENDED** for new systems
- Strong collision resistance
- Strong preimage resistance
- Should be used with salt for password storage

#### Implementation Notes
```python
# Example SHA-256 hash
hash_value = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # "password"
```

### SHA-512

**Status**: Secure  
**Output Length**: 512 bits (128 hex characters)  
**Use Case**: High-security applications, digital signatures

#### Characteristics
- Moderate computation speed
- Excellent security margin
- Future-proof design
- No salt in basic implementation

#### Security Considerations
- **RECOMMENDED** for new systems
- Very strong collision resistance
- Very strong preimage resistance
- Preferred for high-security applications
- Should be used with salt for password storage

#### Implementation Notes
```python
# Example SHA-512 hash
hash_value = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"  # "password"
```

### NTLM

**Status**: Cryptographically Weak  
**Output Length**: 128 bits (32 hex characters)  
**Use Case**: Windows legacy authentication

#### Characteristics
- Based on MD4 algorithm
- UTF-16 Little Endian encoding
- Fast computation speed
- No salt (rainbow table vulnerable)

#### Security Considerations
- **NOT RECOMMENDED** for new systems
- Inherits MD4 weaknesses
- No salt protection
- Easily cracked with rainbow tables
- Being replaced by Kerberos in modern Windows

#### Implementation Notes
```python
# Example NTLM hash
hash_value = "8846f7eaee8fb117ad06bdd830b7586f"  # "password"
```

### bcrypt

**Status**: Secure (Verification Only)  
**Output Length**: 184 bits (60 chars including metadata)  
**Use Case**: Password storage

#### Characteristics
- Adaptive work factor
- Built-in salt
- Slow computation (by design)
- Not crackable in traditional sense

#### Security Considerations
- **RECOMMENDED** for password storage
- Strong against brute force attacks
- Automatic salt generation
- Configurable work factor
- **Cannot be cracked without salt**

#### Implementation Notes
```python
# Example bcrypt hash (format: $2b$12$salt.hash)
hash_value = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"  # "secret"
```

#### Format Details
- `$2b$` - Algorithm identifier
- `12` - Work factor (2^12 iterations)
- `EixZaYVK1fsbw1ZfbX3OXe` - 22-character salt (base64)
- `PaWxn96p36WQoeG6Lruj3vjPGga31lW` - 31-character hash (base64)

### PBKDF2

**Status**: Secure (Verification Only)  
**Output Length**: Variable (configurable)  
**Use Case**: Password storage, key derivation

#### Characteristics
- Adaptive iteration count
- Configurable salt
- Multiple hash algorithms supported
- Standardized (PKCS #5 v2.0)

#### Security Considerations
- **RECOMMENDED** for password storage
- Strong against brute force attacks
- Configurable security parameters
- **Cannot be cracked without salt and iterations**
- Industry standard approach

#### Implementation Notes
```python
# Example PBKDF2 hash (format: pbkdf2:algorithm:iterations:salt:hash)
hash_value = "pbkdf2:sha256:100000:salt123:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"  # "abc"
```

#### Format Details
- `pbkdf2` - Algorithm identifier
- `sha256` - Underlying hash algorithm
- `100000` - Iteration count
- `salt123` - Salt value
- `a665a459...` - Derived key (hex)

## Algorithm Comparison

| Algorithm | Security | Speed | Salt | Crackable | Recommended |
|-----------|----------|-------|------|-----------|-------------|
| MD5 | ❌ Broken | ⚡ Very Fast | ❌ No | ✅ Yes | ❌ No |
| SHA-1 | ❌ Broken | ⚡ Fast | ❌ No | ✅ Yes | ❌ No |
| SHA-256 | ✅ Secure | ⚡ Fast | ❌ No | ✅ Yes | ✅ Yes |
| SHA-512 | ✅ Secure | ⚡ Moderate | ❌ No | ✅ Yes | ✅ Yes |
| NTLM | ❌ Weak | ⚡ Very Fast | ❌ No | ✅ Yes | ❌ No |
| bcrypt | ✅ Secure | 🐌 Slow | ✅ Yes | ❌ No | ✅ Yes |
| PBKDF2 | ✅ Secure | 🐌 Slow | ✅ Yes | ❌ No | ✅ Yes |

## Performance Characteristics

### Hash Rate Benchmarks
Typical performance on modern hardware (8-core CPU):

| Algorithm | Hashes/Second | Relative Speed |
|-----------|---------------|----------------|
| MD5 | ~50,000,000 | 100% |
| SHA-1 | ~35,000,000 | 70% |
| SHA-256 | ~20,000,000 | 40% |
| SHA-512 | ~15,000,000 | 30% |
| NTLM | ~45,000,000 | 90% |
| bcrypt | ~50,000 | 0.1% |
| PBKDF2 | ~30,000 | 0.06% |

### Memory Requirements
- **Fast algorithms (MD5, SHA-1, SHA-256, SHA-512, NTLM)**: Minimal memory
- **Slow algorithms (bcrypt, PBKDF2)**: Higher memory due to iterations

## Usage Recommendations

### For New Systems
1. **Primary Choice**: bcrypt or PBKDF2
2. **Alternative**: SHA-256 or SHA-512 with salt
3. **Avoid**: MD5, SHA-1, NTLM

### For Legacy System Auditing
1. **Identify algorithm** used in the target system
2. **Understand limitations** of weak algorithms
3. **Document findings** for security assessment
4. **Recommend upgrades** to secure alternatives

### For Password Storage
1. **Use bcrypt** for general applications
2. **Use PBKDF2** for standards compliance
3. **Always include salt** with fast algorithms
4. **Configure appropriate work factors** for slow algorithms

## Security Best Practices

### When Auditing Hashes
1. **Verify algorithm identification** before attempting cracking
2. **Understand salt requirements** for each algorithm
3. **Consider computational cost** of slow algorithms
4. **Document security implications** of findings

### When Implementing Hashes
1. **Choose secure algorithms** (bcrypt, PBKDF2, Argon2)
2. **Use proper salting** techniques
3. **Configure appropriate work factors**
4. **Plan for algorithm migration**

### Migration Strategies
1. **Phase out weak algorithms** (MD5, SHA-1, NTLM)
2. **Implement secure alternatives**
3. **Use hash migration** techniques
4. **Update authentication systems**

## Common Issues and Solutions

### Hash Format Issues
- **Case sensitivity**: Most algorithms are case-insensitive
- **Whitespace**: Remove leading/trailing whitespace
- **Encoding**: Ensure consistent character encoding

### Salt Handling
- **Missing salt**: Required for bcrypt and PBKDF2 verification
- **Salt extraction**: Parse hash format correctly
- **Salt generation**: Use cryptographically secure random values

### Performance Optimization
- **Algorithm selection**: Choose appropriate algorithm for workload
- **Hardware utilization**: Use multiprocessing for fast algorithms
- **Memory management**: Stream large wordlists efficiently

## References

- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 8018 - PKCS #5: Password-Based Cryptography](https://tools.ietf.org/html/rfc8018)
- [bcrypt Paper - USENIX 1999](https://www.usenix.org/legacy/events/usenix99/full_papers/provos/provos_html/)

---

This documentation is intended for security professionals and system administrators responsible for password security and auditing.
