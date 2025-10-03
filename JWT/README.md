# JWT (JSON Web Token) Vulnerability Checklist

## Overview
JSON Web Tokens (JWT) are a compact, URL-safe means of representing claims to be transferred between two parties. This comprehensive checklist covers modern JWT vulnerabilities, bypass techniques, and exploitation methods for bug bounty hunting and security research.

## Table of Contents
1. [Understanding JWT](#understanding-jwt)
2. [Algorithm Confusion Attacks](#algorithm-confusion-attacks)
3. [Signature Bypass](#signature-bypass)
4. [Key Confusion Attacks](#key-confusion-attacks)
5. [Timing Attacks](#timing-attacks)
6. [Token Manipulation](#token-manipulation)
7. [Implementation Vulnerabilities](#implementation-vulnerabilities)
8. [Advanced JWT Attacks](#advanced-jwt-attacks)
9. [Automation & Tools](#automation--tools)

---

## Understanding JWT

### 1. JWT Structure
- **Header**: Contains metadata about the token
- **Payload**: Contains the claims (data)
- **Signature**: Used to verify the token's integrity
- **Base64 Encoding**: All parts are Base64 encoded
- **Dot Separation**: Parts are separated by dots (.)

### 2. JWT Algorithms
- **HMAC**: Symmetric key algorithms (HS256, HS384, HS512)
- **RSA**: Asymmetric key algorithms (RS256, RS384, RS512)
- **ECDSA**: Elliptic curve algorithms (ES256, ES384, ES512)
- **None**: No signature (none algorithm)
- **Custom**: Custom algorithms

### 3. Common Vulnerabilities
- **Algorithm Confusion**: Confuse algorithm handling
- **Signature Bypass**: Bypass signature verification
- **Key Confusion**: Confuse key handling
- **Timing Attacks**: Exploit timing vulnerabilities
- **Token Manipulation**: Manipulate token contents

---

## Algorithm Confusion Attacks

### 1. None Algorithm Attack
- **None Algorithm**: Use "none" algorithm to bypass signature
- **Algorithm Confusion**: Confuse algorithm handling
- **Signature Bypass**: Bypass signature verification
- **Key Confusion**: Confuse key handling
- **Implementation Bypass**: Bypass implementation checks

### 2. Algorithm Substitution
- **HS256 to RS256**: Substitute HS256 with RS256
- **RS256 to HS256**: Substitute RS256 with HS256
- **Algorithm Downgrade**: Downgrade to weaker algorithms
- **Algorithm Upgrade**: Upgrade to stronger algorithms
- **Algorithm Confusion**: Confuse algorithm implementation

### 3. Algorithm Bypass
- **Algorithm Bypass**: Bypass algorithm validation
- **Algorithm Injection**: Inject malicious algorithms
- **Algorithm Confusion**: Confuse algorithm handling
- **Algorithm Timing**: Exploit algorithm timing
- **Algorithm Weaknesses**: Exploit algorithm weaknesses

---

## Signature Bypass

### 1. Signature Removal
- **Signature Removal**: Remove signature from token
- **Signature Truncation**: Truncate signature
- **Signature Manipulation**: Manipulate signature
- **Signature Confusion**: Confuse signature handling
- **Signature Bypass**: Bypass signature verification

### 2. Signature Validation
- **Signature Validation**: Bypass signature validation
- **Signature Timing**: Exploit signature timing
- **Signature Weaknesses**: Exploit signature weaknesses
- **Signature Confusion**: Confuse signature implementation
- **Signature Injection**: Inject malicious signatures

### 3. Signature Attacks
- **Signature Forgery**: Forge signatures
- **Signature Replay**: Replay signatures
- **Signature Timing**: Exploit signature timing
- **Signature Weaknesses**: Exploit signature weaknesses
- **Signature Confusion**: Confuse signature handling

---

## Key Confusion Attacks

### 1. Public Key Confusion
- **Public Key Confusion**: Confuse public key handling
- **Public Key Injection**: Inject malicious public keys
- **Public Key Timing**: Exploit public key timing
- **Public Key Weaknesses**: Exploit public key weaknesses
- **Public Key Bypass**: Bypass public key validation

### 2. Private Key Confusion
- **Private Key Confusion**: Confuse private key handling
- **Private Key Injection**: Inject malicious private keys
- **Private Key Timing**: Exploit private key timing
- **Private Key Weaknesses**: Exploit private key weaknesses
- **Private Key Bypass**: Bypass private key validation

### 3. Key Management
- **Key Management**: Exploit key management issues
- **Key Rotation**: Exploit key rotation issues
- **Key Storage**: Exploit key storage issues
- **Key Transmission**: Exploit key transmission issues
- **Key Validation**: Exploit key validation issues

---

## Timing Attacks

### 1. Signature Timing
- **Signature Timing**: Exploit signature timing
- **Algorithm Timing**: Exploit algorithm timing
- **Key Timing**: Exploit key timing
- **Validation Timing**: Exploit validation timing
- **Processing Timing**: Exploit processing timing

### 2. Comparison Timing
- **String Comparison**: Exploit string comparison timing
- **Hash Comparison**: Exploit hash comparison timing
- **Key Comparison**: Exploit key comparison timing
- **Signature Comparison**: Exploit signature comparison timing
- **Token Comparison**: Exploit token comparison timing

### 3. Timing Bypass
- **Timing Bypass**: Bypass timing protections
- **Timing Confusion**: Confuse timing implementation
- **Timing Weaknesses**: Exploit timing weaknesses
- **Timing Injection**: Inject timing attacks
- **Timing Manipulation**: Manipulate timing behavior

---

## Token Manipulation

### 1. Header Manipulation
- **Algorithm Manipulation**: Manipulate algorithm in header
- **Key ID Manipulation**: Manipulate key ID in header
- **Header Injection**: Inject malicious headers
- **Header Confusion**: Confuse header handling
- **Header Bypass**: Bypass header validation

### 2. Payload Manipulation
- **Claim Manipulation**: Manipulate claims in payload
- **Expiration Manipulation**: Manipulate expiration claims
- **Issuer Manipulation**: Manipulate issuer claims
- **Audience Manipulation**: Manipulate audience claims
- **Subject Manipulation**: Manipulate subject claims

### 3. Signature Manipulation
- **Signature Manipulation**: Manipulate signature
- **Signature Injection**: Inject malicious signatures
- **Signature Confusion**: Confuse signature handling
- **Signature Bypass**: Bypass signature validation
- **Signature Forgery**: Forge signatures

---

## Implementation Vulnerabilities

### 1. Library Vulnerabilities
- **Library Vulnerabilities**: Exploit library vulnerabilities
- **Library Confusion**: Confuse library implementation
- **Library Timing**: Exploit library timing
- **Library Weaknesses**: Exploit library weaknesses
- **Library Bypass**: Bypass library protections

### 2. Framework Vulnerabilities
- **Framework Vulnerabilities**: Exploit framework vulnerabilities
- **Framework Confusion**: Confuse framework implementation
- **Framework Timing**: Exploit framework timing
- **Framework Weaknesses**: Exploit framework weaknesses
- **Framework Bypass**: Bypass framework protections

### 3. Custom Implementation
- **Custom Implementation**: Exploit custom implementation
- **Custom Confusion**: Confuse custom implementation
- **Custom Timing**: Exploit custom timing
- **Custom Weaknesses**: Exploit custom weaknesses
- **Custom Bypass**: Bypass custom protections

---

## Advanced JWT Attacks

### 1. Token Chaining
- **Token Chaining**: Chain multiple tokens
- **Token Confusion**: Confuse token handling
- **Token Timing**: Exploit token timing
- **Token Weaknesses**: Exploit token weaknesses
- **Token Bypass**: Bypass token validation

### 2. Token Replay
- **Token Replay**: Replay tokens
- **Token Confusion**: Confuse token handling
- **Token Timing**: Exploit token timing
- **Token Weaknesses**: Exploit token weaknesses
- **Token Bypass**: Bypass token validation

### 3. Token Injection
- **Token Injection**: Inject malicious tokens
- **Token Confusion**: Confuse token handling
- **Token Timing**: Exploit token timing
- **Token Weaknesses**: Exploit token weaknesses
- **Token Bypass**: Bypass token validation

---

## Automation & Tools

### 1. Manual Testing Tools
- **JWT.io**: Use JWT.io for token analysis
- **Burp Suite**: Use Burp Suite for JWT testing
- **OWASP ZAP**: Use OWASP ZAP for JWT scanning
- **Custom Scripts**: Develop custom JWT testing scripts

### 2. Automated Testing
- **JWT Scanner**: Use automated JWT scanners
- **Fuzzing**: Use fuzzing techniques for JWT
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **JWT Templates**: Use JWT attack templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for JWT testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify JWT implementation
2. Map JWT structure
3. Identify JWT endpoints
4. Map JWT operations

### Phase 2: Vulnerability Assessment
1. Test algorithm confusion attacks
2. Test signature bypass
3. Test key confusion attacks
4. Test timing attacks

### Phase 3: Exploitation
1. Attempt JWT attacks
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### None Algorithm Payloads
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

### Algorithm Confusion Payloads
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Signature Bypass Payloads
```json
{
  "alg": "none",
  "typ": "JWT"
}
```

---

## References
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)
- [JWT Security Considerations](https://tools.ietf.org/html/rfc7519)
- [JWT Vulnerability Examples](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JWT)
- [JWT Security Testing](https://github.com/dolevf/jwt-security-testing)
- [JWT Attack Vectors](https://github.com/dolevf/jwt-attack-vectors)