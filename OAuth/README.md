# OAuth Vulnerability Checklist

## Overview
OAuth (Open Authorization) is an authorization framework that allows applications to obtain limited access to user accounts. This comprehensive checklist covers modern OAuth vulnerabilities, bypass techniques, and exploitation methods for bug bounty hunting and security research.

## Table of Contents
1. [Understanding OAuth](#understanding-oauth)
2. [OAuth Flow Vulnerabilities](#oauth-flow-vulnerabilities)
3. [Authorization Code Flow Issues](#authorization-code-flow-issues)
4. [Implicit Flow Vulnerabilities](#implicit-flow-vulnerabilities)
5. [PKCE Bypass Techniques](#pkce-bypass-techniques)
6. [State Parameter Issues](#state-parameter-issues)
7. [Token-based Vulnerabilities](#token-based-vulnerabilities)
8. [Advanced OAuth Attacks](#advanced-oauth-attacks)
9. [Automation & Tools](#automation--tools)

---

## Understanding OAuth

### 1. OAuth Components
- **Client**: Application requesting access
- **Authorization Server**: Server that issues access tokens
- **Resource Server**: Server that hosts protected resources
- **Resource Owner**: User who owns the resources
- **Redirect URI**: Where to redirect after authorization

### 2. OAuth Flows
- **Authorization Code Flow**: Most secure flow for web applications
- **Implicit Flow**: Less secure flow for single-page applications
- **Client Credentials Flow**: For server-to-server communication
- **Device Flow**: For devices with limited input capabilities
- **Refresh Token Flow**: For obtaining new access tokens

### 3. Common Vulnerabilities
- **Open Redirect**: Redirect to malicious URLs
- **State Parameter Bypass**: Bypass CSRF protection
- **Token Leakage**: Expose access tokens
- **Scope Escalation**: Access unauthorized scopes
- **Client Impersonation**: Impersonate legitimate clients

---

## OAuth Flow Vulnerabilities

### 1. Authorization Code Flow Issues
- **Code Interception**: Intercept authorization codes
- **Code Reuse**: Reuse authorization codes
- **Code Prediction**: Predict authorization codes
- **Code Injection**: Inject malicious codes
- **Code Timing**: Exploit timing vulnerabilities

### 2. Implicit Flow Vulnerabilities
- **Token Exposure**: Expose access tokens in URLs
- **Token Interception**: Intercept access tokens
- **Token Reuse**: Reuse access tokens
- **Token Prediction**: Predict access tokens
- **Token Injection**: Inject malicious tokens

### 3. Client Credentials Flow Issues
- **Credential Leakage**: Leak client credentials
- **Credential Reuse**: Reuse client credentials
- **Credential Prediction**: Predict client credentials
- **Credential Injection**: Inject malicious credentials
- **Credential Timing**: Exploit timing vulnerabilities

---

## Authorization Code Flow Issues

### 1. Code Interception
- **Man-in-the-Middle**: Intercept authorization codes
- **Network Sniffing**: Sniff authorization codes
- **Proxy Attacks**: Use proxies to intercept codes
- **DNS Hijacking**: Hijack DNS to intercept codes
- **ARP Spoofing**: Use ARP spoofing to intercept codes

### 2. Code Reuse
- **Code Replay**: Replay authorization codes
- **Code Sharing**: Share authorization codes
- **Code Caching**: Cache authorization codes
- **Code Storage**: Store authorization codes
- **Code Transmission**: Transmit authorization codes

### 3. Code Prediction
- **Sequential Codes**: Predict sequential codes
- **Time-based Codes**: Predict time-based codes
- **Pattern Analysis**: Analyze code patterns
- **Brute Force**: Brute force authorization codes
- **Cryptographic Weaknesses**: Exploit cryptographic weaknesses

---

## Implicit Flow Vulnerabilities

### 1. Token Exposure
- **URL Fragments**: Expose tokens in URL fragments
- **Browser History**: Store tokens in browser history
- **Referrer Headers**: Expose tokens in referrer headers
- **Log Files**: Log tokens in log files
- **Error Messages**: Expose tokens in error messages

### 2. Token Interception
- **Network Sniffing**: Sniff access tokens
- **Proxy Attacks**: Use proxies to intercept tokens
- **DNS Hijacking**: Hijack DNS to intercept tokens
- **ARP Spoofing**: Use ARP spoofing to intercept tokens
- **Man-in-the-Middle**: Intercept access tokens

### 3. Token Reuse
- **Token Replay**: Replay access tokens
- **Token Sharing**: Share access tokens
- **Token Caching**: Cache access tokens
- **Token Storage**: Store access tokens
- **Token Transmission**: Transmit access tokens

---

## PKCE Bypass Techniques

### 1. Code Challenge Bypass
- **Challenge Prediction**: Predict code challenges
- **Challenge Reuse**: Reuse code challenges
- **Challenge Injection**: Inject malicious challenges
- **Challenge Timing**: Exploit timing vulnerabilities
- **Challenge Weaknesses**: Exploit challenge weaknesses

### 2. Code Verifier Bypass
- **Verifier Prediction**: Predict code verifiers
- **Verifier Reuse**: Reuse code verifiers
- **Verifier Injection**: Inject malicious verifiers
- **Verifier Timing**: Exploit timing vulnerabilities
- **Verifier Weaknesses**: Exploit verifier weaknesses

### 3. PKCE Implementation Issues
- **Missing PKCE**: Missing PKCE implementation
- **Weak PKCE**: Weak PKCE implementation
- **PKCE Bypass**: Bypass PKCE protection
- **PKCE Confusion**: Confuse PKCE implementation
- **PKCE Timing**: Exploit PKCE timing

---

## State Parameter Issues

### 1. State Parameter Bypass
- **Missing State**: Missing state parameter
- **Weak State**: Weak state parameter
- **State Reuse**: Reuse state parameters
- **State Prediction**: Predict state parameters
- **State Injection**: Inject malicious state parameters

### 2. State Parameter Validation
- **State Validation**: Validate state parameters
- **State Timing**: Exploit state timing
- **State Storage**: Store state parameters
- **State Transmission**: Transmit state parameters
- **State Confusion**: Confuse state implementation

### 3. CSRF Protection
- **CSRF Bypass**: Bypass CSRF protection
- **CSRF Weaknesses**: Exploit CSRF weaknesses
- **CSRF Timing**: Exploit CSRF timing
- **CSRF Confusion**: Confuse CSRF implementation
- **CSRF Injection**: Inject malicious CSRF tokens

---

## Token-based Vulnerabilities

### 1. Access Token Issues
- **Token Leakage**: Leak access tokens
- **Token Reuse**: Reuse access tokens
- **Token Prediction**: Predict access tokens
- **Token Injection**: Inject malicious tokens
- **Token Timing**: Exploit token timing

### 2. Refresh Token Issues
- **Refresh Token Leakage**: Leak refresh tokens
- **Refresh Token Reuse**: Reuse refresh tokens
- **Refresh Token Prediction**: Predict refresh tokens
- **Refresh Token Injection**: Inject malicious refresh tokens
- **Refresh Token Timing**: Exploit refresh token timing

### 3. ID Token Issues
- **ID Token Leakage**: Leak ID tokens
- **ID Token Reuse**: Reuse ID tokens
- **ID Token Prediction**: Predict ID tokens
- **ID Token Injection**: Inject malicious ID tokens
- **ID Token Timing**: Exploit ID token timing

---

## Advanced OAuth Attacks

### 1. Scope Escalation
- **Scope Bypass**: Bypass scope restrictions
- **Scope Injection**: Inject malicious scopes
- **Scope Confusion**: Confuse scope implementation
- **Scope Timing**: Exploit scope timing
- **Scope Weaknesses**: Exploit scope weaknesses

### 2. Client Impersonation
- **Client ID Spoofing**: Spoof client IDs
- **Client Secret Leakage**: Leak client secrets
- **Client Confusion**: Confuse client implementation
- **Client Timing**: Exploit client timing
- **Client Weaknesses**: Exploit client weaknesses

### 3. Authorization Server Attacks
- **Server Impersonation**: Impersonate authorization servers
- **Server Confusion**: Confuse server implementation
- **Server Timing**: Exploit server timing
- **Server Weaknesses**: Exploit server weaknesses
- **Server Injection**: Inject malicious server responses

---

## Automation & Tools

### 1. Manual Testing Tools
- **Burp Suite**: Use Burp Suite for OAuth testing
- **OWASP ZAP**: Use OWASP ZAP for OAuth scanning
- **Custom Scripts**: Develop custom OAuth testing scripts

### 2. Automated Testing
- **OAuth Scanner**: Use automated OAuth scanners
- **Fuzzing**: Use fuzzing techniques for OAuth
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **OAuth Templates**: Use OAuth attack templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for OAuth testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify OAuth implementation
2. Map OAuth flows
3. Identify OAuth endpoints
4. Map OAuth parameters

### Phase 2: Vulnerability Assessment
1. Test OAuth flow vulnerabilities
2. Test token-based vulnerabilities
3. Test state parameter issues
4. Test advanced attacks

### Phase 3: Exploitation
1. Attempt OAuth attacks
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### OAuth Redirect Payloads
```
https://target.com/oauth/authorize?client_id=123&redirect_uri=https://attacker.com&response_type=code&scope=read&state=random
https://target.com/oauth/authorize?client_id=123&redirect_uri=https://target.com.attacker.com&response_type=code&scope=read&state=random
https://target.com/oauth/authorize?client_id=123&redirect_uri=https://attacker.com/target.com&response_type=code&scope=read&state=random
```

### OAuth State Parameter Payloads
```
state=
state=random
state=1234567890
state=attacker_controlled
state=javascript:alert(1)
```

### OAuth Scope Payloads
```
scope=read
scope=write
scope=admin
scope=read write admin
scope=*
scope=read,write,admin
```

---

## References
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 Threat Model](https://tools.ietf.org/html/rfc6819)
- [OAuth 2.0 Security Considerations](https://tools.ietf.org/html/rfc6749#section-10)
- [OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
- [OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)
