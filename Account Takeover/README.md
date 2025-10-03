# Account Takeover (ATO) Vulnerability Checklist

## Overview
Account Takeover vulnerabilities allow attackers to gain unauthorized access to user accounts, potentially leading to data theft, financial fraud, and unauthorized actions. This comprehensive checklist covers modern ATO techniques and bypass methods.

## Table of Contents
1. [Authentication Bypass](#authentication-bypass)
2. [Password Reset Vulnerabilities](#password-reset-vulnerabilities)
3. [Email-based Attacks](#email-based-attacks)
4. [Session Management Issues](#session-management-issues)
5. [Multi-Factor Authentication Bypass](#multi-factor-authentication-bypass)
6. [OAuth/SSO Vulnerabilities](#oauthsso-vulnerabilities)
7. [API-based ATO](#api-based-ato)
8. [Advanced Techniques](#advanced-techniques)
9. [Automation & Tools](#automation--tools)

---

## Authentication Bypass

### 1. Registration Bypass
- **Duplicate Email Registration**: Try registering with existing emails
  ```
  POST /register
  email=victim@target.com
  password=newpassword123
  ```
- **Case Sensitivity Issues**: Test email case variations
  ```
  victim@target.com
  Victim@target.com
  VICTIM@target.com
  ```
- **Email Domain Variations**: Test subdomain/domain confusion
  ```
  victim@target.com
  victim@target.co.uk
  victim@target.org
  ```

### 2. Login Bypass Techniques
- **SQL Injection in Login**: Test for SQLi in username/password fields
  ```sql
  username: admin'--
  password: anything
  username: admin' OR '1'='1'--
  username: admin' UNION SELECT 1,2,3--
  ```
- **NoSQL Injection**: Test for NoSQL injection
  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
  ```
- **LDAP Injection**: Test LDAP-based authentication
  ```
  username: *)(uid=*))(|(uid=*
  username: admin)(&(password=*)
  ```

### 3. Session Fixation
- **Session ID Prediction**: Analyze session ID patterns
- **Session Hijacking**: Test for weak session management
- **Concurrent Sessions**: Test multiple session handling

---

## Password Reset Vulnerabilities

### 1. Token-based Reset Issues
- **Weak Token Generation**: Test token predictability
- **Token Reuse**: Test if tokens can be reused
- **Token Expiration**: Test token expiration handling
- **Race Conditions**: Test concurrent reset requests

### 2. Email-based Reset Bypass
- **Email Enumeration**: Test if emails can be enumerated
- **Email Spoofing**: Test email header manipulation
- **Email Forwarding**: Test email forwarding scenarios
- **Subdomain Confusion**: Test email subdomain attacks

### 3. Phone-based Reset Issues
- **SMS Interception**: Test SMS-based reset
- **Phone Number Enumeration**: Test phone number discovery
- **SIM Swapping**: Test SIM swap scenarios
- **VoIP Bypass**: Test VoIP number handling

---

## Email-based Attacks

### 1. Email Confusion Attacks
- **Domain Confusion**: Test similar domains
  ```
  target.com vs target.co.uk
  target.com vs target.org
  ```
- **Subdomain Confusion**: Test subdomain attacks
  ```
  victim@target.com vs victim@mail.target.com
  ```
- **Email Aliasing**: Test email alias handling
  ```
  victim+test@target.com
  victim.test@target.com
  ```

### 2. Email Header Manipulation
- **From Header Spoofing**: Test email header spoofing
- **Reply-To Manipulation**: Test reply-to header attacks
- **Return-Path Bypass**: Test return-path manipulation

---

## Session Management Issues

### 1. Session Token Vulnerabilities
- **Weak Randomization**: Test session token entropy
- **Predictable Tokens**: Test token predictability
- **Token Reuse**: Test token reuse scenarios
- **Concurrent Sessions**: Test multiple session handling

### 2. Cookie-based Attacks
- **Cookie Manipulation**: Test cookie modification
- **Cookie Injection**: Test cookie injection attacks
- **HttpOnly Bypass**: Test HttpOnly cookie bypass
- **Secure Flag Bypass**: Test secure flag bypass

---

## Multi-Factor Authentication Bypass

### 1. 2FA Bypass Techniques
- **Backup Codes**: Test backup code handling
- **Recovery Methods**: Test recovery method bypass
- **Time-based Attacks**: Test TOTP timing attacks
- **SMS Interception**: Test SMS-based 2FA

### 2. MFA Implementation Issues
- **Missing MFA**: Test if MFA can be bypassed
- **Weak MFA**: Test weak MFA implementations
- **MFA Bypass**: Test MFA bypass techniques

---

## OAuth/SSO Vulnerabilities

### 1. OAuth Flow Issues
- **Authorization Code Flow**: Test authorization code handling
- **Implicit Flow**: Test implicit flow vulnerabilities
- **PKCE Bypass**: Test PKCE implementation
- **State Parameter**: Test state parameter handling

### 2. SSO Bypass Techniques
- **SAML Bypass**: Test SAML implementation
- **JWT Vulnerabilities**: Test JWT handling
- **OpenID Connect**: Test OpenID Connect issues

---

## API-based ATO

### 1. API Authentication Issues
- **API Key Exposure**: Test API key handling
- **JWT Vulnerabilities**: Test JWT implementation
- **OAuth Token Issues**: Test OAuth token handling

### 2. API Endpoint Vulnerabilities
- **User Enumeration**: Test user enumeration via API
- **Password Reset API**: Test password reset endpoints
- **Account Modification**: Test account modification APIs

---

## Advanced Techniques

### 1. Business Logic Bypass
- **Account Linking**: Test account linking vulnerabilities
- **Account Merging**: Test account merging issues
- **Account Deletion**: Test account deletion bypass

### 2. Social Engineering
- **Phishing**: Test phishing resistance
- **Social Proof**: Test social proof vulnerabilities
- **Authority Bypass**: Test authority-based bypass

---

## Automation & Tools

### 1. Manual Testing Tools
- **Burp Suite**: Use Burp Suite for manual testing
- **OWASP ZAP**: Use OWASP ZAP for vulnerability scanning
- **Postman**: Use Postman for API testing

### 2. Automated Testing
- **Custom Scripts**: Develop custom testing scripts
- **Fuzzing**: Use fuzzing techniques
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Wordlists
- **Common Passwords**: Use common password lists
- **Email Patterns**: Use email pattern lists
- **Username Lists**: Use username enumeration lists

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify authentication endpoints
2. Map user registration flow
3. Identify password reset mechanisms
4. Map session management

### Phase 2: Vulnerability Assessment
1. Test authentication bypass
2. Test password reset vulnerabilities
3. Test session management
4. Test MFA implementation

### Phase 3: Exploitation
1. Attempt account takeover
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### SQL Injection Payloads
```sql
' OR '1'='1'--
' OR 1=1--
' UNION SELECT 1,2,3--
' AND (SELECT 6377 FROM (SELECT(SLEEP(5)))hLTl)--
```

### NoSQL Injection Payloads
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### LDAP Injection Payloads
```
*)(uid=*))(|(uid=*
admin)(&(password=*)
*)(|(password=*)
```

---

## References
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PortSwigger Authentication Bypass](https://portswigger.net/web-security/authentication)
- [HackerOne ATO Reports](https://hackerone.com/reports?search=account%20takeover)
- [Bug Bounty Methodology](https://github.com/OWASP/wstg)
