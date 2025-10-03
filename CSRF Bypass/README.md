# CSRF Bypass Vulnerability Checklist

## Overview
Cross-Site Request Forgery (CSRF) attacks exploit the trust that a web application has in a user's browser. This comprehensive checklist covers modern CSRF bypass techniques and defense circumvention methods.

## Table of Contents
1. [Basic CSRF Bypass Techniques](#basic-csrf-bypass-techniques)
2. [Token-based Bypass](#token-based-bypass)
3. [Header-based Bypass](#header-based-bypass)
4. [Referer-based Bypass](#referer-based-bypass)
5. [SameSite Cookie Bypass](#samesite-cookie-bypass)
6. [Advanced Bypass Techniques](#advanced-bypass-techniques)
7. [Framework-specific Bypass](#framework-specific-bypass)
8. [Automation & Tools](#automation--tools)

---

## Basic CSRF Bypass Techniques

### 1. Token Manipulation
- **Change Single Character**: Modify one character in the CSRF token
  ```
  Original: csrf_token=abc123def456
  Modified: csrf_token=abc123def457
  ```
- **Empty Token Value**: Send empty CSRF token
  ```
  csrf_token=
  ```
- **Replace with Same Length**: Replace token with same length string
  ```
  Original: csrf_token=abc123def456
  Modified: csrf_token=000000000000
  ```

### 2. Parameter Manipulation
- **Remove CSRF Parameter**: Completely remove CSRF parameter
- **Use Another User's Token**: Test with valid tokens from other users
- **Duplicate Parameters**: Add duplicate CSRF parameters
  ```
  csrf_token=valid_token&csrf_token=invalid_token
  ```

### 3. HTTP Method Changes
- **POST to GET**: Change POST requests to GET
- **GET to POST**: Change GET requests to POST
- **Custom Methods**: Try custom HTTP methods
  ```
  METHOD: CUSTOM
  ```

---

## Token-based Bypass

### 1. Token Prediction
- **Time-based Tokens**: Test if tokens are time-predictable
- **Sequential Tokens**: Test if tokens are sequential
- **Weak Randomization**: Test token entropy
- **Token Reuse**: Test if tokens can be reused

### 2. Token Extraction
- **XSS to Extract Tokens**: Use XSS to extract CSRF tokens
  ```javascript
  fetch('/sensitive-action', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
    }
  });
  ```
- **Error Messages**: Check error messages for token information
- **Source Code**: Check source code for token patterns

### 3. Token Bypass Techniques
- **Hash Decryption**: Try to decrypt hashed tokens
- **Token Substitution**: Substitute tokens with known patterns
- **Token Injection**: Inject tokens into different parameters

---

## Header-based Bypass

### 1. Referer Header Bypass
- **Remove Referer Header**: Remove the Referer header entirely
  ```html
  <meta name="referrer" content="no-referrer">
  ```
- **Subdomain Bypass**: Use subdomain confusion
  ```
  Referer: https://victim.com.attacker.com
  ```
- **Protocol Bypass**: Change protocol in Referer
  ```
  Referer: http://victim.com (instead of https://)
  ```

### 2. Origin Header Bypass
- **Origin Spoofing**: Spoof the Origin header
- **Null Origin**: Use null origin
  ```
  Origin: null
  ```
- **Cross-Origin**: Test cross-origin scenarios

### 3. Custom Header Bypass
- **X-Forwarded-For**: Test X-Forwarded-For header
- **X-Real-IP**: Test X-Real-IP header
- **X-Originating-IP**: Test X-Originating-IP header

---

## Referer-based Bypass

### 1. Referer Validation Bypass
- **Empty Referer**: Send empty Referer header
- **Malformed Referer**: Send malformed Referer
- **Subdomain Confusion**: Use subdomain attacks
  ```
  Referer: https://victim.com.attacker.com
  Referer: https://attacker.com/victim.com
  ```

### 2. Referer Header Manipulation
- **Protocol Downgrade**: Change HTTPS to HTTP
- **Port Manipulation**: Add/remove ports
- **Path Manipulation**: Manipulate paths in Referer

---

## SameSite Cookie Bypass

### 1. SameSite Attribute Bypass
- **Lax Mode**: Test SameSite=Lax bypass
- **Strict Mode**: Test SameSite=Strict bypass
- **None Mode**: Test SameSite=None bypass

### 2. Cookie Manipulation
- **Cookie Injection**: Inject cookies via XSS
- **Cookie Override**: Override existing cookies
- **Cookie Deletion**: Delete protective cookies

---

## Advanced Bypass Techniques

### 1. Clickjacking
- **Hidden Forms**: Use hidden forms for CSRF
- **Iframe Attacks**: Use iframe-based attacks
- **Drag and Drop**: Test drag-and-drop CSRF

### 2. File Upload CSRF
- **Malicious File Upload**: Upload malicious files via CSRF
- **File Type Bypass**: Bypass file type restrictions
- **Path Traversal**: Test path traversal in file uploads

### 3. JSON CSRF
- **Content-Type Bypass**: Change Content-Type to bypass JSON CSRF
  ```
  Content-Type: text/plain
  ```
- **JSONP Attacks**: Use JSONP for CSRF
- **CORS Bypass**: Bypass CORS restrictions

---

## Framework-specific Bypass

### 1. Django CSRF Bypass
- **CSRF_COOKIE_HTTPONLY**: Test HttpOnly cookie bypass
- **CSRF_COOKIE_SECURE**: Test Secure cookie bypass
- **CSRF_TRUSTED_ORIGINS**: Test trusted origins bypass

### 2. Rails CSRF Bypass
- **protect_from_forgery**: Test Rails CSRF protection
- **authenticity_token**: Test authenticity token bypass
- **CSRF Meta Tags**: Test CSRF meta tag bypass

### 3. Laravel CSRF Bypass
- **VerifyCsrfToken**: Test Laravel CSRF middleware
- **X-CSRF-TOKEN**: Test X-CSRF-TOKEN header bypass
- **_token Parameter**: Test _token parameter bypass

---

## Automation & Tools

### 1. Manual Testing Tools
- **Burp Suite**: Use Burp Suite for CSRF testing
- **OWASP ZAP**: Use OWASP ZAP for CSRF scanning
- **Custom Scripts**: Develop custom CSRF testing scripts

### 2. Automated Testing
- **CSRF Scanner**: Use automated CSRF scanners
- **Fuzzing**: Use fuzzing techniques for CSRF
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **CSRF Templates**: Use CSRF attack templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for CSRF testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify CSRF-protected endpoints
2. Map CSRF protection mechanisms
3. Identify token generation patterns
4. Map session management

### Phase 2: Vulnerability Assessment
1. Test basic CSRF bypass techniques
2. Test token-based bypass
3. Test header-based bypass
4. Test advanced techniques

### Phase 3: Exploitation
1. Attempt CSRF attacks
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### HTML Form Payloads
```html
<form action="https://target.com/sensitive-action" method="POST">
  <input type="hidden" name="csrf_token" value="bypassed_token">
  <input type="hidden" name="action" value="delete_account">
  <input type="submit" value="Click me">
</form>
```

### JavaScript Payloads
```javascript
fetch('/sensitive-action', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-CSRF-Token': 'bypassed_token'
  },
  body: 'action=delete_account'
});
```

### XMLHttpRequest Payloads
```javascript
var xhr = new XMLHttpRequest();
xhr.open('POST', '/sensitive-action', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.setRequestHeader('X-CSRF-Token', 'bypassed_token');
xhr.send('action=delete_account');
```

---

## Defense Bypass Techniques

### 1. Double Submit Cookie Bypass
- **Cookie Manipulation**: Manipulate CSRF cookies
- **Cookie Injection**: Inject cookies via XSS
- **Cookie Override**: Override existing cookies

### 2. Origin Header Bypass
- **Origin Spoofing**: Spoof Origin header
- **Null Origin**: Use null origin
- **Cross-Origin**: Test cross-origin scenarios

### 3. Custom Header Bypass
- **Header Injection**: Inject custom headers
- **Header Override**: Override existing headers
- **Header Spoofing**: Spoof headers

---

## References
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [HackerOne CSRF Reports](https://hackerone.com/reports?search=csrf)
- [CSRF Bypass Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20injection)
