# WebSocket Vulnerability Checklist

## Overview
WebSocket is a computer communications protocol that provides full-duplex communication channels over a single TCP connection. This comprehensive checklist covers modern WebSocket vulnerabilities, bypass techniques, and exploitation methods for bug bounty hunting and security research.

## Table of Contents
1. [Understanding WebSocket](#understanding-websocket)
2. [Authentication Bypass](#authentication-bypass)
3. [Authorization Issues](#authorization-issues)
4. [Message Injection](#message-injection)
5. [Denial of Service](#denial-of-service)
6. [Information Disclosure](#information-disclosure)
7. [Session Management](#session-management)
8. [Advanced WebSocket Attacks](#advanced-websocket-attacks)
9. [Automation & Tools](#automation--tools)

---

## Understanding WebSocket

### 1. WebSocket Protocol
- **Handshake**: Initial HTTP handshake
- **Upgrade**: Protocol upgrade from HTTP to WebSocket
- **Frames**: Data transmission in frames
- **Ping/Pong**: Keep-alive mechanism
- **Close**: Connection termination

### 2. WebSocket Features
- **Full-Duplex**: Bidirectional communication
- **Low Latency**: Real-time communication
- **Persistent Connection**: Long-lived connections
- **Binary Support**: Binary data transmission
- **Cross-Origin**: Cross-origin communication

### 3. Common Vulnerabilities
- **Authentication Bypass**: Bypass authentication mechanisms
- **Authorization Issues**: Authorization bypass
- **Message Injection**: Inject malicious messages
- **Denial of Service**: Cause service disruption
- **Information Disclosure**: Expose sensitive information

---

## Authentication Bypass

### 1. Handshake Bypass
- **Handshake Manipulation**: Manipulate handshake process
- **Header Injection**: Inject malicious headers
- **Protocol Confusion**: Confuse protocol handling
- **Timing Attacks**: Exploit timing vulnerabilities
- **Race Conditions**: Exploit race conditions

### 2. Token Bypass
- **Token Manipulation**: Manipulate authentication tokens
- **Token Injection**: Inject malicious tokens
- **Token Confusion**: Confuse token handling
- **Token Timing**: Exploit token timing
- **Token Weaknesses**: Exploit token weaknesses

### 3. Session Bypass
- **Session Manipulation**: Manipulate session handling
- **Session Injection**: Inject malicious sessions
- **Session Confusion**: Confuse session handling
- **Session Timing**: Exploit session timing
- **Session Weaknesses**: Exploit session weaknesses

---

## Authorization Issues

### 1. Role Bypass
- **Role Manipulation**: Manipulate user roles
- **Role Injection**: Inject malicious roles
- **Role Confusion**: Confuse role handling
- **Role Timing**: Exploit role timing
- **Role Weaknesses**: Exploit role weaknesses

### 2. Permission Bypass
- **Permission Manipulation**: Manipulate permissions
- **Permission Injection**: Inject malicious permissions
- **Permission Confusion**: Confuse permission handling
- **Permission Timing**: Exploit permission timing
- **Permission Weaknesses**: Exploit permission weaknesses

### 3. Access Control
- **Access Control Bypass**: Bypass access controls
- **Access Control Confusion**: Confuse access control implementation
- **Access Control Timing**: Exploit access control timing
- **Access Control Weaknesses**: Exploit access control weaknesses
- **Access Control Injection**: Inject malicious access controls

---

## Message Injection

### 1. SQL Injection
- **SQL Injection**: Inject SQL queries
- **NoSQL Injection**: Inject NoSQL queries
- **Query Injection**: Inject database queries
- **Command Injection**: Inject system commands
- **Code Injection**: Inject malicious code

### 2. XSS Injection
- **XSS Injection**: Inject cross-site scripting
- **DOM XSS**: Inject DOM-based XSS
- **Stored XSS**: Inject stored XSS
- **Reflected XSS**: Inject reflected XSS
- **Blind XSS**: Inject blind XSS

### 3. Template Injection
- **Template Injection**: Inject template code
- **SSTI**: Server-side template injection
- **CSTI**: Client-side template injection
- **Template Confusion**: Confuse template handling
- **Template Weaknesses**: Exploit template weaknesses

---

## Denial of Service

### 1. Resource Exhaustion
- **Memory Exhaustion**: Exhaust server memory
- **CPU Exhaustion**: Exhaust server CPU
- **Connection Exhaustion**: Exhaust server connections
- **Bandwidth Exhaustion**: Exhaust server bandwidth
- **Storage Exhaustion**: Exhaust server storage

### 2. Message Flooding
- **Message Flooding**: Flood server with messages
- **Large Messages**: Send large messages
- **Rapid Messages**: Send messages rapidly
- **Binary Messages**: Send binary messages
- **Malformed Messages**: Send malformed messages

### 3. Connection Attacks
- **Connection Flooding**: Flood server with connections
- **Slow Connections**: Create slow connections
- **Persistent Connections**: Create persistent connections
- **Connection Confusion**: Confuse connection handling
- **Connection Weaknesses**: Exploit connection weaknesses

---

## Information Disclosure

### 1. Error Messages
- **Error Messages**: Expose error messages
- **Stack Traces**: Expose stack traces
- **Debug Information**: Expose debug information
- **Internal Information**: Expose internal information
- **Sensitive Information**: Expose sensitive information

### 2. Data Leakage
- **Data Leakage**: Leak sensitive data
- **Data Injection**: Inject sensitive data
- **Data Confusion**: Confuse data handling
- **Data Timing**: Exploit data timing
- **Data Weaknesses**: Exploit data weaknesses

### 3. Metadata Exposure
- **Metadata Exposure**: Expose metadata
- **Metadata Injection**: Inject malicious metadata
- **Metadata Confusion**: Confuse metadata handling
- **Metadata Timing**: Exploit metadata timing
- **Metadata Weaknesses**: Exploit metadata weaknesses

---

## Session Management

### 1. Session Hijacking
- **Session Hijacking**: Hijack user sessions
- **Session Fixation**: Fix session tokens
- **Session Confusion**: Confuse session handling
- **Session Timing**: Exploit session timing
- **Session Weaknesses**: Exploit session weaknesses

### 2. Session Manipulation
- **Session Manipulation**: Manipulate session data
- **Session Injection**: Inject malicious session data
- **Session Confusion**: Confuse session implementation
- **Session Timing**: Exploit session timing
- **Session Weaknesses**: Exploit session weaknesses

### 3. Session Validation
- **Session Validation**: Bypass session validation
- **Session Confusion**: Confuse session validation
- **Session Timing**: Exploit session validation timing
- **Session Weaknesses**: Exploit session validation weaknesses
- **Session Injection**: Inject malicious session validation

---

## Advanced WebSocket Attacks

### 1. Protocol Confusion
- **Protocol Confusion**: Confuse protocol handling
- **Protocol Injection**: Inject malicious protocol data
- **Protocol Timing**: Exploit protocol timing
- **Protocol Weaknesses**: Exploit protocol weaknesses
- **Protocol Bypass**: Bypass protocol protections

### 2. Frame Manipulation
- **Frame Manipulation**: Manipulate WebSocket frames
- **Frame Injection**: Inject malicious frames
- **Frame Confusion**: Confuse frame handling
- **Frame Timing**: Exploit frame timing
- **Frame Weaknesses**: Exploit frame weaknesses

### 3. Handshake Attacks
- **Handshake Attacks**: Attack WebSocket handshake
- **Handshake Injection**: Inject malicious handshake data
- **Handshake Confusion**: Confuse handshake handling
- **Handshake Timing**: Exploit handshake timing
- **Handshake Weaknesses**: Exploit handshake weaknesses

---

## Automation & Tools

### 1. Manual Testing Tools
- **WebSocket King**: Use WebSocket King for testing
- **Burp Suite**: Use Burp Suite for WebSocket testing
- **OWASP ZAP**: Use OWASP ZAP for WebSocket scanning
- **Custom Scripts**: Develop custom WebSocket testing scripts

### 2. Automated Testing
- **WebSocket Scanner**: Use automated WebSocket scanners
- **Fuzzing**: Use fuzzing techniques for WebSocket
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **WebSocket Templates**: Use WebSocket attack templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for WebSocket testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify WebSocket implementation
2. Map WebSocket endpoints
3. Identify WebSocket operations
4. Map WebSocket protocol

### Phase 2: Vulnerability Assessment
1. Test authentication bypass
2. Test authorization issues
3. Test message injection
4. Test denial of service

### Phase 3: Exploitation
1. Attempt WebSocket attacks
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### Authentication Bypass Payloads
```javascript
// Token manipulation
{
  "token": "",
  "token": "admin",
  "token": "bypass",
  "token": "null",
  "token": "undefined"
}
```

### Message Injection Payloads
```javascript
// SQL injection
{
  "query": "SELECT * FROM users WHERE id = 1 OR 1=1",
  "query": "SELECT * FROM users WHERE id = 1 UNION SELECT 1,2,3",
  "query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;"
}
```

### XSS Injection Payloads
```javascript
// XSS injection
{
  "message": "<script>alert('XSS')</script>",
  "message": "<img src=x onerror=alert('XSS')>",
  "message": "javascript:alert('XSS')"
}
```

---

## References
- [WebSocket Security Best Practices](https://tools.ietf.org/html/rfc6455)
- [WebSocket Security Considerations](https://tools.ietf.org/html/rfc6455#section-10)
- [WebSocket Vulnerability Examples](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/WebSocket)
- [WebSocket Security Testing](https://github.com/dolevf/websocket-security-testing)
- [WebSocket Attack Vectors](https://github.com/dolevf/websocket-attack-vectors)