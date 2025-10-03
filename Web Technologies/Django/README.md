# Django Application Vulnerability Checklist

## Overview
Django is a high-level Python web framework that encourages rapid development and clean, pragmatic design. This comprehensive checklist covers Django-specific vulnerabilities, security misconfigurations, and exploitation techniques for bug bounty hunting and security research.

## Table of Contents
1. [Understanding Django Security](#understanding-django-security)
2. [Authentication Vulnerabilities](#authentication-vulnerabilities)
3. [Authorization Issues](#authorization-issues)
4. [Template Vulnerabilities](#template-vulnerabilities)
5. [ORM Vulnerabilities](#orm-vulnerabilities)
6. [Configuration Issues](#configuration-issues)
7. [Middleware Vulnerabilities](#middleware-vulnerabilities)
8. [Advanced Django Attacks](#advanced-django-attacks)
9. [Automation & Tools](#automation--tools)

---

## Understanding Django Security

### 1. Django Security Model
- **Model-View-Template**: Django's MVC architecture
- **ORM**: Object-Relational Mapping
- **Template Engine**: Django template system
- **Middleware**: Request/response processing
- **Authentication**: Built-in authentication system

### 2. Common Attack Vectors
- **SQL Injection**: ORM-based SQL injection
- **Template Injection**: Server-side template injection
- **CSRF**: Cross-site request forgery
- **XSS**: Cross-site scripting
- **Authentication Bypass**: Django auth bypass

### 3. Security Considerations
- **Input Validation**: Django form validation
- **Output Encoding**: Template auto-escaping
- **CSRF Protection**: CSRF middleware
- **Authentication**: Django auth framework
- **Authorization**: Django permissions system

---

## Authentication Vulnerabilities

### 1. Django Auth Bypass
- **Session Fixation**: Django session fixation
- **Session Hijacking**: Django session hijacking
- **Authentication Bypass**: Bypassing Django auth
- **Password Reset**: Django password reset issues
- **User Enumeration**: Django user enumeration

### 2. Session Management
- **Session Manipulation**: Manipulating Django sessions
- **Session Injection**: Injecting malicious sessions
- **Session Confusion**: Confusing session handling
- **Session Timing**: Exploiting session timing
- **Session Weaknesses**: Exploiting session weaknesses

### 3. User Management
- **User Injection**: Injecting malicious users
- **User Manipulation**: Manipulating user data
- **User Confusion**: Confusing user handling
- **User Timing**: Exploiting user timing
- **User Weaknesses**: Exploiting user weaknesses

---

## Authorization Issues

### 1. Permission Bypass
- **Permission Injection**: Injecting malicious permissions
- **Permission Manipulation**: Manipulating permissions
- **Permission Confusion**: Confusing permission handling
- **Permission Timing**: Exploiting permission timing
- **Permission Weaknesses**: Exploiting permission weaknesses

### 2. Group Management
- **Group Injection**: Injecting malicious groups
- **Group Manipulation**: Manipulating groups
- **Group Confusion**: Confusing group handling
- **Group Timing**: Exploiting group timing
- **Group Weaknesses**: Exploiting group weaknesses

### 3. Role-Based Access Control
- **Role Injection**: Injecting malicious roles
- **Role Manipulation**: Manipulating roles
- **Role Confusion**: Confusing role handling
- **Role Timing**: Exploiting role timing
- **Role Weaknesses**: Exploiting role weaknesses

---

## Template Vulnerabilities

### 1. Server-Side Template Injection
- **Template Injection**: Injecting malicious templates
- **Template Manipulation**: Manipulating templates
- **Template Confusion**: Confusing template handling
- **Template Timing**: Exploiting template timing
- **Template Weaknesses**: Exploiting template weaknesses

### 2. Template Auto-Escaping
- **Auto-Escaping Bypass**: Bypassing auto-escaping
- **Auto-Escaping Confusion**: Confusing auto-escaping
- **Auto-Escaping Timing**: Exploiting auto-escaping timing
- **Auto-Escaping Weaknesses**: Exploiting auto-escaping weaknesses
- **Auto-Escaping Injection**: Injecting malicious auto-escaping

### 3. Template Filters
- **Filter Injection**: Injecting malicious filters
- **Filter Manipulation**: Manipulating filters
- **Filter Confusion**: Confusing filter handling
- **Filter Timing**: Exploiting filter timing
- **Filter Weaknesses**: Exploiting filter weaknesses

---

## ORM Vulnerabilities

### 1. SQL Injection via ORM
- **ORM Injection**: Injecting malicious ORM queries
- **ORM Manipulation**: Manipulating ORM queries
- **ORM Confusion**: Confusing ORM handling
- **ORM Timing**: Exploiting ORM timing
- **ORM Weaknesses**: Exploiting ORM weaknesses

### 2. QuerySet Vulnerabilities
- **QuerySet Injection**: Injecting malicious QuerySets
- **QuerySet Manipulation**: Manipulating QuerySets
- **QuerySet Confusion**: Confusing QuerySet handling
- **QuerySet Timing**: Exploiting QuerySet timing
- **QuerySet Weaknesses**: Exploiting QuerySet weaknesses

### 3. Model Vulnerabilities
- **Model Injection**: Injecting malicious models
- **Model Manipulation**: Manipulating models
- **Model Confusion**: Confusing model handling
- **Model Timing**: Exploiting model timing
- **Model Weaknesses**: Exploiting model weaknesses

---

## Configuration Issues

### 1. Settings Vulnerabilities
- **Settings Injection**: Injecting malicious settings
- **Settings Manipulation**: Manipulating settings
- **Settings Confusion**: Confusing settings handling
- **Settings Timing**: Exploiting settings timing
- **Settings Weaknesses**: Exploiting settings weaknesses

### 2. Environment Variables
- **Env Injection**: Injecting malicious environment variables
- **Env Manipulation**: Manipulating environment variables
- **Env Confusion**: Confusing environment variable handling
- **Env Timing**: Exploiting environment variable timing
- **Env Weaknesses**: Exploiting environment variable weaknesses

### 3. Database Configuration
- **DB Injection**: Injecting malicious database config
- **DB Manipulation**: Manipulating database config
- **DB Confusion**: Confusing database config handling
- **DB Timing**: Exploiting database config timing
- **DB Weaknesses**: Exploiting database config weaknesses

---

## Middleware Vulnerabilities

### 1. CSRF Middleware
- **CSRF Bypass**: Bypassing CSRF middleware
- **CSRF Injection**: Injecting malicious CSRF tokens
- **CSRF Confusion**: Confusing CSRF handling
- **CSRF Timing**: Exploiting CSRF timing
- **CSRF Weaknesses**: Exploiting CSRF weaknesses

### 2. Security Middleware
- **Security Bypass**: Bypassing security middleware
- **Security Injection**: Injecting malicious security headers
- **Security Confusion**: Confusing security handling
- **Security Timing**: Exploiting security timing
- **Security Weaknesses**: Exploiting security weaknesses

### 3. Custom Middleware
- **Custom Middleware Injection**: Injecting malicious custom middleware
- **Custom Middleware Manipulation**: Manipulating custom middleware
- **Custom Middleware Confusion**: Confusing custom middleware handling
- **Custom Middleware Timing**: Exploiting custom middleware timing
- **Custom Middleware Weaknesses**: Exploiting custom middleware weaknesses

---

## Advanced Django Attacks

### 1. Admin Interface
- **Admin Bypass**: Bypassing Django admin
- **Admin Injection**: Injecting malicious admin data
- **Admin Confusion**: Confusing admin handling
- **Admin Timing**: Exploiting admin timing
- **Admin Weaknesses**: Exploiting admin weaknesses

### 2. REST Framework
- **DRF Injection**: Injecting malicious DRF data
- **DRF Manipulation**: Manipulating DRF data
- **DRF Confusion**: Confusing DRF handling
- **DRF Timing**: Exploiting DRF timing
- **DRF Weaknesses**: Exploiting DRF weaknesses

### 3. Celery Tasks
- **Celery Injection**: Injecting malicious Celery tasks
- **Celery Manipulation**: Manipulating Celery tasks
- **Celery Confusion**: Confusing Celery handling
- **Celery Timing**: Exploiting Celery timing
- **Celery Weaknesses**: Exploiting Celery weaknesses

---

## Automation & Tools

### 1. Manual Testing Tools
- **Django Debug Toolbar**: Use Django Debug Toolbar for analysis
- **Burp Suite**: Use Burp Suite for Django testing
- **OWASP ZAP**: Use OWASP ZAP for Django scanning
- **Custom Scripts**: Develop custom Django testing scripts

### 2. Automated Testing
- **Django Scanner**: Use automated Django scanners
- **Fuzzing**: Use fuzzing techniques for Django
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **Django Templates**: Use Django attack templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for Django testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify Django implementation
2. Map Django models and views
3. Identify Django settings
4. Map Django middleware

### Phase 2: Vulnerability Assessment
1. Test authentication vulnerabilities
2. Test authorization issues
3. Test template vulnerabilities
4. Test ORM vulnerabilities

### Phase 3: Exploitation
1. Attempt Django attacks
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### Template Injection Payloads
```python
# SSTI payloads
{{7*7}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### ORM Injection Payloads
```python
# ORM injection
User.objects.filter(username__contains=user_input)
User.objects.extra(where=["username = '%s'" % user_input])
```

### CSRF Bypass Payloads
```html
<!-- CSRF bypass -->
<form action="/admin/users/delete/1/" method="post">
  <input type="hidden" name="csrfmiddlewaretoken" value="">
  <input type="submit" value="Delete">
</form>
```

---

## References
- [Django Security Best Practices](https://docs.djangoproject.com/en/stable/topics/security/)
- [Django Security Considerations](https://docs.djangoproject.com/en/stable/topics/security/)
- [Django Vulnerability Examples](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Django)
- [Django Security Testing](https://github.com/dolevf/django-security-testing)
- [Django Attack Vectors](https://github.com/dolevf/django-attack-vectors)