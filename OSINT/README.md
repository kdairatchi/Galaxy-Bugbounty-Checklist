# OSINT (Open Source Intelligence) Reconnaissance Checklist

## Overview
OSINT is the practice of collecting and analyzing publicly available information to gather intelligence about targets. This comprehensive checklist covers modern OSINT techniques, tools, and methodologies for bug bounty hunting and security research.

## Table of Contents
1. [Target Identification](#target-identification)
2. [Domain Intelligence](#domain-intelligence)
3. [Subdomain Enumeration](#subdomain-enumeration)
4. [Technology Stack Analysis](#technology-stack-analysis)
5. [Social Media Intelligence](#social-media-intelligence)
6. [Email Intelligence](#email-intelligence)
7. [Code Repository Analysis](#code-repository-analysis)
8. [Infrastructure Analysis](#infrastructure-analysis)
9. [Personnel Intelligence](#personnel-intelligence)
10. [Automation & Tools](#automation--tools)

---

## Target Identification

### 1. Company Information
- **Company Name**: Identify official company name
- **Legal Entity**: Find legal entity names
- **Acquisitions**: Research company acquisitions
- **Subsidiaries**: Identify subsidiaries and related companies
- **Business Relationships**: Map business partnerships

### 2. Brand Assets
- **Domain Names**: Identify all owned domains
- **Trademarks**: Research registered trademarks
- **Copyrights**: Find copyright information
- **Brand Variations**: Identify brand name variations
- **Logo Variations**: Find different logo versions

### 3. Contact Information
- **Email Addresses**: Collect email addresses
- **Phone Numbers**: Find phone numbers
- **Physical Addresses**: Identify physical locations
- **Social Media**: Find social media accounts
- **Contact Forms**: Identify contact forms

---

## Domain Intelligence

### 1. Domain Registration
- **WHOIS Lookup**: Perform WHOIS lookups
- **Registration History**: Check registration history
- **Expiration Dates**: Note domain expiration dates
- **Registrar Information**: Identify domain registrars
- **DNS Records**: Analyze DNS records

### 2. Domain Variations
- **Typosquatting**: Test common typos
- **Homograph Attacks**: Test homograph domains
- **Subdomain Variations**: Test subdomain patterns
- **TLD Variations**: Test different TLDs
- **Internationalized Domains**: Test IDN domains

### 3. Domain Monitoring
- **New Registrations**: Monitor new domain registrations
- **DNS Changes**: Monitor DNS record changes
- **Certificate Transparency**: Monitor SSL certificates
- **Domain Expiration**: Monitor domain expirations
- **Subdomain Takeovers**: Check for subdomain takeovers

---

## Subdomain Enumeration

### 1. Passive Enumeration
- **Certificate Transparency**: Use CT logs for subdomains
- **DNS Records**: Analyze DNS records for subdomains
- **Search Engines**: Use search engines for subdomains
- **Social Media**: Check social media for subdomains
- **Code Repositories**: Search code repos for subdomains

### 2. Active Enumeration
- **DNS Brute Force**: Brute force DNS subdomains
- **VHost Enumeration**: Enumerate virtual hosts
- **Port Scanning**: Scan common ports on subdomains
- **Service Detection**: Detect services on subdomains
- **Technology Detection**: Identify technologies used

### 3. Subdomain Takeover
- **CNAME Records**: Check CNAME records for takeovers
- **NS Records**: Check NS records for takeovers
- **MX Records**: Check MX records for takeovers
- **TXT Records**: Check TXT records for takeovers
- **Service Status**: Check service status for takeovers

---

## Technology Stack Analysis

### 1. Web Technologies
- **Web Servers**: Identify web servers (Apache, Nginx, IIS)
- **Application Servers**: Identify app servers (Tomcat, JBoss)
- **Frameworks**: Identify frameworks (Django, Rails, Spring)
- **CMS Systems**: Identify CMS (WordPress, Drupal)
- **E-commerce**: Identify e-commerce platforms

### 2. Programming Languages
- **Backend Languages**: Identify backend languages
- **Frontend Technologies**: Identify frontend technologies
- **Mobile Technologies**: Identify mobile technologies
- **API Technologies**: Identify API technologies
- **Database Technologies**: Identify database technologies

### 3. Security Technologies
- **WAF Solutions**: Identify WAF solutions
- **CDN Services**: Identify CDN services
- **DDoS Protection**: Identify DDoS protection
- **Security Headers**: Analyze security headers
- **SSL/TLS**: Analyze SSL/TLS configuration

---

## Social Media Intelligence

### 1. Platform Analysis
- **LinkedIn**: Analyze LinkedIn profiles and company pages
- **Twitter**: Monitor Twitter accounts and mentions
- **Facebook**: Analyze Facebook pages and groups
- **Instagram**: Check Instagram accounts
- **YouTube**: Analyze YouTube channels

### 2. Content Analysis
- **Posts and Updates**: Analyze posts and updates
- **Comments and Interactions**: Analyze comments and interactions
- **Hashtags**: Monitor relevant hashtags
- **Mentions**: Monitor mentions and tags
- **Geolocation**: Analyze geolocation data

### 3. Employee Intelligence
- **Employee Profiles**: Identify employee profiles
- **Job Postings**: Analyze job postings
- **Company Culture**: Understand company culture
- **Skills and Technologies**: Identify skills and technologies
- **Professional Networks**: Map professional networks

---

## Email Intelligence

### 1. Email Collection
- **Public Sources**: Collect emails from public sources
- **Social Media**: Extract emails from social media
- **Company Websites**: Extract emails from websites
- **Job Postings**: Extract emails from job postings
- **Press Releases**: Extract emails from press releases

### 2. Email Analysis
- **Email Patterns**: Analyze email patterns
- **Domain Analysis**: Analyze email domains
- **Email Validation**: Validate email addresses
- **Email Reputation**: Check email reputation
- **Email Security**: Analyze email security

### 3. Email Attacks
- **Phishing**: Test phishing resistance
- **Email Spoofing**: Test email spoofing
- **Email Bombing**: Test email bombing
- **Email Harvesting**: Test email harvesting
- **Email Validation**: Test email validation

---

## Code Repository Analysis

### 1. Repository Discovery
- **GitHub**: Search GitHub repositories
- **GitLab**: Search GitLab repositories
- **Bitbucket**: Search Bitbucket repositories
- **SourceForge**: Search SourceForge repositories
- **Private Repositories**: Search private repositories

### 2. Code Analysis
- **Source Code**: Analyze source code
- **Configuration Files**: Analyze configuration files
- **Documentation**: Analyze documentation
- **Commit History**: Analyze commit history
- **Issues and Pull Requests**: Analyze issues and PRs

### 3. Sensitive Information
- **API Keys**: Search for API keys
- **Passwords**: Search for passwords
- **Tokens**: Search for tokens
- **Credentials**: Search for credentials
- **Secrets**: Search for secrets

---

## Infrastructure Analysis

### 1. Network Infrastructure
- **IP Addresses**: Identify IP addresses
- **ASN Information**: Analyze ASN information
- **Network Ranges**: Identify network ranges
- **Routing Information**: Analyze routing information
- **Network Topology**: Map network topology

### 2. Server Infrastructure
- **Server Types**: Identify server types
- **Operating Systems**: Identify operating systems
- **Virtualization**: Identify virtualization technologies
- **Cloud Services**: Identify cloud services
- **Container Technologies**: Identify container technologies

### 3. Security Infrastructure
- **Firewalls**: Identify firewall technologies
- **Intrusion Detection**: Identify IDS/IPS systems
- **Security Monitoring**: Identify security monitoring
- **Incident Response**: Identify incident response capabilities
- **Security Policies**: Analyze security policies

---

## Personnel Intelligence

### 1. Employee Information
- **Employee Names**: Identify employee names
- **Job Titles**: Identify job titles
- **Departments**: Identify departments
- **Skills**: Identify skills and expertise
- **Contact Information**: Identify contact information

### 2. Executive Information
- **C-Level Executives**: Identify C-level executives
- **Board Members**: Identify board members
- **Key Personnel**: Identify key personnel
- **Decision Makers**: Identify decision makers
- **Influencers**: Identify influencers

### 3. Professional Networks
- **LinkedIn Networks**: Analyze LinkedIn networks
- **Professional Associations**: Identify professional associations
- **Industry Groups**: Identify industry groups
- **Conferences**: Identify conference participation
- **Publications**: Identify publications

---

## Automation & Tools

### 1. OSINT Tools
- **Maltego**: Use Maltego for OSINT
- **SpiderFoot**: Use SpiderFoot for OSINT
- **theHarvester**: Use theHarvester for OSINT
- **Recon-ng**: Use Recon-ng for OSINT
- **OSINT Framework**: Use OSINT Framework

### 2. Custom Scripts
- **Python Scripts**: Develop custom Python scripts
- **Bash Scripts**: Develop custom Bash scripts
- **PowerShell Scripts**: Develop custom PowerShell scripts
- **API Integrations**: Integrate with APIs
- **Data Processing**: Process collected data

### 3. Data Sources
- **Public APIs**: Use public APIs
- **Data Feeds**: Use data feeds
- **Web Scraping**: Use web scraping
- **Social Media APIs**: Use social media APIs
- **Search Engines**: Use search engines

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify target information
2. Map domain infrastructure
3. Enumerate subdomains
4. Analyze technology stack

### Phase 2: Intelligence Gathering
1. Collect social media intelligence
2. Analyze code repositories
3. Gather personnel information
4. Map infrastructure

### Phase 3: Analysis
1. Analyze collected data
2. Identify attack vectors
3. Map attack surface
4. Document findings

---

## Common OSINT Techniques

### 1. Search Engine Queries
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:api
site:target.com inurl:test
```

### 2. Social Media Queries
```
"target.com" site:linkedin.com
"target.com" site:twitter.com
"target.com" site:facebook.com
"target.com" site:instagram.com
"target.com" site:youtube.com
```

### 3. Code Repository Queries
```
"target.com" site:github.com
"target.com" site:gitlab.com
"target.com" site:bitbucket.org
"target.com" site:sourceforge.net
"target.com" site:code.google.com
```

---

## References
- [OSINT Framework](https://osintframework.com/)
- [OSINT Techniques](https://github.com/lockfale/OSINT-Framework)
- [OSINT Tools](https://github.com/Ph055a/OSINT_Collection)
- [OSINT Methodology](https://github.com/0xmaximus/Galaxy-Bugbounty-Checklist)
- [OSINT Resources](https://github.com/cipher387/osint_stuff_tool_collection)