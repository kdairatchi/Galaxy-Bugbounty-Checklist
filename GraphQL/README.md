# GraphQL Vulnerability Checklist

## Overview
GraphQL is a query language and runtime for APIs that provides a more efficient, powerful, and flexible alternative to REST. This comprehensive checklist covers modern GraphQL vulnerabilities, bypass techniques, and exploitation methods for bug bounty hunting and security research.

## Table of Contents
1. [Understanding GraphQL](#understanding-graphql)
2. [Query Complexity Attacks](#query-complexity-attacks)
3. [Depth-based Attacks](#depth-based-attacks)
4. [Introspection Vulnerabilities](#introspection-vulnerabilities)
5. [Authorization Bypass](#authorization-bypass)
6. [Data Exposure](#data-exposure)
7. [Injection Attacks](#injection-attacks)
8. [Advanced GraphQL Attacks](#advanced-graphql-attacks)
9. [Automation & Tools](#automation--tools)

---

## Understanding GraphQL

### 1. GraphQL Components
- **Schema**: Defines the structure of the API
- **Queries**: Read operations
- **Mutations**: Write operations
- **Subscriptions**: Real-time operations
- **Resolvers**: Functions that resolve queries

### 2. GraphQL Features
- **Single Endpoint**: All operations through one endpoint
- **Flexible Queries**: Clients specify exactly what data they need
- **Strong Typing**: Schema defines data types
- **Introspection**: Self-documenting API
- **Real-time**: Subscriptions for real-time updates

### 3. Common Vulnerabilities
- **Query Complexity**: Resource exhaustion attacks
- **Depth Attacks**: Deeply nested queries
- **Introspection**: Information disclosure
- **Authorization**: Bypass access controls
- **Injection**: Code injection attacks

---

## Query Complexity Attacks

### 1. Resource Exhaustion
- **Large Queries**: Send large queries to exhaust resources
- **Multiple Fields**: Request multiple fields simultaneously
- **Nested Queries**: Use deeply nested queries
- **Array Queries**: Request large arrays of data
- **Complex Filters**: Use complex filter operations

### 2. Query Complexity Bypass
- **Complexity Limits**: Bypass query complexity limits
- **Rate Limiting**: Bypass rate limiting controls
- **Timeout Bypass**: Bypass query timeout limits
- **Memory Exhaustion**: Exhaust server memory
- **CPU Exhaustion**: Exhaust server CPU

### 3. Query Optimization Attacks
- **Inefficient Queries**: Send inefficient queries
- **Redundant Queries**: Send redundant queries
- **Circular Queries**: Send circular queries
- **Infinite Loops**: Create infinite query loops
- **Resource Leaks**: Cause resource leaks

---

## Depth-based Attacks

### 1. Deep Nesting
- **Nested Objects**: Deeply nest object queries
- **Nested Arrays**: Deeply nest array queries
- **Nested Unions**: Deeply nest union queries
- **Nested Interfaces**: Deeply nest interface queries
- **Nested Fragments**: Deeply nest fragment queries

### 2. Depth Limit Bypass
- **Depth Limits**: Bypass depth limits
- **Recursive Queries**: Use recursive queries
- **Circular References**: Use circular references
- **Infinite Depth**: Create infinite depth queries
- **Depth Confusion**: Confuse depth implementation

### 3. Depth-based DoS
- **Stack Overflow**: Cause stack overflow
- **Memory Exhaustion**: Exhaust memory with depth
- **CPU Exhaustion**: Exhaust CPU with depth
- **Timeout Attacks**: Cause timeout attacks
- **Resource Exhaustion**: Exhaust resources

---

## Introspection Vulnerabilities

### 1. Schema Disclosure
- **Schema Introspection**: Expose schema information
- **Type Information**: Expose type information
- **Field Information**: Expose field information
- **Directive Information**: Expose directive information
- **Enum Information**: Expose enum information

### 2. Implementation Details
- **Resolver Information**: Expose resolver information
- **Database Schema**: Expose database schema
- **Business Logic**: Expose business logic
- **Internal APIs**: Expose internal APIs
- **Sensitive Data**: Expose sensitive data

### 3. Attack Surface Discovery
- **Available Queries**: Discover available queries
- **Available Mutations**: Discover available mutations
- **Available Subscriptions**: Discover available subscriptions
- **Available Fields**: Discover available fields
- **Available Arguments**: Discover available arguments

---

## Authorization Bypass

### 1. Field-level Authorization
- **Field Bypass**: Bypass field-level authorization
- **Field Injection**: Inject unauthorized fields
- **Field Confusion**: Confuse field authorization
- **Field Timing**: Exploit field timing
- **Field Weaknesses**: Exploit field weaknesses

### 2. Query-level Authorization
- **Query Bypass**: Bypass query-level authorization
- **Query Injection**: Inject unauthorized queries
- **Query Confusion**: Confuse query authorization
- **Query Timing**: Exploit query timing
- **Query Weaknesses**: Exploit query weaknesses

### 3. Mutation-level Authorization
- **Mutation Bypass**: Bypass mutation-level authorization
- **Mutation Injection**: Inject unauthorized mutations
- **Mutation Confusion**: Confuse mutation authorization
- **Mutation Timing**: Exploit mutation timing
- **Mutation Weaknesses**: Exploit mutation weaknesses

---

## Data Exposure

### 1. Sensitive Data Leakage
- **Data Leakage**: Leak sensitive data
- **Data Injection**: Inject sensitive data
- **Data Confusion**: Confuse data handling
- **Data Timing**: Exploit data timing
- **Data Weaknesses**: Exploit data weaknesses

### 2. Information Disclosure
- **Error Messages**: Expose error messages
- **Stack Traces**: Expose stack traces
- **Debug Information**: Expose debug information
- **Internal Information**: Expose internal information
- **Sensitive Information**: Expose sensitive information

### 3. Data Validation
- **Input Validation**: Bypass input validation
- **Output Validation**: Bypass output validation
- **Data Sanitization**: Bypass data sanitization
- **Data Encoding**: Bypass data encoding
- **Data Filtering**: Bypass data filtering

---

## Injection Attacks

### 1. SQL Injection
- **SQL Injection**: Inject SQL queries
- **NoSQL Injection**: Inject NoSQL queries
- **Query Injection**: Inject GraphQL queries
- **Mutation Injection**: Inject GraphQL mutations
- **Subscription Injection**: Inject GraphQL subscriptions

### 2. Code Injection
- **JavaScript Injection**: Inject JavaScript code
- **Python Injection**: Inject Python code
- **PHP Injection**: Inject PHP code
- **Java Injection**: Inject Java code
- **C# Injection**: Inject C# code

### 3. Template Injection
- **Template Injection**: Inject template code
- **SSTI**: Server-side template injection
- **CSTI**: Client-side template injection
- **Template Confusion**: Confuse template handling
- **Template Weaknesses**: Exploit template weaknesses

---

## Advanced GraphQL Attacks

### 1. Schema Poisoning
- **Schema Injection**: Inject malicious schema
- **Schema Confusion**: Confuse schema handling
- **Schema Timing**: Exploit schema timing
- **Schema Weaknesses**: Exploit schema weaknesses
- **Schema Bypass**: Bypass schema validation

### 2. Resolver Attacks
- **Resolver Injection**: Inject malicious resolvers
- **Resolver Confusion**: Confuse resolver handling
- **Resolver Timing**: Exploit resolver timing
- **Resolver Weaknesses**: Exploit resolver weaknesses
- **Resolver Bypass**: Bypass resolver validation

### 3. Subscription Attacks
- **Subscription Injection**: Inject malicious subscriptions
- **Subscription Confusion**: Confuse subscription handling
- **Subscription Timing**: Exploit subscription timing
- **Subscription Weaknesses**: Exploit subscription weaknesses
- **Subscription Bypass**: Bypass subscription validation

---

## Automation & Tools

### 1. Manual Testing Tools
- **GraphQL Playground**: Use GraphQL Playground for testing
- **Insomnia**: Use Insomnia for GraphQL testing
- **Postman**: Use Postman for GraphQL testing
- **Custom Scripts**: Develop custom GraphQL testing scripts

### 2. Automated Testing
- **GraphQL Scanner**: Use automated GraphQL scanners
- **Fuzzing**: Use fuzzing techniques for GraphQL
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **GraphQL Templates**: Use GraphQL attack templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for GraphQL testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify GraphQL implementation
2. Map GraphQL schema
3. Identify GraphQL endpoints
4. Map GraphQL operations

### Phase 2: Vulnerability Assessment
1. Test query complexity attacks
2. Test depth-based attacks
3. Test introspection vulnerabilities
4. Test authorization bypass

### Phase 3: Exploitation
1. Attempt GraphQL attacks
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### Query Complexity Payloads
```graphql
query {
  users {
    id
    name
    email
    posts {
      id
      title
      content
      comments {
        id
        text
        author {
          id
          name
          email
        }
      }
    }
  }
}
```

### Depth-based Payloads
```graphql
query {
  user {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author {
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### Introspection Payloads
```graphql
query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}
```

---

## References
- [GraphQL Security Best Practices](https://graphql.org/learn/best-practices/)
- [GraphQL Security Considerations](https://graphql.org/learn/security/)
- [GraphQL Vulnerability Examples](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL)
- [GraphQL Security Testing](https://github.com/dolevf/graphql-security-testing)
- [GraphQL Attack Vectors](https://github.com/dolevf/graphql-attack-vectors)