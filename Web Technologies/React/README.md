# React Application Vulnerability Checklist

## Overview
React is a popular JavaScript library for building user interfaces. This comprehensive checklist covers React-specific vulnerabilities, security misconfigurations, and exploitation techniques for bug bounty hunting and security research.

## Table of Contents
1. [Understanding React Security](#understanding-react-security)
2. [Client-Side Vulnerabilities](#client-side-vulnerabilities)
3. [State Management Issues](#state-management-issues)
4. [Component Vulnerabilities](#component-vulnerabilities)
5. [Routing Vulnerabilities](#routing-vulnerabilities)
6. [API Integration Issues](#api-integration-issues)
7. [Build Configuration](#build-configuration)
8. [Advanced React Attacks](#advanced-react-attacks)
9. [Automation & Tools](#automation--tools)

---

## Understanding React Security

### 1. React Security Model
- **Client-Side Rendering**: React runs in the browser
- **Virtual DOM**: React's virtual DOM manipulation
- **Component Lifecycle**: Component mounting and unmounting
- **State Management**: Component and global state
- **Props System**: Data passing between components

### 2. Common Attack Vectors
- **XSS via JSX**: Cross-site scripting through JSX
- **State Injection**: Malicious state injection
- **Props Manipulation**: Props-based attacks
- **Event Handler Injection**: Event handler manipulation
- **Context Pollution**: React context pollution

### 3. Security Considerations
- **Input Sanitization**: Sanitizing user inputs
- **Output Encoding**: Encoding outputs
- **State Validation**: Validating component state
- **Props Validation**: Validating component props
- **Event Handler Security**: Securing event handlers

---

## Client-Side Vulnerabilities

### 1. XSS via JSX
- **Dangerously Set InnerHTML**: Using dangerouslySetInnerHTML
- **Template Injection**: Template-based XSS
- **Expression Injection**: JavaScript expression injection
- **Component Injection**: Component-based XSS
- **Event Handler XSS**: XSS via event handlers

### 2. State-Based XSS
- **State Injection**: Injecting malicious state
- **State Manipulation**: Manipulating component state
- **State Confusion**: Confusing state handling
- **State Timing**: Exploiting state timing
- **State Weaknesses**: Exploiting state weaknesses

### 3. Props-Based XSS
- **Props Injection**: Injecting malicious props
- **Props Manipulation**: Manipulating component props
- **Props Confusion**: Confusing props handling
- **Props Timing**: Exploiting props timing
- **Props Weaknesses**: Exploiting props weaknesses

---

## State Management Issues

### 1. Redux Vulnerabilities
- **State Injection**: Injecting malicious Redux state
- **Action Injection**: Injecting malicious Redux actions
- **Reducer Manipulation**: Manipulating Redux reducers
- **Middleware Injection**: Injecting malicious middleware
- **Store Manipulation**: Manipulating Redux store

### 2. Context Vulnerabilities
- **Context Injection**: Injecting malicious context
- **Context Manipulation**: Manipulating React context
- **Context Confusion**: Confusing context handling
- **Context Timing**: Exploiting context timing
- **Context Weaknesses**: Exploiting context weaknesses

### 3. Local State Issues
- **Local State Injection**: Injecting malicious local state
- **Local State Manipulation**: Manipulating local state
- **Local State Confusion**: Confusing local state handling
- **Local State Timing**: Exploiting local state timing
- **Local State Weaknesses**: Exploiting local state weaknesses

---

## Component Vulnerabilities

### 1. Component Injection
- **Dynamic Components**: Injecting dynamic components
- **Component Props**: Injecting malicious component props
- **Component State**: Injecting malicious component state
- **Component Methods**: Injecting malicious component methods
- **Component Lifecycle**: Exploiting component lifecycle

### 2. Higher-Order Components
- **HOC Injection**: Injecting malicious HOCs
- **HOC Manipulation**: Manipulating HOCs
- **HOC Confusion**: Confusing HOC handling
- **HOC Timing**: Exploiting HOC timing
- **HOC Weaknesses**: Exploiting HOC weaknesses

### 3. Render Props
- **Render Props Injection**: Injecting malicious render props
- **Render Props Manipulation**: Manipulating render props
- **Render Props Confusion**: Confusing render props handling
- **Render Props Timing**: Exploiting render props timing
- **Render Props Weaknesses**: Exploiting render props weaknesses

---

## Routing Vulnerabilities

### 1. React Router Issues
- **Route Injection**: Injecting malicious routes
- **Route Manipulation**: Manipulating routes
- **Route Confusion**: Confusing route handling
- **Route Timing**: Exploiting route timing
- **Route Weaknesses**: Exploiting route weaknesses

### 2. Navigation Attacks
- **Navigation Injection**: Injecting malicious navigation
- **Navigation Manipulation**: Manipulating navigation
- **Navigation Confusion**: Confusing navigation handling
- **Navigation Timing**: Exploiting navigation timing
- **Navigation Weaknesses**: Exploiting navigation weaknesses

### 3. History API Issues
- **History Manipulation**: Manipulating browser history
- **History Injection**: Injecting malicious history
- **History Confusion**: Confusing history handling
- **History Timing**: Exploiting history timing
- **History Weaknesses**: Exploiting history weaknesses

---

## API Integration Issues

### 1. Fetch API Vulnerabilities
- **Fetch Injection**: Injecting malicious fetch requests
- **Fetch Manipulation**: Manipulating fetch requests
- **Fetch Confusion**: Confusing fetch handling
- **Fetch Timing**: Exploiting fetch timing
- **Fetch Weaknesses**: Exploiting fetch weaknesses

### 2. Axios Vulnerabilities
- **Axios Injection**: Injecting malicious Axios requests
- **Axios Manipulation**: Manipulating Axios requests
- **Axios Confusion**: Confusing Axios handling
- **Axios Timing**: Exploiting Axios timing
- **Axios Weaknesses**: Exploiting Axios weaknesses

### 3. GraphQL Integration
- **GraphQL Injection**: Injecting malicious GraphQL queries
- **GraphQL Manipulation**: Manipulating GraphQL queries
- **GraphQL Confusion**: Confusing GraphQL handling
- **GraphQL Timing**: Exploiting GraphQL timing
- **GraphQL Weaknesses**: Exploiting GraphQL weaknesses

---

## Build Configuration

### 1. Webpack Vulnerabilities
- **Webpack Injection**: Injecting malicious Webpack config
- **Webpack Manipulation**: Manipulating Webpack config
- **Webpack Confusion**: Confusing Webpack handling
- **Webpack Timing**: Exploiting Webpack timing
- **Webpack Weaknesses**: Exploiting Webpack weaknesses

### 2. Babel Vulnerabilities
- **Babel Injection**: Injecting malicious Babel config
- **Babel Manipulation**: Manipulating Babel config
- **Babel Confusion**: Confusing Babel handling
- **Babel Timing**: Exploiting Babel timing
- **Babel Weaknesses**: Exploiting Babel weaknesses

### 3. Environment Variables
- **Env Injection**: Injecting malicious environment variables
- **Env Manipulation**: Manipulating environment variables
- **Env Confusion**: Confusing environment variable handling
- **Env Timing**: Exploiting environment variable timing
- **Env Weaknesses**: Exploiting environment variable weaknesses

---

## Advanced React Attacks

### 1. Server-Side Rendering
- **SSR Injection**: Injecting malicious SSR content
- **SSR Manipulation**: Manipulating SSR content
- **SSR Confusion**: Confusing SSR handling
- **SSR Timing**: Exploiting SSR timing
- **SSR Weaknesses**: Exploiting SSR weaknesses

### 2. Hydration Attacks
- **Hydration Injection**: Injecting malicious hydration data
- **Hydration Manipulation**: Manipulating hydration data
- **Hydration Confusion**: Confusing hydration handling
- **Hydration Timing**: Exploiting hydration timing
- **Hydration Weaknesses**: Exploiting hydration weaknesses

### 3. Code Splitting
- **Code Splitting Injection**: Injecting malicious code splits
- **Code Splitting Manipulation**: Manipulating code splits
- **Code Splitting Confusion**: Confusing code splitting handling
- **Code Splitting Timing**: Exploiting code splitting timing
- **Code Splitting Weaknesses**: Exploiting code splitting weaknesses

---

## Automation & Tools

### 1. Manual Testing Tools
- **React Developer Tools**: Use React DevTools for analysis
- **Burp Suite**: Use Burp Suite for React testing
- **OWASP ZAP**: Use OWASP ZAP for React scanning
- **Custom Scripts**: Develop custom React testing scripts

### 2. Automated Testing
- **React Scanner**: Use automated React scanners
- **Fuzzing**: Use fuzzing techniques for React
- **Reconnaissance**: Use reconnaissance tools

### 3. Payloads and Templates
- **React Templates**: Use React attack templates
- **Payload Generators**: Use payload generators
- **Wordlists**: Use wordlists for React testing

---

## Testing Methodology

### Phase 1: Reconnaissance
1. Identify React implementation
2. Map React components
3. Identify React state management
4. Map React routing

### Phase 2: Vulnerability Assessment
1. Test client-side vulnerabilities
2. Test state management issues
3. Test component vulnerabilities
4. Test routing vulnerabilities

### Phase 3: Exploitation
1. Attempt React attacks
2. Document findings
3. Test impact and scope
4. Report vulnerabilities

---

## Common Payloads

### JSX XSS Payloads
```jsx
// dangerouslySetInnerHTML XSS
<div dangerouslySetInnerHTML={{__html: userInput}} />

// Template injection
{`<img src=x onerror=alert('XSS')>`}

// Expression injection
{userInput && <div>{userInput}</div>}
```

### State Injection Payloads
```javascript
// State injection
this.setState({
  userInput: "<script>alert('XSS')</script>"
});

// Props injection
<Component userInput="<script>alert('XSS')</script>" />
```

### Event Handler Payloads
```jsx
// Event handler injection
<button onClick={userInput}>Click me</button>

// Event handler manipulation
<input onChange={userInput} />
```

---

## References
- [React Security Best Practices](https://reactjs.org/docs/security.html)
- [React Security Considerations](https://reactjs.org/docs/security.html)
- [React Vulnerability Examples](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/React)
- [React Security Testing](https://github.com/dolevf/react-security-testing)
- [React Attack Vectors](https://github.com/dolevf/react-attack-vectors)