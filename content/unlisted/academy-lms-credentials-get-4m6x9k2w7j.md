---
title: "Credentials Exposure via GET Parameters in Academy LMS Login API"
date: 2025-07-20
tags: ["security", "information-disclosure", "academy-lms", "credentials"]
categories: ["Security Research"]
draft: false
url: "/academy-lms-credentials-get-4m6x9k2w7j/"
_build:
  list: false
  render: true
  publishResources: true
sitemap:
  disable: true
---

## Overview

A security vulnerability has been discovered in Academy LMS versions up to and including 5.13, where the login API accepts sensitive authentication credentials via GET parameters, causing usernames and passwords to be logged in server access logs and browser history.

## Technical Details

**CVE ID:** [CVE-2025-56751](https://nvd.nist.gov/vuln/detail/CVE-2025-56751)  
**CVSS Score:** 6.7 (Medium)  
**Affected Versions:** Academy LMS ≤ v5.13  
**Vulnerability Type:** Information Disclosure / Insecure Data Transmission  

### Affected Components
- File: `lms/application/controllers/Api.php:165`
- File: `lms/application/models/Api_model.php:login_get()`

### Affected Endpoint
- `GET /lms/api/login`

### Vulnerability Description

The Academy LMS login API incorrectly accepts authentication credentials through GET parameters instead of POST body data. This design flaw causes sensitive information including usernames and passwords to be stored in server access logs, browser history, proxy logs, and potentially exposed through HTTP referrer headers.

### Vulnerable Source Code

```php
// From lms/application/controllers/Api.php:165-169
// Login Api
public function login_get()
{
  $userdata = $this->api_model->login_get();
  if ($userdata['validity'] == 1) {
    $userdata['token'] = $this->tokenHandler->GenerateToken($userdata);
  }
  $this->set_response($userdata, REST_Controller::HTTP_OK);
}

// The model processes GET parameters instead of POST data
// From lms/application/models/Api_model.php
public function login_get() {
  $email = $this->input->get('email');        // Vulnerable: GET parameter
  $password = $this->input->get('password');  // Vulnerable: GET parameter
  // ... authentication logic
}
```

## Impact

Sensitive authentication credentials can be compromised through:

1. **Server Access Logs** - Plaintext credentials logged in web server access logs
2. **Browser History** - Credentials stored in user's browser history  
3. **Proxy Logs** - Corporate proxies logging full URLs with credentials
4. **HTTP Referrer Headers** - Credentials leaked when navigating to external sites
5. **Analytics Systems** - Web analytics platforms capturing URLs with sensitive data
6. **Network Monitoring** - Network administrators intercepting unencrypted URLs

## Affected Endpoint Details

### Vulnerable Implementation
```
GET /lms/api/login?email=user@example.com&password=secretpassword
```

The API accepts credentials via URL parameters, which violates security best practices for handling sensitive data.

## Proof of Concept

### 1. Credential Exposure in Server Logs
```bash
# User logs in via GET request
curl "https://target.com/lms/api/login?email=admin@target.com&password=supersecret123"

# Credentials are logged in server access log
tail /var/log/apache2/access.log
# Output: GET /lms/api/login?email=admin@target.com&password=supersecret123 [timestamp] [IP]
```

### 2. Browser History Exposure
```javascript
// Login request stores credentials in browser history
window.location.href = "https://target.com/lms/api/login?email=user@test.com&password=mypassword";

// Credentials accessible via browser history
console.log(window.history);
```

### 3. Referrer Header Leakage
```html
<!-- User navigates to external site after login -->
<a href="https://external-analytics.com">View Analytics</a>

<!-- external-analytics.com receives referrer header with credentials -->
Referer: https://target.com/lms/api/login?email=user@test.com&password=mypassword
```

## Attack Scenarios

### Scenario 1: Server Administrator Access
Malicious server administrators can extract user credentials from access logs:

```bash
# Extract credentials from access logs
grep "/lms/api/login" /var/log/apache2/access.log | \
  grep -oP "email=[^&]*&password=[^&]*" | \
  sed 's/email=//g; s/&password=/:/g'

# Output:
# admin@target.com:supersecret123
# user@example.com:password123
# instructor@site.com:mypassword
```

### Scenario 2: Shared Computer Attack
Attackers with physical access to shared computers can extract credentials from browser history:

```sql
-- Chrome browser history extraction
SELECT url FROM urls 
WHERE url LIKE '%/lms/api/login%' 
AND url LIKE '%password=%';
```

### Scenario 3: Corporate Network Monitoring
In corporate environments, network administrators can capture credentials from HTTP traffic logs:

```bash
# Network traffic analysis
tcpdump -A -s 0 'tcp port 80 and host target.com' | grep "GET /lms/api/login"
```

### Scenario 4: Analytics Platform Data Breach
If web analytics platforms are compromised, credentials become exposed:

```javascript
// Analytics tracking may capture full URL with credentials
gtag('config', 'GA_TRACKING_ID', {
  'page_location': window.location.href  // Contains credentials!
});
```

## Technical Analysis

### Current Vulnerable Implementation
```php
// In Api.php controller
public function login() {
    $email = $this->input->get('email');        // Vulnerable: GET parameter
    $password = $this->input->get('password');  // Vulnerable: GET parameter
    
    // Process login...
}
```

### Server Log Evidence
Typical server access log entry showing exposed credentials:
```
192.168.1.100 - - [20/Jul/2024:10:30:45 +0000] "GET /lms/api/login?email=admin%40target.com&password=AdminPass123 HTTP/1.1" 200 245 "-" "Mozilla/5.0..."
```

## Mitigation

### Immediate Fix
Change the login API to use POST method with credentials in request body:

```php
// Secure implementation
public function login() {
    // Only accept POST requests for login
    if ($this->input->method() !== 'post') {
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        return;
    }
    
    $email = $this->input->post('email');        // Secure: POST body
    $password = $this->input->post('password');  // Secure: POST body
    
    // Process login...
}
```

### Frontend Changes
Update client-side code to use POST requests:

```javascript
// Replace GET request
fetch('/lms/api/login?email=' + email + '&password=' + password);

// With secure POST request
fetch('/lms/api/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'email=' + encodeURIComponent(email) + 
          '&password=' + encodeURIComponent(password)
});
```

### Additional Security Measures

#### 1. Audit Existing Logs
```bash
# Search for exposed credentials in logs
grep -r "password=" /var/log/apache2/ | grep "GET"

# Remove or redact sensitive log entries
sed -i 's/password=[^&]*/password=REDACTED/g' /var/log/apache2/access.log
```

#### 2. Implement HTTPS
Ensure all authentication endpoints use HTTPS to encrypt transmission:

```apache
# Force HTTPS for login endpoints
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^lms/api/login(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
```

#### 3. Add Security Headers
```php
// Add security headers for login endpoints
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
```

#### 4. Implement Rate Limiting
```php
// Rate limit login attempts
$ip = $this->input->ip_address();
$attempts = $this->cache->get("login_attempts_$ip") ?: 0;

if ($attempts >= 5) {
    http_response_code(429);
    echo json_encode(['error' => 'Too many attempts']);
    return;
}
```

## Remediation Timeline

1. **Immediate (Day 1):**
   - Change login API to POST method
   - Update frontend authentication code
   
2. **Short Term (Week 1):**
   - Audit and clean server logs
   - Implement HTTPS enforcement
   - Add security headers
   
3. **Medium Term (Month 1):**
   - Implement comprehensive logging strategy
   - Add rate limiting mechanisms
   - Conduct security testing

## Timeline

- **Discovery:** July 2025 (During white box penetration testing)
- **Vendor Notification:** July 20, 2025 (Responsible disclosure to Creativeitem/Academy LMS team)
- **CVE Request Submitted:** July 20, 2025 (CVE number requested from MITRE)
- **Vendor Response:** Awaiting response from vendor
- **Public Disclosure:** July 20, 2025

*This vulnerability was discovered during a white box penetration test. Given that Academy LMS is a widely-used commercial template with many installations across different organizations, we decided to report this as a responsible disclosure to help protect all users of this platform.*

*This timeline will be updated accordingly as the responsible disclosure process progresses.*

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [RFC 7231: HTTP/1.1 Semantics and Content](https://tools.ietf.org/html/rfc7231)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Credit

This vulnerability was discovered and responsibly disclosed by the security research team at suryadina.com.

---
*This post is part of our ongoing security research into popular Learning Management Systems. For more security insights, visit [https://suryadina.com](https://suryadina.com).*
