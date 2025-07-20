---
title: "JWT Token Exposure via URL Parameters in Academy LMS"
date: 2025-07-20
tags: ["security", "jwt", "academy-lms", "information-disclosure"]
categories: ["Security Research"]
draft: false
---

## Overview

A security vulnerability has been discovered in Academy LMS versions up to and including 5.13, where JWT authentication tokens are transmitted via URL parameters, leading to token exposure through various logging mechanisms.

## Technical Details

**CVE ID:** Pending Assignment  
**CVSS Score:** 6.7 (Medium)  
**Affected Versions:** Academy LMS ≤ v5.13  
**Vulnerability Type:** Information Disclosure / Token Exposure  

### Affected Component
- File: `lms/application/controllers/Api.php`
- Method: Uses `$_GET['auth_token']` for authentication

### Vulnerability Description

Multiple API endpoints in Academy LMS accept JWT authentication tokens as URL parameters instead of using standard HTTP Authorization headers. This design flaw causes sensitive authentication tokens to be logged in server access logs, stored in browser history, and potentially exposed through HTTP referrer headers.

### Vulnerable Source Code

```php
// From lms/application/controllers/Api.php:20-24
public function web_redirect_to_buy_course_get($auth_token = "", $course_id = "", $app_url = "")
{
  $this->load->library('session');
  $price = 0;
  if ($auth_token != "" && $course_id != "" && is_numeric($course_id)) {
    // Token passed as URL parameter instead of header
    $jwtData = $this->tokenHandler->DecodeToken($auth_token);
    // ... process request ...
  }
}

// Similar pattern in other endpoints that accept auth_token as GET parameter
```

## Impact

JWT tokens can be compromised through:
1. **Server Access Logs** - Tokens logged in web server access logs
2. **Browser History** - Tokens stored in user's browser history
3. **HTTP Referrer Headers** - Tokens leaked when navigating to external sites
4. **Proxy Logs** - Corporate proxies logging full URLs with tokens
5. **Analytics Systems** - Web analytics capturing URLs with sensitive data

Once an attacker obtains a valid JWT token, they can:
- Impersonate the legitimate user
- Access protected resources
- Perform actions on behalf of the victim

## Affected Endpoints

The following API endpoints transmit JWT tokens via URL parameters:

```
GET /lms/api/web_redirect_to_buy_course?auth_token=...
GET /lms/api/save_course_progress?auth_token=...
GET /lms/api/my_courses?auth_token=...
GET /lms/api/my_wishlist?auth_token=...
GET /lms/api/enroll_free_course?auth_token=...
GET /lms/api/toggle_wishlist_items?auth_token=...
GET /lms/api/course_details_by_id?auth_token=...
GET /lms/api/lesson_details?auth_token=...
GET /lms/api/bundle_courses?auth_token=...
GET /lms/api/my_bundle_courses?auth_token=...
GET /lms/api/my_purchases?auth_token=...
GET /lms/api_instructor/userdata?auth_token=...
GET /lms/api_instructor/courses?auth_token=...
GET /lms/api_instructor/edit_course_form?auth_token=...
GET /lms/api_instructor/update_course_status?auth_token=...
GET /lms/api_instructor/sales_report?auth_token=...
GET /lms/api_instructor/payout_report?auth_token=...
GET /lms/api_instructor/delete_withdrawal_request?auth_token=...
GET /lms/api_instructor/live_class?auth_token=...
GET /lms/api_instructor/live_class_settings?auth_token=...
```

## Proof of Concept

### 1. Token Exposure in Server Logs
```bash
# Access API endpoint with token in URL
curl "https://target.com/lms/api/my_courses?auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Check server access log
tail /var/log/apache2/access.log
# Shows: GET /lms/api/my_courses?auth_token=eyJ0eXAiOiJKV1Qi... [timestamp] [IP]
```

### 2. Browser History Exposure
```javascript
// Token stored in browser history
window.location.href = "https://target.com/lms/api/my_courses?auth_token=SECRET_TOKEN";

// Later accessible via browser history
console.log(window.history);
```

### 3. Referrer Header Leakage
```html
<!-- User clicks external link while on a page with token in URL -->
<a href="https://external-site.com">External Link</a>

<!-- external-site.com receives referrer header containing the token -->
Referer: https://target.com/lms/api/my_courses?auth_token=SECRET_TOKEN
```

## Attack Scenarios

### Scenario 1: Server Administrator Access
A malicious server administrator can extract JWT tokens from access logs and impersonate users:

```bash
# Extract tokens from access logs
grep "auth_token=" /var/log/apache2/access.log | cut -d'=' -f2 | cut -d' ' -f1
```

### Scenario 2: Shared Computer Attack
An attacker with access to a shared computer can view browser history to extract tokens:

```bash
# Chrome history location (example)
sqlite3 ~/.config/google-chrome/Default/History \
  "SELECT url FROM urls WHERE url LIKE '%auth_token=%'"
```

### Scenario 3: Network Monitoring
Corporate environments monitoring network traffic can capture tokens from URLs.

## Mitigation

### Recommended Fix
Modify all affected endpoints to accept tokens via HTTP Authorization header instead of URL parameters:

```php
// Current vulnerable implementation
$auth_token = $this->input->get('auth_token');

// Secure implementation
$auth_header = $this->input->get_request_header('Authorization');
if (strpos($auth_header, 'Bearer ') === 0) {
    $auth_token = substr($auth_header, 7);
} else {
    // Reject request
}
```

### Client-Side Changes
Update frontend code to send tokens in headers:

```javascript
// Replace URL parameter approach
fetch('/lms/api/my_courses?auth_token=' + token);

// With header-based authentication
fetch('/lms/api/my_courses', {
    headers: {
        'Authorization': 'Bearer ' + token
    }
});
```

### Additional Security Measures
1. **Audit existing logs** for exposed tokens and invalidate them
2. **Implement HTTPS** to encrypt token transmission
3. **Use POST requests** for sensitive operations instead of GET
4. **Implement token refresh** mechanisms to limit exposure window
5. **Monitor for token abuse** in server logs

## Timeline

- **Discovery:** July 2025 (During white box penetration testing)
- **Vendor Notification:** July 20, 2025 (Responsible disclosure to Creativeitem/Academy LMS team)
- **CVE Request Submitted:** July 20, 2025 (CVE number requested from MITRE)
- **Vendor Response:** Awaiting response from vendor
- **Public Disclosure:** July 20, 2025

*This vulnerability was discovered during a white box penetration test. Given that Academy LMS is a widely-used commercial template with many installations across different organizations, we decided to report this as a responsible disclosure to help protect all users of this platform.*

*This timeline will be updated accordingly as the responsible disclosure process progresses.*

## References

- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://tools.ietf.org/html/rfc6750)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

## Credit

This vulnerability was discovered and responsibly disclosed by the security research team at suryadina.com.

---
*This post is part of our ongoing security research into popular Learning Management Systems. For more security insights, visit [https://suryadina.com](https://suryadina.com).*