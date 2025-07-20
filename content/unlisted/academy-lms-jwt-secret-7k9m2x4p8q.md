---
title: "Critical JWT Secret Vulnerability in Academy LMS v5.13"
date: 2025-07-20
tags: ["security", "jwt", "academy-lms", "vulnerability"]
categories: ["Security Research"]
draft: false
---

## Overview

A critical security vulnerability has been discovered in Academy LMS versions up to and including 5.13, where the application uses a hardcoded default JWT secret for token authentication.

## Technical Details

**CVE ID:** Pending Assignment  
**CVSS Score:** 9.3 (Critical)  
**Affected Versions:** Academy LMS ≤ v5.13  
**Vulnerability Type:** Authentication Bypass via Hardcoded Credentials  

### Affected Component
- File: `lms/application/libraries/TokenHandler.php`
- Default Secret: `academy-lms-xxxxxxxxxxx` - masked to protect users who still use the secret

### Vulnerability Description

Academy LMS uses a predictable, hardcoded JWT secret "academy-lms-xxxxxxxx" for signing authentication tokens with the HS256 algorithm. This secret is the same across all default installations of Academy LMS, making it trivial for attackers to forge valid JWT tokens.

### Vulnerable Source Code

```php
// From lms/application/libraries/TokenHandler.php:6
class TokenHandler
{
   //////////The function generate token/////////////
   PRIVATE $key = "academy-lms-xxxxxxxx";
   public function GenerateToken($data)
   {
       $jwt = JWT::encode($data, $this->key);
       return $jwt;
   }

  //////This function decode the token////////////////////
   public function DecodeToken($token)
   {
       $decoded = JWT::decode($token, $this->key, array('HS256'));
       $decodedData = (array) $decoded;
       return $decodedData;
   }
}
```

## Impact

An attacker can:
1. Purchase the Academy LMS template to obtain the source code and discover the default secret
2. Generate valid JWT tokens for any user account, including administrators
3. Completely bypass authentication mechanisms
4. Achieve privilege escalation to administrative access
5. Access sensitive user data and system functions

## Proof of Concept

```python
import jwt
import json

# Known default secret from Academy LMS
secret = "academy-lms-xxxxxx"

# Forge admin token
payload = {
    "user_id": "1",
    "role_id": "1",
    "is_admin": True,
    "email": "admin@example.com"
}

# Generate malicious JWT
forged_token = jwt.encode(payload, secret, algorithm='HS256')
print(f"Forged Admin Token: {forged_token}")
```

## Affected Endpoints

All API endpoints that rely on JWT authentication are vulnerable, including:
- User authentication endpoints
- Course management APIs
- Administrative functions
- Payment processing APIs

## Mitigation

### Immediate Actions
1. **Change the JWT secret immediately** to a cryptographically secure random value
2. **Invalidate all existing JWT tokens** by changing the secret
3. **Force all users to re-authenticate**

### Recommended Implementation
```php
// Generate secure random secret
$jwt_secret = bin2hex(random_bytes(32)); // 64-character hex string

// Store in environment variables or secure config
// Never hardcode in source code
```

### Best Practices
- Use environment variables for secrets
- Implement JWT secret rotation
- Consider using RS256 with public/private key pairs
- Implement proper token expiration policies

## Timeline

- **Discovery:** July 2025 (During white box penetration testing)
- **Vendor Notification:** July 20, 2025 (Responsible disclosure to Creativeitem/Academy LMS team)
- **CVE Request Submitted:** July 20, 2025 (CVE number requested from MITRE)
- **Vendor Response:** Awaiting response from vendor
- **Public Disclosure:** July 20, 2025

*This vulnerability was discovered during a white box penetration test. Given that Academy LMS is a widely-used commercial template with many installations across different organizations, we decided to report this as a responsible disclosure to help protect all users of this platform.*

*This timeline will be updated accordingly as the responsible disclosure process progresses.*

## References

- [Academy LMS Official Website](https://codecanyon.net/item/academy-learning-management-system/22703468)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc7519)

## Credit

This vulnerability was discovered and responsibly disclosed by the security research team at suryadina.com.

---
*This post is part of our ongoing security research into popular Learning Management Systems. For more security insights, visit [https://suryadina.com](https://suryadina.com).*