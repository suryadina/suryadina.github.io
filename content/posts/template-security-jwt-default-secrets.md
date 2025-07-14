---
title: "The Hidden Risk in Third-Party Templates: A JWT Secret Story"
date: 2025-07-14
description: "How a default JWT secret in a marketplace template created a security vulnerability that could compromise many of its users"
categories: ["Penetration Testing", "Web Security"]
tags: ["jwt", "authentication", "templates", "codeigniter", "default-credentials", "pentest"]
draft: false
---

![Description of image](/images/posts/jwt-secret/image-1.jpeg)
In today's fast-paced development environment, organizations constantly seek ways to accelerate their software delivery while managing limited resources. One increasingly popular approach is leveraging third-party services and building applications based on pre-built templates from online marketplaces. This practice, when executed properly, can dramatically reduce development time and costs, especially for organizations with constrained budgets or tight deadlines.

However, beneath this convenience lies a potential security minefield that many developers unknowingly navigate. This is the story of how a single oversight in template customization exposed a vulnerability that could compromise not just one application, but potentially hundreds of others built from the same foundation.

## The Evolution of Default Credential Vulnerabilities

The concept of default credentials isn't new to the cybersecurity landscape. For decades, security professionals have encountered countless instances of unchanged default passwords in infrastructure components, IoT devices, and vendor-supplied applications. Network equipment with "admin/admin" credentials, database systems with default "sa" passwords, and industrial control systems with factory-set access codes have all contributed to security breaches worldwide.

What makes this particular case unique is how this age-old vulnerability has evolved and adapted to modern development practices. Instead of manifesting in obvious places like login forms or configuration files, default credentials have found new hiding places in the complex authentication mechanisms of contemporary web applications.

## Understanding JWT Tokens and HS256 Signing

Before diving into the story, it's crucial to understand the technology at the heart of this vulnerability: JSON Web Tokens (JWT) and the HS256 signing algorithm.

### What is a JWT Token?

A JSON Web Token is a compact, URL-safe means of representing claims to be transferred between two parties. Think of it as a digital passport that contains information about a user and their permissions. The token consists of three parts separated by dots:

```
header.payload.signature
```

![Description of image](/images/posts/jwt-secret/image-2.png)

- **Header**: Contains metadata about the token type and signing algorithm
- **Payload**: Contains the actual claims (user ID, permissions, expiration time)
- **Signature**: Ensures the token hasn't been tampered with

### The HS256 Algorithm

HS256 (HMAC SHA-256) is a symmetric signing algorithm used to create the signature portion of JWT tokens. This means the same secret key is used both to sign tokens when they're created and to verify them when they're received. The critical security requirement is that this secret must be:

1. **Unique** - Different for every application
2. **Random** - Unpredictable and cryptographically strong
3. **Secret** - Never exposed or shared

When developers use the same secret across multiple applications, any of these applications can create valid tokens for all the others—a scenario that transforms a simple authentication token into a master key.

## The Discovery: A Template-Based Application

The target application in this story was a custom web platform developed by a creative agency for their client. The agency had made a sensible business decision: rather than building everything from scratch, they purchased a comprehensive template from a popular marketplace. The template, built on the CodeIgniter framework, promised to deliver a complete web application with both traditional web interface functionality and a modern API layer.

This approach is not just common—it's often the smart choice. Templates can provide:
- **Faster time-to-market** - Skip months of foundational development
- **Cost efficiency** - Leverage existing, tested code
- **Feature richness** - Access to functionality that would be expensive to develop in-house
- **Professional design** - Benefit from experienced developers' work

However, as I would soon discover, the convenience of templates comes with hidden responsibilities that many developers overlook.

## The White-Box Advantage: Access to Source Code

This particular penetration test was conducted using a white-box approach, meaning the client had provided me with complete access to the application's source code. This level of access is invaluable for security assessments as it allows for comprehensive analysis of the application's architecture, implementation details, and potential vulnerabilities that might not be apparent from external testing alone.

As I examined the authentication mechanisms within the source code, I discovered something concerning: the JWT secret used for token generation had a distinctly "template-like" appearance. The value `"template-name-api-token-handler"` immediately raised suspicions—it looked exactly like a placeholder that a template developer would use, with its generic naming convention and descriptive structure.

To confirm my suspicions, I approached the client with a direct question: had they changed the default JWT secret during their implementation? The response was telling—they couldn't provide a definitive answer. This uncertainty, combined with the template-like secret I had already discovered in the source code, confirmed that a deeper investigation was warranted.

## The Dual Nature of Modern Authentication

As I began examining the application, I encountered something increasingly common in modern web development: dual authentication systems. The application employed two distinct methods for user authentication:

**Traditional Web Authentication**: The familiar approach using session cookies (`ci_session`) that most users interact with when logging in through their browsers. This system was reasonably well-implemented, following standard CodeIgniter patterns with only minor issues.

**API Authentication**: A more sophisticated JWT-based system designed for programmatic access, mobile applications, and third-party integrations. This system operated independently from the web authentication, with its own login endpoints and token management.

The existence of this dual system created an interesting dynamic. Most clients and developers focus primarily on the web interface—it's what users see and interact with daily. The API layer, while potentially powerful, often remains in the background, sometimes forgotten or considered "future functionality."

This oversight is understandable but dangerous. In security, forgotten or unused functionality often becomes the weakest link.

## The Subtle Signs of Trouble

During my analysis of the API endpoints, I encountered several design choices that raised concerns:

```http
GET /api/login?username=admin&password=secret123
```

While these patterns were problematic—credentials in URLs, sensitive data in server logs, authentication tokens passed as URL parameters—they were overshadowed by a more fundamental issue that would soon become apparent.

## Confirming the Hypothesis: Template Demo Comparison

With the suspicious JWT secret identified in the source code, I needed to prove that it was indeed the default template value. Since the template was available on a public marketplace, I could access the template creator's demo website to conduct a comparison test.

The demo site, intended to showcase the template's features, included:
- Pre-configured test accounts
- Full API functionality
- The ability to generate JWT tokens

I authenticated against the demo site and extracted a JWT token:

```bash
curl -X GET "https://demo.template-site.com/api/login?username=admin&password=demo123"
```

Then came the moment of truth. When I compared the JWT tokens from the demo site with those from the target application, my suspicions were confirmed. The tokens shared:
- **Identical signing algorithm** (HS256)
- **Interchangeable validity** - tokens from one system worked on the other
- **Predictable user structures** - simple incremental user IDs (1, 2, 3...)

This last point was particularly significant. Upon decoding the JWT payload, I discovered that user identification followed a painfully simple pattern that would prove crucial for the exploitation phase.

This meant that anyone with access to the template—whether through purchase or the demo site—could generate valid authentication tokens for any application using the same template with unchanged default secrets.

## The Attack Vector: From Discovery to Exploitation

With the default secret confirmed and the predictable user ID structure identified, I could now craft a complete attack strategy. However, there was still one challenge: I needed to identify which user ID corresponded to an administrator account.

### Step 1: Systematic User Enumeration

The application provided an API endpoint to retrieve user profiles based on the user ID claimed in the JWT token. Combined with the predictable incremental user IDs, this created an opportunity for systematic enumeration.

Using Burp Suite's Intruder tool, I crafted JWT tokens for incremental user IDs and systematically tested hundreds of them against the profile API endpoint. This process allowed me to map out the user base and identify accounts with administrative privileges.

The secret value `"template-name-api-token-handler"` was clearly a placeholder that should have been changed during deployment but remained unchanged in the production environment. This generic, template-style naming convention was a clear indicator that the default configuration had never been properly customized.

### Step 2: Account Takeover via Email Manipulation

Once I had identified an administrator account, the next phase involved leveraging another API endpoint that allowed users to update their email addresses. This seemingly innocent functionality became the key to complete account takeover:



### Step 3: Password Reset and Complete Access

With control over the administrator's email address, I could now initiate a password reset through the normal web interface:

1. **Navigate to the password reset page** on the web interface
2. **Enter the administrator's username** (which I had identified through the profile API)
3. **Receive the password reset email** at the controlled email address
4. **Complete the password reset process** to gain legitimate access to the administrator account

This multi-step attack chain transformed a JWT secret vulnerability into complete administrative access to the application, demonstrating how multiple seemingly minor security issues can compound into critical vulnerabilities.

### The Complete Attack Flow

The entire attack sequence could be summarized as:

1. **Default Secret Discovery** - Confirmed through template demo comparison
2. **User Enumeration** - Generated JWTs for incremental user IDs (1, 2, 3...)
3. **Profile API Exploitation** - Identified administrator accounts through systematic testing
4. **Email Takeover** - Modified admin email address using update API
5. **Password Reset** - Completed account takeover through legitimate reset flow

This attack required no sophisticated techniques, no brute-force attempts, and left minimal traces in standard application logs. The combination of default secrets, predictable user structures, and permissive API endpoints created a perfect storm for complete system compromise.

## The Ripple Effect: Scale and Impact

The implications extended far beyond the single application I was testing:

**Immediate Impact**: Complete authentication bypass, administrative access, data exfiltration capabilities, and persistent unauthorized access.

**Broader Implications**: Every application built from the same template with unchanged default secrets shared the same vulnerability. With templates often selling hundreds or thousands of copies, a single default secret could potentially compromise countless applications across the internet.

**Detection Challenges**: Unlike traditional brute-force attacks or obvious intrusion attempts, this vulnerability could be exploited leaving minimal traces in standard security logs.

## The Lessons: Beyond Technical Fixes

This discovery reinforced several critical principles for organizations using third-party templates:

### The Security Handoff Problem

When organizations adopt third-party templates, there's often an implicit assumption that security is "handled" by the template creators. However, security is never a one-size-fits-all solution. Each implementation requires customization, hardening, and ongoing maintenance.

### The Inventory Challenge

Modern templates often include extensive functionality that goes beyond what organizations initially plan to use. This unused functionality—like API endpoints in primarily web-based applications—can create hidden attack surfaces that remain unmonitored and unhardened.

### The Default Secret Pandemic

Default credentials have evolved from obvious username/password combinations to sophisticated secrets buried in configuration files, authentication algorithms, and cryptographic implementations. The security implications remain the same, but the detection and mitigation require deeper technical knowledge.

## Moving Forward: Building Security into Template Usage

For organizations considering or currently using third-party templates, this story provides several actionable insights:

**Before Implementation**: Conduct comprehensive security assessments of all template functionality, not just the features you plan to use immediately.

**During Customization**: Maintain detailed inventories of all authentication mechanisms, default secrets, and configuration parameters that require customization.

**After Deployment**: Implement regular security reviews that account for template updates, new vulnerabilities, and evolving threat landscapes.

**Ongoing Management**: Treat template-based applications as living systems that require continuous security attention, not set-and-forget solutions.

## The Broader Context: Third-Party Risk in Modern Development

This case study represents a microcosm of a larger challenge facing modern software development. As organizations increasingly rely on third-party components—whether templates, libraries, APIs, or services—the traditional security perimeter becomes more complex and porous.

The balance between development velocity and security rigor requires careful consideration. Templates and third-party components will continue to play crucial roles in software development, but their adoption must be accompanied by robust security practices and ongoing vigilance.


---

*This story serves as a reminder that in cybersecurity, the most dangerous vulnerabilities are often hiding in plain sight, waiting for someone to look beyond the obvious and question the defaults.*