---
title: "JWT Generator & Debugger"
date: 2024-01-01
draft: false
type: "page"
---

<style>
.jwt-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.jwt-section {
    background: #1a1a1a;
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
    border: 1px solid #333;
}

.jwt-input, .jwt-output {
    width: 100%;
    min-height: 200px;
    background: #0f0f0f;
    color: #fff;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 15px;
    font-family: 'Monaco', 'Consolas', monospace;
    font-size: 14px;
    resize: vertical;
}

.jwt-header {
    background: #ff0000;
    color: white;
    padding: 5px 10px;
    border-radius: 4px;
    display: inline-block;
    margin: 5px;
}

.jwt-payload {
    background: #800080;
    color: white;
    padding: 5px 10px;
    border-radius: 4px;
    display: inline-block;
    margin: 5px;
}

.jwt-signature {
    background: #00bfff;
    color: white;
    padding: 5px 10px;
    border-radius: 4px;
    display: inline-block;
    margin: 5px;
}

.btn {
    background: #007acc;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 4px;
    cursor: pointer;
    margin: 5px;
}

.btn:hover {
    background: #005a9e;
}

.btn-danger {
    background: #dc3545;
}

.btn-danger:hover {
    background: #c82333;
}

.form-group {
    margin: 15px 0;
}

.form-group label {
    display: block;
    margin-bottom: 5px;
    font-weight: bold;
}

.form-group input, .form-group select {
    width: 100%;
    padding: 8px;
    border: 1px solid #444;
    border-radius: 4px;
    background: #0f0f0f;
    color: #fff;
}

.decoded-section {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-top: 20px;
}

.error {
    color: #ff6b6b;
    background: #2d1b1b;
    padding: 10px;
    border-radius: 4px;
    margin: 10px 0;
}

.success {
    color: #51cf66;
    background: #1b2d1b;
    padding: 10px;
    border-radius: 4px;
    margin: 10px 0;
}

@media (max-width: 768px) {
    .decoded-section {
        grid-template-columns: 1fr;
    }
}
</style>

<div class="jwt-container">
    <h1>JWT Generator & Debugger</h1>
    
    <div class="jwt-section">
        <h2>JWT Token</h2>
        <p>Paste your JWT token below to decode it, or use the generator to create a new one.</p>
        <textarea id="jwtInput" class="jwt-input" placeholder="Paste your JWT token here..."></textarea>
        <div style="margin: 10px 0;">
            <button class="btn" onclick="decodeJWT()">Decode JWT</button>
            <button class="btn" onclick="clearAll()">Clear</button>
            <button class="btn" onclick="copyToClipboard('jwtInput')">Copy JWT</button>
        </div>
        <div id="jwtParts" style="margin-top: 10px;"></div>
    </div>

    <div class="decoded-section">
        <div class="jwt-section">
            <h3>Header</h3>
            <textarea id="headerOutput" class="jwt-output" placeholder="Decoded header will appear here..."></textarea>
        </div>
        <div class="jwt-section">
            <h3>Payload</h3>
            <textarea id="payloadOutput" class="jwt-output" placeholder="Decoded payload will appear here..."></textarea>
        </div>
    </div>

    <div class="jwt-section">
        <h3>Signature Verification</h3>
        <div class="form-group">
            <label for="secretKey">Secret Key (for HMAC algorithms):</label>
            <input type="text" id="secretKey" placeholder="your-256-bit-secret">
        </div>
        <button class="btn" onclick="verifySignature()">Verify Signature</button>
        <div id="signatureStatus"></div>
    </div>

    <div class="jwt-section">
        <h2>JWT Generator</h2>
        <div class="form-group">
            <label for="algorithm">Algorithm:</label>
            <select id="algorithm">
                <option value="HS256">HS256</option>
                <option value="HS384">HS384</option>
                <option value="HS512">HS512</option>
            </select>
        </div>
        
        <div class="form-group">
            <label for="issuer">Issuer (iss):</label>
            <input type="text" id="issuer" placeholder="your-app-name">
        </div>
        
        <div class="form-group">
            <label for="subject">Subject (sub):</label>
            <input type="text" id="subject" placeholder="user-id">
        </div>
        
        <div class="form-group">
            <label for="audience">Audience (aud):</label>
            <input type="text" id="audience" placeholder="your-audience">
        </div>
        
        <div class="form-group">
            <label for="expiration">Expiration (hours from now):</label>
            <input type="number" id="expiration" value="24" min="1">
        </div>
        
        <div class="form-group">
            <label for="customClaims">Custom Claims (JSON):</label>
            <textarea id="customClaims" class="jwt-input" style="min-height: 100px;" placeholder='{"role": "admin", "permissions": ["read", "write"]}'></textarea>
        </div>
        
        <div class="form-group">
            <label for="generateSecret">Secret Key:</label>
            <input type="text" id="generateSecret" placeholder="your-256-bit-secret">
        </div>
        
        <button class="btn" onclick="generateJWT()">Generate JWT</button>
        <button class="btn" onclick="generateRandomSecret()">Generate Random Secret</button>
    </div>

    <div id="messages"></div>
</div>

<script>
// Base64 URL encoding/decoding functions
function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    return atob(str);
}

function base64UrlEncode(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function showMessage(message, type = 'success') {
    const messagesDiv = document.getElementById('messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = type;
    messageDiv.textContent = message;
    messagesDiv.appendChild(messageDiv);
    
    setTimeout(() => {
        messagesDiv.removeChild(messageDiv);
    }, 5000);
}

function decodeJWT() {
    const jwt = document.getElementById('jwtInput').value.trim();
    
    if (!jwt) {
        showMessage('Please enter a JWT token', 'error');
        return;
    }

    try {
        const parts = jwt.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        // Decode header
        const header = JSON.parse(base64UrlDecode(parts[0]));
        document.getElementById('headerOutput').value = JSON.stringify(header, null, 2);

        // Decode payload
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        document.getElementById('payloadOutput').value = JSON.stringify(payload, null, 2);

        // Show JWT parts with color coding
        const jwtPartsDiv = document.getElementById('jwtParts');
        jwtPartsDiv.innerHTML = `
            <div style="word-break: break-all; margin: 10px 0;">
                <span class="jwt-header">${parts[0]}</span>.<span class="jwt-payload">${parts[1]}</span>.<span class="jwt-signature">${parts[2]}</span>
            </div>
            <div style="font-size: 12px; color: #888;">
                <span class="jwt-header">HEADER</span>
                <span class="jwt-payload">PAYLOAD</span>
                <span class="jwt-signature">SIGNATURE</span>
            </div>
        `;

        showMessage('JWT decoded successfully!');
    } catch (error) {
        showMessage('Error decoding JWT: ' + error.message, 'error');
    }
}

async function verifySignature() {
    const jwt = document.getElementById('jwtInput').value.trim();
    const secret = document.getElementById('secretKey').value.trim();
    
    if (!jwt || !secret) {
        showMessage('Please enter both JWT token and secret key', 'error');
        return;
    }

    try {
        const parts = jwt.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        const header = JSON.parse(base64UrlDecode(parts[0]));
        const algorithm = header.alg;

        if (!algorithm.startsWith('HS')) {
            showMessage('Only HMAC algorithms (HS256, HS384, HS512) are supported for verification', 'error');
            return;
        }

        const data = parts[0] + '.' + parts[1];
        const signature = parts[2];

        // Import secret key
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret);
        
        let hashAlgorithm;
        switch (algorithm) {
            case 'HS256': hashAlgorithm = 'SHA-256'; break;
            case 'HS384': hashAlgorithm = 'SHA-384'; break;
            case 'HS512': hashAlgorithm = 'SHA-512'; break;
            default: throw new Error('Unsupported algorithm');
        }

        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: hashAlgorithm },
            false,
            ['sign']
        );

        // Generate signature
        const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
        const generatedSignature = base64UrlEncode(String.fromCharCode(...new Uint8Array(signatureBuffer)));

        const statusDiv = document.getElementById('signatureStatus');
        if (generatedSignature === signature) {
            statusDiv.innerHTML = '<div class="success">✓ Signature verified successfully!</div>';
        } else {
            statusDiv.innerHTML = '<div class="error">✗ Invalid signature</div>';
        }
    } catch (error) {
        document.getElementById('signatureStatus').innerHTML = `<div class="error">Error verifying signature: ${error.message}</div>`;
    }
}

async function generateJWT() {
    const algorithm = document.getElementById('algorithm').value;
    const issuer = document.getElementById('issuer').value;
    const subject = document.getElementById('subject').value;
    const audience = document.getElementById('audience').value;
    const expirationHours = parseInt(document.getElementById('expiration').value);
    const customClaimsText = document.getElementById('customClaims').value.trim();
    const secret = document.getElementById('generateSecret').value.trim();

    if (!secret) {
        showMessage('Please enter a secret key', 'error');
        return;
    }

    try {
        // Create header
        const header = {
            alg: algorithm,
            typ: 'JWT'
        };

        // Create payload
        const now = Math.floor(Date.now() / 1000);
        const payload = {
            iat: now,
            exp: now + (expirationHours * 3600)
        };

        if (issuer) payload.iss = issuer;
        if (subject) payload.sub = subject;
        if (audience) payload.aud = audience;

        // Add custom claims
        if (customClaimsText) {
            const customClaims = JSON.parse(customClaimsText);
            Object.assign(payload, customClaims);
        }

        // Encode header and payload
        const encodedHeader = base64UrlEncode(JSON.stringify(header));
        const encodedPayload = base64UrlEncode(JSON.stringify(payload));
        const data = encodedHeader + '.' + encodedPayload;

        // Generate signature
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret);
        
        let hashAlgorithm;
        switch (algorithm) {
            case 'HS256': hashAlgorithm = 'SHA-256'; break;
            case 'HS384': hashAlgorithm = 'SHA-384'; break;
            case 'HS512': hashAlgorithm = 'SHA-512'; break;
            default: throw new Error('Unsupported algorithm');
        }

        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: hashAlgorithm },
            false,
            ['sign']
        );

        const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
        const signature = base64UrlEncode(String.fromCharCode(...new Uint8Array(signatureBuffer)));

        // Create final JWT
        const jwt = data + '.' + signature;
        
        // Update the input field
        document.getElementById('jwtInput').value = jwt;
        
        // Automatically decode the generated JWT
        decodeJWT();
        
        showMessage('JWT generated successfully!');
    } catch (error) {
        showMessage('Error generating JWT: ' + error.message, 'error');
    }
}

function generateRandomSecret() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const secret = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    document.getElementById('generateSecret').value = secret;
    showMessage('Random secret generated!');
}

function clearAll() {
    document.getElementById('jwtInput').value = '';
    document.getElementById('headerOutput').value = '';
    document.getElementById('payloadOutput').value = '';
    document.getElementById('jwtParts').innerHTML = '';
    document.getElementById('signatureStatus').innerHTML = '';
    showMessage('All fields cleared!');
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    showMessage('Copied to clipboard!');
}

// Auto-decode when pasting JWT
document.getElementById('jwtInput').addEventListener('paste', function() {
    setTimeout(() => {
        if (this.value.trim()) {
            decodeJWT();
        }
    }, 100);
});

// Example JWT for demonstration
document.addEventListener('DOMContentLoaded', function() {
    const exampleJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    document.getElementById('jwtInput').placeholder = `Example: ${exampleJWT}`;
});
</script>