---
title: "QR Code Generator"
date: 2025-01-14T00:00:00Z
draft: false
description: "Generate QR codes for any URL with customizable size options"
tags: ["tools", "qr-code", "generator"]
categories: ["tools"]
---

{{< rawhtml >}}
<style>
    .qr-container {
        background: white;
        border-radius: 15px;
        padding: 30px;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
        text-align: center;
        max-width: 500px;
        margin: 0 auto;
    }
    .qr-container h2 {
        color: #333;
        margin-bottom: 30px;
        font-size: 28px;
    }
    .input-group {
        margin-bottom: 20px;
    }
    .input-group label {
        display: block;
        margin-bottom: 8px;
        color: #555;
        font-weight: bold;
        text-align: left;
    }
    .input-group input[type="text"] {
        width: 100%;
        padding: 12px;
        border: 2px solid #ddd;
        border-radius: 8px;
        font-size: 16px;
        box-sizing: border-box;
        transition: border-color 0.3s;
    }
    .input-group input[type="text"]:focus {
        outline: none;
        border-color: #667eea;
    }
    .qr-button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 12px 30px;
        font-size: 16px;
        border-radius: 8px;
        cursor: pointer;
        transition: transform 0.2s, box-shadow 0.2s;
        margin: 10px 5px;
    }
    .qr-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
    }
    .qr-button:active {
        transform: translateY(0);
    }
    #qrcode {
        margin: 30px auto;
        padding: 20px;
        background: #f9f9f9;
        border-radius: 10px;
        display: inline-block;
    }
    .url-display {
        background: #f8f9fa;
        padding: 15px;
        border-radius: 8px;
        margin: 20px 0;
        word-break: break-all;
        font-family: monospace;
        color: #495057;
        border-left: 4px solid #667eea;
    }
    .size-controls {
        margin: 20px 0;
    }
    .size-controls label {
        display: inline-block;
        margin-right: 10px;
        text-align: center;
    }
    .qr-select {
        padding: 8px;
        border: 2px solid #ddd;
        border-radius: 5px;
        font-size: 14px;
    }
    .hidden {
        display: none;
    }
</style>

<div class="qr-container">
    <h2>🔳 QR Code Generator</h2>
    
    <div class="input-group">
        <label for="urlInput">Enter URL:</label>
        <input type="text" id="urlInput" placeholder="https://example.com">
    </div>
    
    <div class="size-controls">
        <label for="sizeSelect">QR Code Size:</label>
        <select id="sizeSelect" class="qr-select">
            <option value="200">200x200 px</option>
            <option value="300" selected>300x300 px</option>
            <option value="400">400x400 px</option>
            <option value="500">500x500 px</option>
        </select>
    </div>
    
    <button onclick="generateQR()" class="qr-button">Generate QR Code</button>
    <button onclick="downloadQR()" id="downloadBtn" class="qr-button hidden">Download QR Code</button>
    
    <div id="qrcode"></div>
    
    <div id="urlDisplay" class="url-display hidden">
        <strong>Generated for URL:</strong><br>
        <span id="currentUrl"></span>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script>
<script>
    let currentQRCode = null;
    
    function generateQR() {
        const url = document.getElementById('urlInput').value.trim();
        const size = parseInt(document.getElementById('sizeSelect').value);
        
        if (!url) {
            alert('Please enter a URL');
            return;
        }
        
        // Validate URL format
        try {
            new URL(url);
        } catch (e) {
            if (!url.startsWith('http://') && !url.startsWith('https://')) {
                // Try adding https:// prefix
                const fullUrl = 'https://' + url;
                try {
                    new URL(fullUrl);
                    document.getElementById('urlInput').value = fullUrl;
                    generateQRCode(fullUrl, size);
                    return;
                } catch (e2) {
                    alert('Please enter a valid URL');
                    return;
                }
            } else {
                alert('Please enter a valid URL');
                return;
            }
        }
        
        generateQRCode(url, size);
    }
    
    function generateQRCode(url, size) {
        // Clear previous QR code
        document.getElementById('qrcode').innerHTML = '';
        
        try {
            // Create QR code
            const qr = qrcode(0, 'M');
            qr.addData(url);
            qr.make();
            
            // Create canvas
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const moduleCount = qr.getModuleCount();
            const cellSize = size / moduleCount;
            
            canvas.width = size;
            canvas.height = size;
            
            // Draw QR code
            ctx.fillStyle = '#FFFFFF';
            ctx.fillRect(0, 0, size, size);
            
            ctx.fillStyle = '#000000';
            for (let row = 0; row < moduleCount; row++) {
                for (let col = 0; col < moduleCount; col++) {
                    if (qr.isDark(row, col)) {
                        ctx.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
                    }
                }
            }
            
            // Display QR code
            document.getElementById('qrcode').appendChild(canvas);
            
            // Show URL and download button
            document.getElementById('currentUrl').textContent = url;
            document.getElementById('urlDisplay').classList.remove('hidden');
            document.getElementById('downloadBtn').classList.remove('hidden');
            
            // Store current QR code for download
            currentQRCode = canvas;
            
        } catch (error) {
            alert('Error generating QR code: ' + error.message);
        }
    }
    
    function downloadQR() {
        if (!currentQRCode) {
            alert('No QR code to download');
            return;
        }
        
        // Create download link
        const link = document.createElement('a');
        link.download = 'qrcode.png';
        link.href = currentQRCode.toDataURL();
        link.click();
    }
    
    // Generate QR code when Enter is pressed
    document.getElementById('urlInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            generateQR();
        }
    });
    
    // Generate QR code when size changes
    document.getElementById('sizeSelect').addEventListener('change', function() {
        const url = document.getElementById('urlInput').value.trim();
        if (url) {
            generateQR();
        }
    });
</script>
{{< /rawhtml >}}