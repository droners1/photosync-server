// Admin Interface JavaScript
// Integrates with existing license system

// Configuration - matching the existing license.js
const SECRET_KEY = 'photosync-2024-hmac-secret-key-v1';
const SERVER_URL = 'https://droners1.github.io/photosync-server/photosync-status.json';
const LOCAL_KEYS_FILE = 'generated-keys.json';
const LOCAL_SERVER_FILE = 'photosync-status.json';

// State management
let generatedKeys = [];
let serverStatus = null;
let revokedKeys = [];

// Check if we're in Node.js environment
const isNodeJS = typeof window === 'undefined';
let crypto, fs, path, https;

if (isNodeJS) {
    crypto = require('crypto');
    fs = require('fs');
    path = require('path');
    https = require('https');
} else {
    // Browser environment - use Web Crypto API
    crypto = window.crypto;
}

// Initialize the admin interface
function initializeAdmin() {
    console.log('🚀 Initializing Photosync Admin Interface...');
    loadLocalKeys();
    refreshServerStatus();
    
    // Auto-refresh server status every 5 minutes
    setInterval(refreshServerStatus, 5 * 60 * 1000);
}

// Load locally stored keys
function loadLocalKeys() {
    try {
        if (isNodeJS && fs.existsSync(LOCAL_KEYS_FILE)) {
            const data = fs.readFileSync(LOCAL_KEYS_FILE, 'utf8');
            generatedKeys = JSON.parse(data);
            console.log(`📋 Loaded ${generatedKeys.length} keys from local storage`);
        } else if (!isNodeJS) {
            // Browser - use localStorage
            const data = localStorage.getItem('photosync-generated-keys');
            if (data) {
                generatedKeys = JSON.parse(data);
                console.log(`📋 Loaded ${generatedKeys.length} keys from browser storage`);
            }
        }
    } catch (error) {
        console.error('❌ Error loading local keys:', error);
        generatedKeys = [];
    }
}

// Save keys to local storage
function saveLocalKeys() {
    try {
        const data = JSON.stringify(generatedKeys, null, 2);
        if (isNodeJS) {
            fs.writeFileSync(LOCAL_KEYS_FILE, data);
        } else {
            localStorage.setItem('photosync-generated-keys', data);
        }
        console.log('💾 Keys saved to local storage');
    } catch (error) {
        console.error('❌ Error saving keys:', error);
    }
}

// Generate HMAC for license key validation (Node.js version)
function generateHMACNode(data) {
    return crypto.createHmac('sha256', SECRET_KEY).update(data).digest('hex');
}

// Generate HMAC for license key validation (Browser version)
async function generateHMACBrowser(data) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(SECRET_KEY);
    const messageData = encoder.encode(data);
    
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Generate HMAC (unified function)
async function generateHMAC(data) {
    if (isNodeJS) {
        return generateHMACNode(data);
    } else {
        return await generateHMACBrowser(data);
    }
}

// Generate random bytes
function generateRandomBytes(length) {
    if (isNodeJS) {
        return crypto.randomBytes(length).toString('hex').toUpperCase();
    } else {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
            .toUpperCase();
    }
}

// Generate UUID
function generateUUID() {
    if (isNodeJS) {
        return crypto.randomUUID();
    } else {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

// Generate a single license key
async function generateLicenseKey(userInfo = '') {
    const randomBytes = generateRandomBytes(16);
    
    // Create segments for the key
    const segment1 = randomBytes.substring(0, 6);
    const segment2 = randomBytes.substring(6, 14);
    const segment3 = randomBytes.substring(14, 22);
    
    // Format: PSYNC-2024-XXXXXX-XXXXXXXX-XXXXXXXX
    const licenseKey = `PSYNC-2024-${segment1}-${segment2}-${segment3}`;
    
    // Generate HMAC for validation
    const hmac = await generateHMAC(licenseKey);
    
    const keyData = {
        key: licenseKey,
        hmac: hmac,
        generated: new Date().toISOString(),
        userInfo: userInfo || 'No user info provided',
        status: 'active',
        id: generateUUID()
    };
    
    return keyData;
}

// Validate a license key
async function validateLicenseKey(licenseKey) {
    // Format validation
    const keyPattern = /^PSYNC-2024-[A-Z0-9]{6}-[A-Z0-9]{8}-[A-Z0-9]{8}$/;
    if (!keyPattern.test(licenseKey)) {
        return { valid: false, reason: 'Invalid format' };
    }
    
    // HMAC validation
    const expectedHMAC = await generateHMAC(licenseKey);
    
    // Check if key exists in our generated keys
    const keyRecord = generatedKeys.find(k => k.key === licenseKey);
    if (!keyRecord) {
        return { valid: false, reason: 'Key not found in database' };
    }
    
    // Check if key is revoked
    if (keyRecord.status === 'revoked' || revokedKeys.includes(licenseKey)) {
        return { valid: false, reason: 'Key has been revoked' };
    }
    
    return { 
        valid: true, 
        keyData: keyRecord,
        hmac: expectedHMAC
    };
}

// UI Functions
async function generateKeys() {
    const userInfo = document.getElementById('userInfo').value;
    const quantity = parseInt(document.getElementById('keyQuantity').value) || 1;
    
    if (quantity > 100) {
        updateOutput('generatedKeys', '❌ Maximum 100 keys per batch');
        return;
    }
    
    updateOutput('generatedKeys', '🔄 Generating keys...');
    
    const newKeys = [];
    for (let i = 0; i < quantity; i++) {
        const keyData = await generateLicenseKey(userInfo);
        newKeys.push(keyData);
        generatedKeys.push(keyData);
    }
    
    saveLocalKeys();
    
    let output = `✅ Generated ${quantity} license key(s):\n\n`;
    newKeys.forEach((keyData, index) => {
        output += `Key ${index + 1}: ${keyData.key}\n`;
        output += `Generated: ${keyData.generated}\n`;
        output += `User Info: ${keyData.userInfo}\n`;
        output += `ID: ${keyData.id}\n\n`;
    });
    
    updateOutput('generatedKeys', output);
    console.log(`🔑 Generated ${quantity} new license keys`);
}

async function generateBatchKeys() {
    await generateKeys();
}

async function validateKey() {
    const licenseKey = document.getElementById('manageKey').value.trim().toUpperCase();
    
    if (!licenseKey) {
        updateOutput('keyManagementOutput', '❌ Please enter a license key');
        return;
    }
    
    updateOutput('keyManagementOutput', '🔄 Validating key...');
    
    const validation = await validateLicenseKey(licenseKey);
    
    let output = `🔍 License Key Validation Results:\n\n`;
    output += `Key: ${licenseKey}\n`;
    output += `Valid: ${validation.valid ? '✅ YES' : '❌ NO'}\n`;
    
    if (validation.valid) {
        output += `Status: ${validation.keyData.status}\n`;
        output += `Generated: ${validation.keyData.generated}\n`;
        output += `User Info: ${validation.keyData.userInfo}\n`;
        output += `HMAC: ${validation.hmac.substring(0, 16)}...\n`;
    } else {
        output += `Reason: ${validation.reason}\n`;
    }
    
    updateOutput('keyManagementOutput', output);
}

function revokeKey() {
    const licenseKey = document.getElementById('manageKey').value.trim().toUpperCase();
    
    if (!licenseKey) {
        updateOutput('keyManagementOutput', '❌ Please enter a license key');
        return;
    }
    
    const keyIndex = generatedKeys.findIndex(k => k.key === licenseKey);
    if (keyIndex === -1) {
        updateOutput('keyManagementOutput', '❌ Key not found in database');
        return;
    }
    
    generatedKeys[keyIndex].status = 'revoked';
    generatedKeys[keyIndex].revokedAt = new Date().toISOString();
    
    // Add to revoked keys list
    if (!revokedKeys.includes(licenseKey)) {
        revokedKeys.push(licenseKey);
    }
    
    saveLocalKeys();
    updateServerStatus();
    
    updateOutput('keyManagementOutput', `✅ Key revoked successfully: ${licenseKey}`);
    console.log(`🚫 Revoked license key: ${licenseKey}`);
}

function restoreKey() {
    const licenseKey = document.getElementById('manageKey').value.trim().toUpperCase();
    
    if (!licenseKey) {
        updateOutput('keyManagementOutput', '❌ Please enter a license key');
        return;
    }
    
    const keyIndex = generatedKeys.findIndex(k => k.key === licenseKey);
    if (keyIndex === -1) {
        updateOutput('keyManagementOutput', '❌ Key not found in database');
        return;
    }
    
    generatedKeys[keyIndex].status = 'active';
    delete generatedKeys[keyIndex].revokedAt;
    
    // Remove from revoked keys list
    const revokedIndex = revokedKeys.indexOf(licenseKey);
    if (revokedIndex > -1) {
        revokedKeys.splice(revokedIndex, 1);
    }
    
    saveLocalKeys();
    updateServerStatus();
    
    updateOutput('keyManagementOutput', `✅ Key restored successfully: ${licenseKey}`);
    console.log(`✅ Restored license key: ${licenseKey}`);
}

async function checkKeyStatus() {
    const licenseKey = document.getElementById('manageKey').value.trim().toUpperCase();
    
    if (!licenseKey) {
        updateOutput('keyManagementOutput', '❌ Please enter a license key');
        return;
    }
    
    const keyRecord = generatedKeys.find(k => k.key === licenseKey);
    
    let output = `📊 Key Status Report:\n\n`;
    output += `Key: ${licenseKey}\n`;
    
    if (keyRecord) {
        output += `Status: ${keyRecord.status}\n`;
        output += `Generated: ${keyRecord.generated}\n`;
        output += `User Info: ${keyRecord.userInfo}\n`;
        output += `ID: ${keyRecord.id}\n`;
        
        if (keyRecord.revokedAt) {
            output += `Revoked At: ${keyRecord.revokedAt}\n`;
        }
        
        const validation = await validateLicenseKey(licenseKey);
        output += `Currently Valid: ${validation.valid ? '✅ YES' : '❌ NO'}\n`;
    } else {
        output += `Status: ❌ Not found in database\n`;
    }
    
    updateOutput('keyManagementOutput', output);
}

function loadActiveKeys() {
    const activeKeys = generatedKeys.filter(k => k.status === 'active');
    const revokedKeysCount = generatedKeys.filter(k => k.status === 'revoked').length;
    
    let html = `<div style="margin-bottom: 15px; padding: 10px; background: rgba(45, 45, 68, 0.5); border-radius: 6px;">`;
    html += `<strong>📊 Summary:</strong> ${activeKeys.length} active, ${revokedKeysCount} revoked, ${generatedKeys.length} total`;
    html += `</div>`;
    
    if (generatedKeys.length === 0) {
        html += '<p>No keys generated yet.</p>';
    } else {
        generatedKeys.forEach(keyData => {
            const isRevoked = keyData.status === 'revoked';
            html += `<div class="key-item ${isRevoked ? 'revoked' : ''}">`;
            html += `<div>`;
            html += `<div class="key-code">${keyData.key}</div>`;
            html += `<div style="font-size: 11px; color: #888; margin-top: 4px;">`;
            html += `${keyData.userInfo} • ${new Date(keyData.generated).toLocaleDateString()}`;
            if (isRevoked && keyData.revokedAt) {
                html += ` • Revoked: ${new Date(keyData.revokedAt).toLocaleDateString()}`;
            }
            html += `</div>`;
            html += `</div>`;
            html += `<div style="font-size: 12px; color: ${isRevoked ? '#ff4757' : '#2ed573'};">`;
            html += `${isRevoked ? '🚫 REVOKED' : '✅ ACTIVE'}`;
            html += `</div>`;
            html += `</div>`;
        });
    }
    
    document.getElementById('activeKeysList').innerHTML = html;
    console.log(`📋 Loaded ${generatedKeys.length} keys for display`);
}

function exportKeys() {
    const exportData = {
        exportDate: new Date().toISOString(),
        totalKeys: generatedKeys.length,
        activeKeys: generatedKeys.filter(k => k.status === 'active').length,
        revokedKeys: generatedKeys.filter(k => k.status === 'revoked').length,
        keys: generatedKeys
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `photosync-keys-export-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    console.log('📥 Keys exported successfully');
}

function clearRevokedKeys() {
    const revokedCount = generatedKeys.filter(k => k.status === 'revoked').length;
    
    if (revokedCount === 0) {
        updateOutput('keyManagementOutput', '✅ No revoked keys to clear');
        return;
    }
    
    if (confirm(`Are you sure you want to permanently delete ${revokedCount} revoked keys?`)) {
        generatedKeys = generatedKeys.filter(k => k.status !== 'revoked');
        revokedKeys = [];
        saveLocalKeys();
        loadActiveKeys();
        updateOutput('keyManagementOutput', `✅ Cleared ${revokedCount} revoked keys`);
        console.log(`🗑️ Cleared ${revokedCount} revoked keys`);
    }
}

// Server Management Functions
function refreshServerStatus() {
    updateServerStatusDisplay('Checking server status...', 'offline');
    
    if (isNodeJS) {
        // Node.js version
        const req = https.get(SERVER_URL, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    serverStatus = JSON.parse(data);
                    updateServerStatusFromData();
                    console.log('🌐 Server status refreshed from remote');
                } catch (error) {
                    console.error('❌ Error parsing server response:', error);
                    loadLocalServerStatus();
                }
            });
        }).on('error', (error) => {
            console.error('❌ Error fetching server status:', error);
            loadLocalServerStatus();
        });
        
        req.setTimeout(5000, () => {
            req.destroy();
            loadLocalServerStatus();
        });
    } else {
        // Browser version
        fetch(SERVER_URL)
            .then(response => response.json())
            .then(data => {
                serverStatus = data;
                updateServerStatusFromData();
                console.log('🌐 Server status refreshed from remote');
            })
            .catch(error => {
                console.error('❌ Error fetching server status:', error);
                loadLocalServerStatus();
            });
    }
}

function loadLocalServerStatus() {
    try {
        let data;
        if (isNodeJS && fs.existsSync(LOCAL_SERVER_FILE)) {
            data = fs.readFileSync(LOCAL_SERVER_FILE, 'utf8');
        } else if (!isNodeJS) {
            data = localStorage.getItem('photosync-server-status');
        }
        
        if (data) {
            serverStatus = JSON.parse(data);
            updateServerStatusFromData();
            console.log('📁 Loaded server status from local storage');
        } else {
            // Create default server status
            serverStatus = {
                allowAccess: true,
                revokedKeys: [],
                maintenanceMode: false,
                lastUpdated: new Date().toISOString(),
                version: "1.0.0"
            };
            saveLocalServerStatus();
            updateServerStatusFromData();
        }
    } catch (error) {
        console.error('❌ Error loading local server status:', error);
        updateServerStatusDisplay('Error loading server status', 'offline');
    }
}

function saveLocalServerStatus() {
    try {
        const data = JSON.stringify(serverStatus, null, 2);
        if (isNodeJS) {
            fs.writeFileSync(LOCAL_SERVER_FILE, data);
        } else {
            localStorage.setItem('photosync-server-status', data);
        }
        console.log('💾 Server status saved locally');
    } catch (error) {
        console.error('❌ Error saving server status:', error);
    }
}

function updateServerStatusFromData() {
    if (!serverStatus) {
        updateServerStatusDisplay('No server data available', 'offline');
        return;
    }
    
    revokedKeys = serverStatus.revokedKeys || [];
    
    let status = 'online';
    let message = 'Server Online - Access Allowed';
    
    if (serverStatus.maintenanceMode) {
        status = 'maintenance';
        message = 'Maintenance Mode Active';
    } else if (!serverStatus.allowAccess) {
        status = 'offline';
        message = 'Access Denied - Kill Switch Active';
    }
    
    message += ` (${revokedKeys.length} revoked keys)`;
    updateServerStatusDisplay(message, status);
}

function updateServerStatusDisplay(message, status) {
    const statusElement = document.getElementById('serverStatus');
    if (!statusElement) return;
    
    const indicator = statusElement.querySelector('.status-indicator');
    const textElement = statusElement.querySelector('span:last-child');
    
    if (indicator) indicator.className = `status-indicator status-${status}`;
    if (textElement) textElement.textContent = message;
}

function updateServerStatus() {
    if (!serverStatus) {
        serverStatus = {
            allowAccess: true,
            revokedKeys: [],
            maintenanceMode: false,
            version: "1.0.0"
        };
    }
    
    serverStatus.revokedKeys = revokedKeys;
    serverStatus.lastUpdated = new Date().toISOString();
    
    saveLocalServerStatus();
    updateServerStatusFromData();
}

function toggleMaintenanceMode() {
    if (!serverStatus) {
        loadLocalServerStatus();
        return;
    }
    
    serverStatus.maintenanceMode = !serverStatus.maintenanceMode;
    serverStatus.lastUpdated = new Date().toISOString();
    
    saveLocalServerStatus();
    updateServerStatusFromData();
    
    const mode = serverStatus.maintenanceMode ? 'enabled' : 'disabled';
    console.log(`🔧 Maintenance mode ${mode}`);
}

function toggleKillSwitch() {
    if (!serverStatus) {
        loadLocalServerStatus();
        return;
    }
    
    const newState = !serverStatus.allowAccess;
    
    if (newState === false) {
        if (!confirm('⚠️ WARNING: This will activate the kill switch and block all access. Are you sure?')) {
            return;
        }
    }
    
    serverStatus.allowAccess = newState;
    serverStatus.lastUpdated = new Date().toISOString();
    
    saveLocalServerStatus();
    updateServerStatusFromData();
    
    const action = serverStatus.allowAccess ? 'deactivated' : 'activated';
    console.log(`🚨 Kill switch ${action}`);
}

// Utility function to update output areas
function updateOutput(elementId, content) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = content;
        element.scrollTop = element.scrollHeight;
    }
}

// Auto-format license key input
function setupKeyFormatting() {
    const manageKeyInput = document.getElementById('manageKey');
    if (manageKeyInput) {
        manageKeyInput.addEventListener('input', function(e) {
            let value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
            
            // Format as PSYNC-2024-XXXXXX-XXXXXXXX-XXXXXXXX
            if (value.length > 0) {
                if (!value.startsWith('PSYNC2024')) {
                    if (value.startsWith('PSYNC')) {
                        value = 'PSYNC2024' + value.substring(5);
                    } else {
                        value = 'PSYNC2024' + value;
                    }
                }
                
                let formatted = value.substring(0, 5) + '-' + value.substring(5, 9);
                if (value.length > 9) formatted += '-' + value.substring(9, 15);
                if (value.length > 15) formatted += '-' + value.substring(15, 23);
                if (value.length > 23) formatted += '-' + value.substring(23, 31);
                
                e.target.value = formatted.substring(0, 35);
            }
        });
    }
}

// Initialize when DOM is ready
if (!isNodeJS) {
    document.addEventListener('DOMContentLoaded', function() {
        setupKeyFormatting();
        initializeAdmin();
    });
    
    // Export functions to global scope for HTML onclick handlers
    window.generateKeys = generateKeys;
    window.generateBatchKeys = generateBatchKeys;
    window.validateKey = validateKey;
    window.revokeKey = revokeKey;
    window.restoreKey = restoreKey;
    window.checkKeyStatus = checkKeyStatus;
    window.loadActiveKeys = loadActiveKeys;
    window.exportKeys = exportKeys;
    window.clearRevokedKeys = clearRevokedKeys;
    window.refreshServerStatus = refreshServerStatus;
    window.toggleMaintenanceMode = toggleMaintenanceMode;
    window.toggleKillSwitch = toggleKillSwitch;
}

// Node.js exports
if (isNodeJS) {
    module.exports = {
        generateKeys,
        generateBatchKeys,
        validateKey,
        revokeKey,
        restoreKey,
        checkKeyStatus,
        loadActiveKeys,
        exportKeys,
        clearRevokedKeys,
        refreshServerStatus,
        toggleMaintenanceMode,
        toggleKillSwitch,
        initializeAdmin
    };
} 