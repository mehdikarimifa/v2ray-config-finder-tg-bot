// tester.js
import axios from 'axios';
import { spawn } from 'child_process';
import crypto from 'crypto';
import 'dotenv/config';
import fs from 'fs/promises';
import path from 'path';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { all, initDb } from './database.js';

// --- Configuration ---
const MAX_LATENCY_MS = process.env.MAX_LATENCY_MS ? parseInt(process.env.MAX_LATENCY_MS, 10) : 3000;
const CONCURRENT_TESTS = process.env.CONCURRENT_TESTS ? parseInt(process.env.CONCURRENT_TESTS, 10) : 10;
const TEST_INTERVAL_MINUTES = process.env.TEST_INTERVAL_MINUTES ? parseInt(process.env.TEST_INTERVAL_MINUTES, 10) : 30;
const ENABLE_SPEED_TEST = process.env.ENABLE_SPEED_TEST === 'true';
const SPEED_TEST_URL = process.env.SPEED_TEST_URL || 'http://cachefly.cachefly.net/5mb.test';
const SPEED_TEST_FILE_SIZE_MB = process.env.SPEED_TEST_FILE_SIZE_MB ? parseInt(process.env.SPEED_TEST_FILE_SIZE_MB, 10) : 5;

const SERVICES_TO_TEST = [
    // --- AI Services ---
    {
        hashtag: '#Gemini',
        /**
         * Tests the actual Gemini API using the key.
         * SUCCESS: 200 OK (key is good) or 400 Bad Request (key is bad, but API was reached).
         * FAILURE: 403 Forbidden (region block, as in your example) or connection timeout.
         */
        test: async (agent, browserHeaders, helpers) => {
            const url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent";
            const postData = { "contents": [{"parts": [{"text": "Hello there.."}]}] };
            const config = {
                httpAgent: agent,
                httpsAgent: agent,
                headers: {
                    'x-goog-api-key': "YOUR_GEMINI_API_KEY_HERE",
                    'Content-Type': 'application/json',
                    'User-Agent': 'v2ray-config-tester'
                },
                timeout: 8000
            };

            try {
                await axios.post(url, postData, config);
            } catch (error) {
                if (error.response) {
                    if (error.response.status !== 403) return

                    // 403 Forbidden is what a region-blocked IP gets. This is a FAILURE.
                    // Any other code (500, etc.) is also a FAILURE.
                    throw new Error(`API returned HTTP ${error.response.status}`);
                }
                // No response (e.g., connection timeout). This is a FAILURE.
                throw error;
            }
        }
    },
    { url: 'https://chatgpt.com/cdn-cgi/trace', hashtag: '#ChatGPT' },
    
    // --- Streaming & Music ---
    { 
        hashtag: '#Netflix',
        test: async (agent, browserHeaders, helpers) => {
            const config = { httpAgent: agent, httpsAgent: agent, headers: browserHeaders, timeout: 5000 };
            await helpers.htmlContentCheck(
                'https://www.netflix.com/title/80018499', // A known show URL
                'page is not available', // The failure string to look for
                config
            );
        }
    },
    { url: 'http://googlevideo.com', hashtag: '#YouTube_Music' },
    { 
        hashtag: '#Spotify',
        test: async (agent, browserHeaders, helpers) => {
            const config = { httpAgent: agent, httpsAgent: agent, headers: browserHeaders, timeout: 5000 };
            await helpers.apiPing(
                'https://api.spotify.com/v1/artists/0TnOYISbd1XYRBk9myaseg',
                [401, 403], // Expected auth-error codes
                config
            );
        }
    },

    // --- Social & Communication ---
    { url: 'https://www.tiktok.com/robots.txt', hashtag: '#TikTok' },
    { url: 'https://api.telegram.org/', hashtag: '#Telegram' },
    { url: 'https://discord.com/api/v10/gateway', hashtag: '#Discord' },

    // --- Gaming ---
    { url: 'https://store.steampowered.com/', hashtag: '#Steam' },
    { url: 'https://www.activision.com/robots.txt', hashtag: '#Activision' }
];

// --- Command-line argument parsing ---
const getArg = (argName) => {
    const argIndex = process.argv.indexOf(argName);
    return (argIndex > -1 && process.argv.length > argIndex + 1) ? process.argv[argIndex + 1] : null;
};

// --- Main Tester Logic ---
async function initialize() {
    const singleFilePath = getArg('--file');

    if (singleFilePath) {
        // Run once for a single local file and then exit.
        console.log(`[Tester] Starting in single-file mode for: ${singleFilePath}`);
        await runSingleFileTest(singleFilePath);
        process.exit(0);
    } else {
        // Default scheduled mode, running continuously.
        console.log('[Tester] Starting in scheduled mode. Fetching configs from database.');
        await initDb();
        if (ENABLE_SPEED_TEST) console.log(`[Tester] Full Speed Testing is ENABLED.`);
        else console.log(`[Tester] Quick Latency Testing is ENABLED.`);
        
        runTestCycle();
        setInterval(runTestCycle, TEST_INTERVAL_MINUTES * 60 * 1000);
    }
}

// --- Helper Functions ---
async function getGeoInfo(ip) {
    if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) || ip.startsWith('192.168') || ip.startsWith('10.') || ip === '127.0.0.1') {
        return { countryCode: 'XX', countryName: 'Private/Invalid IP' };
    }
    try {
        const response = await axios.get(`http://ip-api.com/json/${ip}?fields=country,countryCode`);
        return { countryCode: response.data.countryCode || 'XX', countryName: response.data.country || 'Unknown' };
    } catch (error) {
        return { countryCode: 'XX', countryName: 'Error' };
    }
}

function parseConfigsFromText(text) {
    const lines = text.split('\n');
    const protocolsToTest = ['vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://'];
    const configs = new Set();
    for (const line of lines) {
        const trimmedLine = line.trim();
        if (protocolsToTest.some(p => trimmedLine.startsWith(p))) {
            configs.add(trimmedLine);
        }
    }
    return Array.from(configs);
}

function parseLink(link) {
    const hashIndex = link.indexOf('#');
    const configPart = hashIndex === -1 ? link : link.substring(0, hashIndex);
    const namePart = hashIndex === -1 ? '' : decodeURIComponent(link.substring(hashIndex + 1));
    const protocol = configPart.split('://')[0];

    try {
        let details = {};
        switch (protocol) {
            case 'vmess':
                details = JSON.parse(Buffer.from(configPart.substring(8), 'base64').toString());
                break;
            case 'vless':
            case 'trojan': {
                const url = new URL(configPart);
                details = { id: url.username, add: url.hostname, port: parseInt(url.port) };
                url.searchParams.forEach((value, key) => { details[key] = value; });
                break;
            }
            case 'ss': {
                const url = new URL(configPart);
                const userInfo = Buffer.from(url.username, 'base64').toString();
                const [method, password] = userInfo.split(':');
                details = { method, password, add: url.hostname, port: parseInt(url.port) };
                break;
            }
            case 'hysteria2': {
                const url = new URL(configPart);
                details = { id: url.username, add: url.hostname, port: parseInt(url.port), sni: url.searchParams.get('sni'), insecure: url.searchParams.get('insecure') === '1' };
                break;
            }
            default: return null;
        }
        details.ps = namePart || details.ps || `${details.add}:${details.port}`;
        return { protocol, details };
    } catch (e) { return null; }
}

async function testConfig(originalLink, testPort) {
    const parsed = parseLink(originalLink);
    if (!parsed || !parsed.details.add || !parsed.details.port) return null;
    
    const { protocol, details } = parsed;
    let outboundConfig;
    try {
        switch (protocol) {
             case 'vmess': outboundConfig = { protocol, settings: { vnext: [{ address: details.add, port: details.port, users: [{ id: details.id, alterId: details.aid || 0, security: details.scy || 'auto' }] }] }, streamSettings: { network: details.net, security: details.tls, wsSettings: { path: details.path, headers: { Host: details.host } }, tlsSettings: { serverName: details.sni || details.host } } }; break;
             case 'vless': outboundConfig = { protocol, settings: { vnext: [{ address: details.add, port: details.port, users: [{ id: details.id, flow: details.flow, encryption: "none" }] }] }, streamSettings: { network: details.type, security: details.security, realitySettings: details.security === 'reality' ? { publicKey: details.pbk, shortId: details.sid, fingerprint: details.fp || 'chrome' } : undefined, wsSettings: { path: details.path, headers: { Host: details.host } }, tlsSettings: { serverName: details.sni } } }; break;
             case 'trojan': outboundConfig = { protocol, settings: { servers: [{ address: details.add, port: details.port, password: details.id }] }, streamSettings: { security: details.security || 'tls', tlsSettings: { serverName: details.sni }, wsSettings: { path: details.path, headers: { Host: details.host } } } }; break;
             case 'ss': outboundConfig = { protocol: "shadowsocks", settings: { servers: [{ address: details.add, port: details.port, method: details.method, password: details.password }] } }; break;
             case 'hysteria2': outboundConfig = { protocol, settings: { servers: [{ address: details.add, port: details.port, password: details.id }] }, streamSettings: { network: 'udp', security: 'tls', tlsSettings: { serverName: details.sni, insecure: details.insecure, alpn: ["h3"] } } }; break;
             default: return null;
        }
    } catch (e) { return null; }
    
    const testJson = { log: { loglevel: "none" }, inbounds: [{ port: testPort, listen: "127.0.0.1", protocol: "socks" }], outbounds: [outboundConfig] };
    const tempConfigPath = `./tmp/temp_config_${crypto.randomBytes(4).toString('hex')}.json`;
    let xrayProcess;

    try {
        await fs.writeFile(tempConfigPath, JSON.stringify(testJson));
        xrayProcess = spawn('./xray', ['-c', tempConfigPath]);
        
        await new Promise(resolve => setTimeout(resolve, 300)); // Give Xray a moment to start

        const agent = new SocksProxyAgent(`socks5://127.0.0.1:${testPort}`);
        const startTime = Date.now();
        
        const browserHeaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'
        };

        await axios.get("http://www.gstatic.com/generate_204", { httpAgent: agent, httpsAgent: agent, timeout: MAX_LATENCY_MS });
        const latency = Date.now() - startTime;

        // Services Testing
        const workingServices = [];
        for (const service of SERVICES_TO_TEST) {
            try {
                // Pass the agent, headers, and our collection of helpers
                // Each service.test() contains its own logic now
                if (!service.test) return

                await service.test(agent, browserHeaders, testHelpers);
                
                // If it doesn't throw an error, it's a success
                workingServices.push(service.hashtag);
                console.log(`[${service.hashtag}] success for ${details.ps}`);
                
            } catch (serviceError) {
                // This catches all failures (timeouts, 403s, content blocks, etc.)
                const reason = serviceError.response ? `HTTP ${serviceError.response.status}` : serviceError.message;
                console.log(`[${service.hashtag}] failed (${reason}) for ${details.ps}`);
            }
        }

        let speedMbps = null;
        if (ENABLE_SPEED_TEST) {
            const speedStartTime = Date.now();
            await axios.get(SPEED_TEST_URL, { httpAgent: agent, httpsAgent: agent, timeout: 20000, responseType: 'arraybuffer' });
            const speedEndTime = Date.now();
            const durationSeconds = (speedEndTime - speedStartTime) / 1000;
            if (durationSeconds > 0) {
                 speedMbps = ((SPEED_TEST_FILE_SIZE_MB * 8) / durationSeconds).toFixed(2);
            }
        }
        
        const geo = await getGeoInfo(details.add);
        
        console.log(`✅ [SUCCESS] (${latency}ms) | Speed: ${speedMbps ? speedMbps + 'Mbps' : 'N/A'} | ${geo.countryName} | ${details.ps}`);
        return { config: originalLink, latency, speedMbps, ...geo, name: details.ps, tags: workingServices };

    } catch (error) {
        const reason = error.code === 'ECONNABORTED' ? 'Timeout' : error.message;
        console.log(`❌ [FAIL] (${reason}) ${details.ps}`);
        return null;
    } finally {
        if (xrayProcess) xrayProcess.kill();
        await fs.unlink(tempConfigPath).catch(() => {});
    }
}

async function processAndTestConfigs(configsToTest, sourceName) {
    console.log(`[Tester] Found ${configsToTest.length} configs from ${sourceName}. Starting tests...`);
    const workingConfigs = [];

    for (let i = 0; i < configsToTest.length; i += CONCURRENT_TESTS) {
        const batch = configsToTest.slice(i, i + CONCURRENT_TESTS);
        console.log(`--- Testing batch ${Math.floor(i / CONCURRENT_TESTS) + 1} of ${Math.ceil(configsToTest.length / CONCURRENT_TESTS)} ---`);
        const testPromises = batch.map((config, index) => testConfig(config, 20800 + index));
        const results = await Promise.all(testPromises);
        workingConfigs.push(...results.filter(Boolean));
    }

    if (workingConfigs.length > 0) {
        workingConfigs.sort((a, b) => (b.tags.length - a.tags.length) || (b.speedMbps || 0) - (a.speedMbps || 0) || a.latency - b.latency);
        
        const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '');
        const filename = `./results/${sourceName}_${timestamp}.json`;
        
        await fs.writeFile(filename, JSON.stringify(workingConfigs, null, 2));
        console.log(`\n[Tester] ✅ Success! Saved ${workingConfigs.length} working configs to ${filename}\n`);
    } else {
        console.log(`\n[Tester] ❌ No working configs found for source: ${sourceName}\n`);
    }
}

async function runSingleFileTest(filePath) {
    try {
        const fileContent = await fs.readFile(filePath, 'utf-8');
        const configs = parseConfigsFromText(fileContent);

        if (configs.length === 0) {
            console.log(`[Tester] No valid configs found in ${filePath}.`);
            return;
        }
        
        const sourceName = path.basename(filePath, path.extname(filePath));
        await processAndTestConfigs(configs, sourceName);

    } catch (error) {
        if (error.code === 'ENOENT') {
            console.error(`[Tester] Error: File not found at path: ${filePath}`);
        } else {
            console.error(`[Tester] A critical error occurred during the single file test:`, error);
        }
        process.exit(1);
    }
}

async function runTestCycle() {
    console.log(`\n[Tester] Starting new test cycle at ${new Date().toISOString()}`);
    try {
        let sources = await all("SELECT * FROM config_files");
        if (sources.length === 0) { console.log("[Tester] No sources in database. Skipping cycle."); return; }

        sources = sources.sort(() => 0.5 - Math.random())
        for (const source of sources) {
            console.log(`[Tester] Fetching source: ${source.url}`);
            try {
                const response = await axios.get(source.url, { timeout: 5000 });
                const configs = parseConfigsFromText(response.data);
                
                if (configs.length > 0) {
                    const sourceName = new URL(source.url).pathname.split('/').pop().replace('.txt', '');
                    await processAndTestConfigs(configs, sourceName);
                } else {
                    console.log(`[Tester] No valid configs found in ${source.url}`);
                }
            } catch (error) {
                console.error(`[Tester] Failed to process source ${source.url}:`, error.message);
            }
        }
    } catch (error) {
        console.error("[Tester] A critical error occurred during the test cycle:", error);
    }
}

const testHelpers = {
    /**
     * Performs a simple GET request. Fails on any non-200 status.
     * @param {string} url - The URL to test.
     * @param {object} config - The axios config (with agent, headers, etc.).
     */
    simpleGet: async (url, config) => {
        await axios.get(url, config); // Throws on non-2xx
    },

    /**
     * Performs a GET and checks for a failure string in the HTML.
     * @param {string} url - The URL to test.
     * @param {string} failureString - The lowercase string to check for in the HTML.
     * @param {object} config - The axios config.
     */
    htmlContentCheck: async (url, failureString, config) => {
        const response = await axios.get(url, config);
        const responseBody = String(response.data).toLowerCase();
        if (failureString && responseBody.includes(failureString.toLowerCase())) {
            throw new Error('Content block detected');
        }
    },

    /**
     * Performs an API GET/POST where an auth error (e.g., 401, 403)
     * is considered a SUCCESS (we reached the API).
     * @param {string} url - The API endpoint.
     * @param {number[]} expectedFailureCodes - e.g., [401, 403]
     * @param {object} config - The axios config.
     * @param {string} [method='get'] - 'get' or 'post'.
     * @param {object} [postData=null] - Data for POST requests.
     */
    apiPing: async (url, expectedFailureCodes, config, method = 'get', postData = null) => {
        try {
            const args = (method === 'post') ? [url, postData, config] : [url, config];
            await axios[method](...args);
            
            // If we got 200 OK, but expected an error
            if (expectedFailureCodes.length > 0) {
                throw new Error('API returned 200 OK, but expected an auth error.');
            }
            // else: 200 OK was expected, this is a pass.
        } catch (error) {
            // This is a SUCCESS if we got the *expected* auth error
            if (error.response && expectedFailureCodes.includes(error.response.status)) {
                return; // Success! We reached the API.
            }
            // This is a REAL failure (region block, timeout, 500, etc.)
            throw error;
        }
    }
};


initialize();