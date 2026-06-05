import { chromium } from 'playwright-core';
import { existsSync } from 'fs';
import os from 'os';

const DS_LOGIN_URL = 'https://chat.deepseek.com/sign_in';

const CHROME_CANDIDATES = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    (process.env.LOCALAPPDATA || '') + '\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
];

function findChrome() {
    for (const c of CHROME_CANDIDATES) {
        if (c && existsSync(c)) return c;
    }
    return undefined; // let playwright use its own bundled browser
}

/**
 * Login to DeepSeek using a real headless browser.
 * @param {string} email
 * @param {string} password
 * @param {object} opts  { headless: true, timeout: 60000 }
 * @returns {Promise<{token: string, userId: string}>}
 */
export async function playwrightLogin(email, password, opts = {}) {
    const headless = opts.headless !== false; // default true
    const timeout = opts.timeout || 90000;

    console.log(`[PW] Launching browser to login ${email} (headless=${headless})...`);

    let executablePath;
    // find chrome synchronously
    const { existsSync } = await import('fs');
    const chromeCandidates = [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        (process.env.LOCALAPPDATA || '') + '\\Google\\Chrome\\Application\\chrome.exe',
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/usr/bin/google-chrome',
        '/usr/bin/chromium-browser',
        '/usr/bin/chromium',
    ];
    for (const c of chromeCandidates) {
        if (c && existsSync(c)) { executablePath = c; break; }
    }

    const browser = await chromium.launch({
        executablePath,     // undefined = playwright uses its bundled browser
        headless,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-blink-features=AutomationControlled',
        ],
    });

    let capturedToken = null;

    try {
        const context = await browser.newContext({
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            viewport: { width: 1280, height: 800 },
        });

        const page = await context.newPage();

        // Intercept all requests to capture the auth token from API calls
        page.on('request', (req) => {
            const auth = req.headers()['authorization'];
            if (auth && auth.startsWith('Bearer ') && req.url().includes('chat.deepseek.com')) {
                const tok = auth.slice(7).trim();
                if (tok.length > 20) {
                    capturedToken = tok;
                    console.log(`[PW] Captured Bearer token (${tok.slice(0, 16)}...)`);
                }
            }
        });

        // Also sniff responses for user token in JSON body
        page.on('response', async (resp) => {
            if (capturedToken) return;
            try {
                if (resp.url().includes('/api/v0/users/login') || resp.url().includes('/auth')) {
                    const text = await resp.text().catch(() => '');
                    const m = text.match(/"token"\s*:\s*"([^"]{20,})"/);
                    if (m) {
                        capturedToken = m[1];
                        console.log(`[PW] Captured token from response body`);
                    }
                }
            } catch { /* ignore */ }
        });

        // Navigate to sign in page
        await page.goto(DS_LOGIN_URL, { waitUntil: 'domcontentloaded', timeout });

        console.log(`[PW] Page loaded. Filling credentials...`);

        // Fill email
        await page.waitForSelector('input[type="email"], input[name="email"], input[placeholder*="mail"]', { timeout: 20000 });
        await page.fill('input[type="email"], input[name="email"], input[placeholder*="mail"]', email);

        // Fill password
        await page.waitForSelector('input[type="password"]', { timeout: 10000 });
        await page.fill('input[type="password"]', password);

        // Click login button
        const loginBtn = page.locator('button[type="submit"], button:has-text("Log in"), button:has-text("Sign in"), button:has-text("Login")').first();
        await loginBtn.click();

        console.log(`[PW] Login submitted. Waiting for token capture...`);

        // Wait up to 30 seconds for token to appear
        const deadline = Date.now() + 30000;
        while (!capturedToken && Date.now() < deadline) {
            await page.waitForTimeout(500);
        }

        if (!capturedToken) {
            // Last resort: try reading from localStorage
            capturedToken = await page.evaluate(() => {
                return localStorage.getItem('userToken') ||
                       localStorage.getItem('Authorization') ||
                       localStorage.getItem('token') || null;
            }).catch(() => null);
        }

        if (!capturedToken) {
            throw new Error('Could not capture Bearer token — login may have failed or 2FA required');
        }

        console.log(`[PW] Login success for ${email}!`);
        return { token: capturedToken, userId: email };

    } finally {
        await browser.close().catch(() => {});
    }
}
