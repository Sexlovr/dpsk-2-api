import { chromium } from 'playwright-core';
import { existsSync } from 'fs';

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
    // Docker env var takes priority
    if (process.env.CHROME_EXECUTABLE_PATH && existsSync(process.env.CHROME_EXECUTABLE_PATH)) {
        return process.env.CHROME_EXECUTABLE_PATH;
    }
    for (const c of CHROME_CANDIDATES) {
        if (c && existsSync(c)) return c;
    }
    return undefined;
}

/**
 * Login to DeepSeek using a real browser (headful via Xvfb in Docker).
 * @param {string} email
 * @param {string} password
 * @param {object} opts  { headless: false, timeout: 90000 }
 * @returns {Promise<{token: string, userId: string}>}
 */
export async function playwrightLogin(email, password, opts = {}) {
    const headless = opts.headless === true; // default false (headful for WAF bypass)
    const timeout = opts.timeout || 90000;
    const executablePath = findChrome();

    console.log(`[PW] Launching browser to login ${email} (headless=${headless}, exe=${executablePath || 'bundled'})...`);

    const browser = await chromium.launch({
        executablePath,
        headless,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage',
        ],
    });

    let capturedToken = null;

    try {
        const context = await browser.newContext({
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
            viewport: { width: 1280, height: 800 },
        });

        const page = await context.newPage();

        // Intercept all requests to capture the auth token
        page.on('request', (req) => {
            const auth = req.headers()['authorization'];
            if (auth && auth.startsWith('Bearer ') && req.url().includes('deepseek.com')) {
                const tok = auth.slice(7).trim();
                if (tok.length > 20) {
                    capturedToken = tok;
                    console.log(`[PW] Captured Bearer token (${tok.slice(0, 16)}...)`);
                }
            }
        });

        // Also sniff responses for token in JSON body
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
        console.log(`[PW] Navigating to ${DS_LOGIN_URL}...`);
        await page.goto(DS_LOGIN_URL, { waitUntil: 'networkidle', timeout });

        console.log(`[PW] Page loaded. URL: ${page.url()}`);

        // Wait for email input
        const emailSel = 'input[type="email"], input[name="email"], input[placeholder*="mail"], input[placeholder*="Mail"], input[placeholder*="phone"]';
        await page.waitForSelector(emailSel, { timeout: 30000 });
        await page.fill(emailSel, email);
        console.log(`[PW] Email filled.`);

        // Fill password
        await page.waitForSelector('input[type="password"]', { timeout: 10000 });
        await page.fill('input[type="password"]', password);
        console.log(`[PW] Password filled.`);

        // Click login - try multiple selectors
        const loginBtn = page.locator('button[type="submit"], button:has-text("Log In"), button:has-text("Sign In"), button:has-text("Login"), button:has-text("Log in"), button:has-text("Sign in")').first();
        await loginBtn.waitFor({ state: 'visible', timeout: 10000 });
        await loginBtn.click();
        console.log(`[PW] Login button clicked. Waiting for token...`);

        // Wait up to 30s for token to appear
        const deadline = Date.now() + 30000;
        while (!capturedToken && Date.now() < deadline) {
            await page.waitForTimeout(500);
        }

        if (!capturedToken) {
            // Try localStorage
            capturedToken = await page.evaluate(() => {
                return localStorage.getItem('userToken') ||
                       localStorage.getItem('Authorization') ||
                       localStorage.getItem('token') || null;
            }).catch(() => null);
        }

        if (!capturedToken) {
            // Dump current URL and title for debugging
            const url = page.url();
            const title = await page.title();
            throw new Error(`Could not capture token. Current page: ${url} (${title})`);
        }

        console.log(`[PW] Login success for ${email}!`);
        return { token: capturedToken, userId: email };

    } finally {
        await browser.close().catch(() => {});
    }
}
