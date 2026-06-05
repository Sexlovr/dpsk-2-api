import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { TextEncoder } from 'util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DS_BASE = 'https://chat.deepseek.com';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36';

// ══════════════════════════════════════════
//  WASM PoW Solver
// ══════════════════════════════════════════
let wasmExports = null;
let CACHE = null;

function getUint8Memory() {
    if (!CACHE || CACHE.buffer !== wasmExports.memory.buffer) {
        CACHE = new Uint8Array(wasmExports.memory.buffer);
    }
    return CACHE;
}

const encoder = new TextEncoder();
function passStringToWasm(arg, malloc) {
    const buf = encoder.encode(arg);
    const ptr = malloc(buf.length, 1);
    getUint8Memory().subarray(ptr, ptr + buf.length).set(buf);
    return [ptr, buf.length];
}

export async function initWasm() {
    if (wasmExports) return;
    const wasmPath = path.join(__dirname, '..', 'sha3_wasm_bg.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);
    const wasmModule = await WebAssembly.instantiate(wasmBuffer);
    wasmExports = wasmModule.instance.exports;
    console.log('[WASM] sha3_wasm_bg.wasm loaded successfully');
}

export async function solvePow(challengeStr, saltStr, expireAtInt, difficultyInt) {
    await initWasm();

    // DeepSeek frontend constructs prefix: `${salt}_${expireAt}_`
    const prefix = `${saltStr}_${expireAtInt}_`;

    const [cPtr, cLen] = passStringToWasm(challengeStr, wasmExports.__wbindgen_export_0);
    const [pPtr, pLen] = passStringToWasm(prefix, wasmExports.__wbindgen_export_0);

    const retPtr = wasmExports.__wbindgen_add_to_stack_pointer(-16);

    wasmExports.wasm_solve(retPtr, cPtr, cLen, pPtr, pLen, difficultyInt);

    const view = new DataView(wasmExports.memory.buffer);
    const success = view.getInt32(retPtr, true);
    const answer = view.getFloat64(retPtr + 8, true);

    wasmExports.__wbindgen_add_to_stack_pointer(16);

    if (success === 0) {
        throw new Error('WASM solver failed — difficulty loop exhausted');
    }
    return answer;
}

// ══════════════════════════════════════════
//  DeepSeek API calls
// ══════════════════════════════════════════

export async function login(email, password) {
    const res = await fetch(`${DS_BASE}/api/v0/users/login`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'origin': DS_BASE,
            'user-agent': UA
        },
        body: JSON.stringify({
            email,
            password,
            area_code: '+1',
            mobile: ''
        })
    });

    const rawText = await res.text();
    let json;
    try {
        json = JSON.parse(rawText);
    } catch (e) {
        throw new Error(`Login failed to parse JSON. HTTP ${res.status}. Raw body: ${rawText.slice(0, 200)}...`);
    }

    if (json.code !== 0 || !json.data?.biz_data?.user?.token) {
        throw new Error(`Login failed: ${json.data?.biz_msg || json.msg || res.status}`);
    }
    return {
        token: json.data.biz_data.user.token,
        userId: json.data.biz_data.user.id || email
    };
}

export async function createPowChallenge(token) {
    const res = await fetch(`${DS_BASE}/api/v0/chat/create_pow_challenge`, {
        method: 'POST',
        headers: {
            'authorization': `Bearer ${token}`,
            'content-type': 'application/json',
            'origin': DS_BASE,
            'user-agent': UA
        },
        body: JSON.stringify({ target_path: '/api/v0/chat/completion' })
    });

    if (!res.ok) throw new Error(`create_pow_challenge HTTP ${res.status}`);
    const json = await res.json();
    if (json.code !== 0) throw new Error(`create_pow_challenge API error: ${json.msg}`);
    return json.data.biz_data.challenge;
}

export async function createNewChat(token) {
    const res = await fetch(`${DS_BASE}/api/v0/chat_session/create`, {
        method: 'POST',
        headers: {
            'authorization': `Bearer ${token}`,
            'content-type': 'application/json',
            'origin': DS_BASE,
            'user-agent': UA
        },
        body: JSON.stringify({ character_id: null })
    });
    if (!res.ok) throw new Error(`Failed to create chat session: ${res.status}`);
    const data = await res.json();
    if (!data.data?.biz_data?.chat_session?.id) throw new Error('Invalid create_chat response');
    return data.data.biz_data.chat_session.id;
}

/**
 * Full PoW solve pipeline: challenge -> solve -> return response header payload
 */
export async function generatePowHeader(token) {
    const challenge = await createPowChallenge(token);
    const { algorithm, challenge: chal, salt, difficulty, signature, expire_at } = challenge;

    console.log(`[PoW] Solving: difficulty=${difficulty}, salt=${salt.slice(0, 8)}...`);
    const t0 = Date.now();
    const answer = await solvePow(chal, salt, expire_at, difficulty);
    console.log(`[PoW] Solved in ${Date.now() - t0}ms => answer=${answer}`);

    return {
        algorithm,
        challenge: chal,
        salt,
        answer,
        signature,
        target_path: challenge.target_path || '/api/v0/chat/completion'
    };
}

/**
 * Send a chat completion to DeepSeek and yield SSE data objects.
 */
export async function* sendChatCompletion(token, payload, signal, powResponse) {
    const powHeader = Buffer.from(JSON.stringify(powResponse)).toString('base64');
    const headers = {
        'authorization': `Bearer ${token}`,
        'content-type': 'application/json',
        'origin': DS_BASE,
        'referer': `${DS_BASE}/a/chat/s/${payload.chat_session_id}`,
        'user-agent': UA,
        'x-ds-pow-response': powHeader
    };

    const res = await fetch(`${DS_BASE}/api/v0/chat/completion`, {
        method: 'POST',
        signal,
        headers,
        body: JSON.stringify(payload)
    });

    if (!res.ok) {
        const errBody = await res.text().catch(() => '');
        throw new Error(`Upstream ${res.status}: ${errBody.slice(0, 200)}`);
    }

    // SSE stream parser — works with both native fetch (ReadableStream) and node-fetch (Node stream)
    let buffer = '';

    if (typeof res.body.getReader === 'function') {
        const reader = res.body.getReader();
        const decoder = new TextDecoder('utf-8');
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop();
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const d = line.slice(6);
                    if (!d) continue;
                    try { yield JSON.parse(d); } catch {}
                }
            }
        }
    } else {
        for await (const chunk of res.body) {
            buffer += chunk.toString('utf-8');
            const lines = buffer.split('\n');
            buffer = lines.pop();
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const d = line.slice(6);
                    if (!d) continue;
                    try { yield JSON.parse(d); } catch {}
                }
            }
        }
    }
}
