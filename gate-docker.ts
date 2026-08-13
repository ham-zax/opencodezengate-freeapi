#!/usr/bin/env bun

/**
 * ZenGate — Per-Key IP Pool Reverse Proxy Gateway
 *
 * Each API Key has an independent proxy slot pool (up to SLOTS_PER_KEY)
 * Up to MAX_ACTIVE_KEYS keys concurrently active globally
 * Automatic slot replacement on failure, automatic release on timeout
 * WARP acts as global shared fallback
 */

import https from 'node:https';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { HttpsProxyAgent } from 'hpagent';
import { SocksProxyAgent } from 'socks-proxy-agent';

// ═══════════════════════════════════════════════════════════
//  Type Definitions
// ═══════════════════════════════════════════════════════════

interface ProxyItem {
  address: string;
  protocol: string;
  latency: number;
  quality_grade: string;
}

interface Slot {
  addr: string;
  url: string;
  proto: 'http' | 'socks5';
  latencyMs: number;
  qualityGrade: string;
}

interface KeySlotPool {
  keyId: string;
  slots: Slot[];
  rrCursor: number;
  lastUsedAt: number;
}

interface CandidateItem extends ProxyItem {
  lockedBy: string | null;
}

// ═══════════════════════════════════════════════════════════
//  Persistence File Paths
// ═══════════════════════════════════════════════════════════

const KEYS_FILE = path.join(process.cwd(), 'keys.json');
const SOURCES_FILE = path.join(process.cwd(), 'sources.json');
const CUSTOM_PROXIES_FILE = path.join(process.cwd(), 'custom_proxies.json');
const AUDIT_FILE = path.join(process.cwd(), 'audit.jsonl');

// ═══════════════════════════════════════════════════════════
//  Proxy source configuration (dynamic, persisted to sources.json)
// ═══════════════════════════════════════════════════════════

const DEFAULT_SOURCES = [
  {
    name: 'amux',
    url: 'https://proxy.amux.ai/api/proxies',
    type: 'json' as const,
    parser: (data: any): ProxyItem[] => {
      const list: any[] = Array.isArray(data) ? data : [];
      return list
        .filter((p) => ['S','A','B','C'].includes(p.quality_grade) && p.status === 'active')
        .map((p) => ({ address: p.address, protocol: p.protocol, latency: p.latency || 999, quality_grade: p.quality_grade }));
    },
  },
  {
    name: 'speedx-socks5',
    url: 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt',
    type: 'text' as const,
    parser: (data: string): ProxyItem[] => {
      return data.split('\n')
        .map(line => line.trim())
        .filter(line => line && /^\d+\.\d+\.\d+\.\d+:\d+$/.test(line))
        .map(line => ({ address: line, protocol: 'socks5', latency: 999, quality_grade: 'C' }));
    },
  },
];

let proxySources: typeof DEFAULT_SOURCES = [];

function loadSources() {
  try {
    const raw = JSON.parse(fs.readFileSync(SOURCES_FILE, 'utf-8'));
    // Parsers cannot be serialized; match by name using default source parsers on restoration
    proxySources = raw.map((s: any) => {
      const def = DEFAULT_SOURCES.find(d => d.name === s.name);
      return {
        name: s.name,
        url: s.url,
        type: s.type || 'json',
        parser: def ? def.parser : DEFAULT_SOURCES[0].parser,
      };
    });
    console.log(`[Sources] Loaded ${proxySources.length} proxy sources`);
  } catch {
    proxySources = DEFAULT_SOURCES.map(s => ({ ...s }));
    saveSources();
  }
}

function saveSources() {
  try {
    const data = proxySources.map(s => ({ name: s.name, url: s.url, type: s.type }));
    fs.writeFileSync(SOURCES_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (e: any) {
    console.error(`[Sources] Save failed: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════
//  Custom Proxy Persistence
// ═══════════════════════════════════════════════════════════

let customProxyItems: ProxyItem[] = [];

function loadCustomProxies() {
  try {
    const data = JSON.parse(fs.readFileSync(CUSTOM_PROXIES_FILE, 'utf-8'));
    customProxyItems = Array.isArray(data) ? data : [];
    console.log(`[Custom Proxies] Loaded ${customProxyItems.length} items`);
  } catch {
    customProxyItems = [];
  }
}

function saveCustomProxies() {
  try {
    fs.writeFileSync(CUSTOM_PROXIES_FILE, JSON.stringify(customProxyItems, null, 2), 'utf-8');
  } catch (e: any) {
    console.error(`[Custom Proxies] Save failed: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════

const UPSTREAM = 'https://opencode.ai/zen';
const PORT = parseInt(process.env.PORT || '13339');
const MAX_RETRIES = 3;
const TIMEOUT = 15000;
const STREAM_TIMEOUT = 60000;

const MAX_ACTIVE_KEYS = 20;
const SLOTS_PER_KEY = 3;
const POOL_CLEANUP_MS = 60000;
const KEY_IDLE_RELEASE_MS = 600000;

const PROXY_PROBE_TIMEOUT = parseInt(process.env.PROXY_PROBE_TIMEOUT || '8000');
const PROXY_REFRESH_MS = parseInt(process.env.PROXY_REFRESH_MS || '300000');
const CUSTOM_PROXIES = process.env.CUSTOM_PROXIES || '';
const ZENPROXY_RELAY = process.env.ZENPROXY_RELAY || 'https://zenproxy.top/api/relay';
const ZENPROXY_KEY = process.env.ZENPROXY_KEY || '';
const FORCE_RELAY = process.env.FORCE_RELAY === '1';

const WARP_MODE = process.env.WARP_MODE || 'off';
const WARP_SOCKS5_PORT = parseInt(process.env.WARP_SOCKS5_PORT || '1080');
const WARP_HOST = process.env.WARP_HOST || '127.0.0.1';

// ═══════════════════════════════════════════════════════════
//  Global State
// ═══════════════════════════════════════════════════════════

let warpModeRuntime = WARP_MODE;
let warpHostRuntime = WARP_HOST;
let warpPortRuntime = WARP_SOCKS5_PORT;
let warpStatus: 'unknown' | 'running' | 'stopped' = 'unknown';
let warpSlot: Slot | null = null;
let warpConsecutiveFails = 0;
let warpSkipUntil = 0;

let cachedModels: any[] = [];
let cachedModelsTime = 0;

const API_KEY = process.env.API_KEY || 'admin123';

let candidates: CandidateItem[] = [];
let customSlots: Slot[] = [];
const PROXY_MAX_FAILS = 3;
let proxyFailCount = new Map<string, number>();
let keySlotPools: Map<string, KeySlotPool> = new Map();
let refreshing = false;

const START_TIME = Date.now();
const stats = { total: 0, success: 0, rateLimited: 0, errors: 0 };
const recentLogs: string[] = [];
const MAX_LOGS = 500;

// ═══════════════════════════════════════════════════════════
//  Audit & API Key Management
// ═══════════════════════════════════════════════════════════

interface AuditEntry {
  ts: number;
  keyId: string;
  model: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  cacheCreation: number;
  cacheRead: number;
  latencyMs: number;
  status: number;
  slotAddr: string;
}
const auditLog: AuditEntry[] = [];
const MAX_AUDIT = 10000;

interface ApiKeyRecord {
  key: string;
  name: string;
  enabled: boolean;
  createdAt: number;
  lastUsedAt: number;
  totalRequests: number;
  totalTokens: number;
  maxConcurrency: number;
  maxRequests: number;
  requestCount: number;
  expiresAt: number;
}
let apiKeys: Record<string, ApiKeyRecord> = {};
let activeRequests: Record<string, number> = {};

function loadKeys() {
  try {
    const data = fs.readFileSync(KEYS_FILE, 'utf-8');
    apiKeys = JSON.parse(data);
    console.log(`[Keys] Loaded ${Object.keys(apiKeys).length} API Keys`);
  } catch {
    apiKeys = {};
    saveKeys();
  }
  if (!apiKeys[API_KEY]) {
    apiKeys[API_KEY] = {
      key: API_KEY, name: 'default', enabled: true, createdAt: Date.now(),
      lastUsedAt: 0, totalRequests: 0, totalTokens: 0,
      maxConcurrency: 0, maxRequests: 0, requestCount: 0, expiresAt: 0,
    };
    saveKeys();
  } else {
    const r = apiKeys[API_KEY];
    if (r.maxConcurrency === undefined) r.maxConcurrency = 0;
    if (r.maxRequests === undefined) r.maxRequests = 0;
    if (r.requestCount === undefined) r.requestCount = 0;
    if (r.expiresAt === undefined) r.expiresAt = 0;
  }
}

function saveKeys() {
  try {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(apiKeys, null, 2), 'utf-8');
  } catch (e: any) {
    console.error(`[Keys] Save failed: ${e.message}`);
  }
}

function validateKey(key: string): { ok: boolean; reason?: string } {
  const record = apiKeys[key];
  if (!record) return { ok: false, reason: 'Key not found' };
  if (!record.enabled) return { ok: false, reason: 'Key is disabled' };
  if (record.expiresAt > 0 && Date.now() > record.expiresAt) return { ok: false, reason: 'Key is expired' };
  if (record.maxRequests > 0 && record.requestCount >= record.maxRequests) return { ok: false, reason: 'Request limit reached' };
  if (record.maxConcurrency > 0 && (activeRequests[key] || 0) >= record.maxConcurrency) return { ok: false, reason: 'Concurrency limit reached' };
  return { ok: true };
}

function acquireKey(key: string) {
  activeRequests[key] = (activeRequests[key] || 0) + 1;
}

function releaseKey(key: string) {
  if (activeRequests[key] && activeRequests[key] > 0) activeRequests[key]--;
}

function recordKeyUsage(key: string, tokens: number) {
  const record = apiKeys[key];
  if (record) {
    record.lastUsedAt = Date.now();
    record.totalRequests++;
    record.requestCount++;
    record.totalTokens += tokens;
    saveKeys();
  }
}

// ═══════════════════════════════════════════════════════════
//  Log Capture
// ═══════════════════════════════════════════════════════════

function logCapture(s: string) {
  const line = `[${new Date().toLocaleTimeString()}] ${s}`;
  recentLogs.push(line);
  if (recentLogs.length > MAX_LOGS) recentLogs.shift();
}
const _origLog = console.log;
console.log = (...args: any[]) => {
  const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
  logCapture(msg);
  _origLog.apply(console, args);
};
const _origWarn = console.warn;
console.warn = (...args: any[]) => {
  const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
  logCapture(`⚠️ ${msg}`);
  _origWarn.apply(console, args);
};
const _origError = console.error;
console.error = (...args: any[]) => {
  const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
  logCapture(`❌ ${msg}`);
  _origError.apply(console, args);
};

const FORWARD = [
  'authorization', 'x-opencode-project', 'x-opencode-session',
  'x-opencode-request', 'x-opencode-client', 'content-type',
  'accept', 'anthropic-version', 'anthropic-beta', 'user-agent',
];

// ═══════════════════════════════════════════════════════════
//  Custom Proxies (Fallback standby)
// ═══════════════════════════════════════════════════════════

function parseCustomProxies(input: string): ProxyItem[] {
  if (!input.trim()) return [];
  return input.split(',').map((addr) => {
    const trimmed = addr.trim();
    if (!trimmed) return null;
    const isSocks = trimmed.startsWith('socks5://') || trimmed.startsWith('socks5h://');
    return {
      address: trimmed.replace(/^https?:\/\//, '').replace(/^socks5h?:\/\//, ''),
      protocol: isSocks ? 'socks5' : 'http',
      latency: 0,
      quality_grade: 'custom',
    };
  }).filter((p): p is ProxyItem => p !== null);
}

async function initCustomSlots(): Promise<void> {
  if (!CUSTOM_PROXIES) return;
  const items = parseCustomProxies(CUSTOM_PROXIES);
  if (items.length === 0) return;
  const results = await Promise.all(items.map(async (item) => {
    const r = await probe(item);
    return { item, ...r };
  }));
  for (const r of results) {
    if (!r.ok) continue;
    const url = r.item.protocol === 'socks5' ? `socks5h://${r.item.address}` : `http://${r.item.address}`;
    customSlots.push({ addr: r.item.address, url, proto: r.item.protocol as 'http' | 'socks5', latencyMs: r.latencyMs || 0, qualityGrade: 'C' });
    console.log(`[Fallback+] ${r.item.address} (${r.latencyMs}ms)`);
  }
  console.log(`[Fallback] ${customSlots.length}/${items.length} custom proxies ready`);
}

// ═══════════════════════════════════════════════════════════
//  Candidate Pool (Proxy List Aggregation)
// ═══════════════════════════════════════════════════════════

async function fetchSource(source: typeof DEFAULT_SOURCES[0]): Promise<ProxyItem[]> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 15000);
  try {
    if (warpModeRuntime === 'on' && warpSlot) {
      const agent = new SocksProxyAgent(warpSlot.url, { timeout: 10000 }) as unknown as https.Agent;
      const body = await new Promise<string>((resolve, reject) => {
        const req = https.request(source.url, {
          method: 'GET',
          headers: { 'user-agent': 'Mozilla/5.0' },
          agent,
          rejectUnauthorized: false,
          timeout: 10000,
        }, (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
          res.on('error', reject);
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.end();
      });
      const raw = source.type === 'json' ? JSON.parse(body) : body;
      const items = source.parser(raw);
      if (items.length === 0) { console.warn(`[Source][${source.name}] Empty list`); return []; }
      console.log(`[Source][${source.name}] ${items.length} proxies`);
      return items;
    } else {
      const res = await fetch(source.url, { signal: ctl.signal });
      if (!res.ok) { console.warn(`[Source][${source.name}] HTTP ${res.status}`); return []; }
      const raw = source.type === 'json' ? await res.json() : await res.text();
      const items = source.parser(raw);
      if (items.length === 0) { console.warn(`[Source][${source.name}] Empty list`); return []; }
      console.log(`[Source][${source.name}] ${items.length} proxies`);
      return items;
    }
  } catch (e: any) {
    console.warn(`[Source][${source.name}] Failed: ${e.message}`);
    return [];
  } finally {
    clearTimeout(timer);
  }
}

async function loadCandidates(): Promise<void> {
  const seen = new Set<string>();
  const all: ProxyItem[] = [];
  const results = await Promise.allSettled(proxySources.map(fetchSource));
  for (const r of results) {
    if (r.status === 'fulfilled') {
      for (const item of r.value) {
        const key = `${item.protocol}://${item.address}`;
        if (!seen.has(key)) { seen.add(key); all.push(item); }
      }
    }
  }
  // Merge custom persisted proxies
  for (const item of customProxyItems) {
    const key = `${item.protocol}://${item.address}`;
    if (!seen.has(key)) { seen.add(key); all.push(item); }
  }
  const gradeOrder: Record<string, number> = { S: 0, A: 1, B: 2, C: 3 };
  all.sort((a, b) => {
    const ga = gradeOrder[a.quality_grade] ?? 99;
    const gb = gradeOrder[b.quality_grade] ?? 99;
    if (ga !== gb) return ga - gb;
    return (a.latency || 999) - (b.latency || 999);
  });
  const oldLocked = new Map<string, string>();
  for (const c of candidates) { if (c.lockedBy) oldLocked.set(c.address, c.lockedBy); }
  candidates = all.map(item => ({
    ...item,
    lockedBy: oldLocked.get(item.address) || null,
  }));
  const srcCount = proxySources.length;
  console.log(`[Pool] Aggregated ${srcCount} sources`, customProxyItems.length > 0 ? `+ ${customProxyItems.length} custom` : '', `total ${candidates.length} candidates`);
}

// ═══════════════════════════════════════════════════════════
//  Health Checking
// ═══════════════════════════════════════════════════════════

function makeAgent(url: string, proto: 'http' | 'socks5'): https.Agent {
  if (proto === 'socks5') {
    return new SocksProxyAgent(url, { timeout: PROXY_PROBE_TIMEOUT }) as unknown as https.Agent;
  }
  return new HttpsProxyAgent({
    proxy: url,
    keepAlive: false,
    timeout: PROXY_PROBE_TIMEOUT,
  }) as unknown as https.Agent;
}

async function probe(item: ProxyItem): Promise<{ ok: boolean; latencyMs: number }> {
  const url = item.protocol === 'socks5' ? `socks5h://${item.address}` : `http://${item.address}`;
  const agent = makeAgent(url, item.protocol as 'http' | 'socks5');
  const start = Date.now();
  try {
    const result = await new Promise<{ ok: boolean }>((resolve) => {
      const req = https.request(`${UPSTREAM}/v1/models`, {
        method: 'GET',
        headers: { accept: 'application/json', authorization: 'Bearer public', 'x-opencode-client': 'desktop' },
        agent,
        rejectUnauthorized: false,
        timeout: PROXY_PROBE_TIMEOUT,
      }, (res) => {
        res.on('data', () => {});
        res.on('end', () => resolve({ ok: res.statusCode! >= 200 && res.statusCode! < 400 }));
      });
      req.on('error', () => resolve({ ok: false }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
      req.end();
    });
    return { ok: result.ok, latencyMs: Date.now() - start };
  } catch {
    return { ok: false, latencyMs: Date.now() - start };
  } finally {
    try { agent.destroy(); } catch {}
  }
}

function getWarpAddr(): string { return `${warpHostRuntime}:${warpPortRuntime}`; }
function getWarpUrl(): string { return `socks5h://${warpHostRuntime}:${warpPortRuntime}`; }

async function probeWarp(): Promise<boolean> {
  if (warpModeRuntime !== 'on') return false;
  if (Date.now() < warpSkipUntil) return false;
  const warpAddr = getWarpAddr();
  const warpUrl = getWarpUrl();
  try {
    const agent = new SocksProxyAgent(warpUrl, { timeout: 5000 }) as unknown as https.Agent;
    const start = Date.now();
    const result = await new Promise<{ ok: boolean }>((resolve) => {
      const req = https.request(`${UPSTREAM}/v1/models`, {
        method: 'GET',
        headers: { accept: 'application/json', authorization: 'Bearer public' },
        agent,
        rejectUnauthorized: false,
        timeout: 5000,
      }, (res) => {
        res.on('data', () => {});
        res.on('end', () => resolve({ ok: res.statusCode! >= 200 && res.statusCode! < 400 }));
      });
      req.on('error', () => resolve({ ok: false }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
      req.end();
    });
    const latency = Date.now() - start;
    if (result.ok) {
      warpStatus = 'running';
      warpSlot = { addr: warpAddr, url: warpUrl, proto: 'socks5', latencyMs: latency, qualityGrade: 'S' };
      warpConsecutiveFails = 0;
      console.log(`[WARP] Probe successful (${latency}ms), global fallback ready`);
      return true;
    }
    warpStatus = 'stopped';
    warpSlot = null;
    // Clean up WARP slots from all pools
    for (const [, pool] of keySlotPools) {
      const removeIdx = pool.slots.findIndex(s => s.addr === getWarpAddr());
      if (removeIdx >= 0) pool.slots.splice(removeIdx, 1);
    }
    warpConsecutiveFails++;
    const backoffMs = Math.min(60000 * warpConsecutiveFails, 3600000);
    warpSkipUntil = Date.now() + backoffMs;
    console.warn(`[WARP] Probe failed, retrying in ${backoffMs/1000}s (consecutive failures: ${warpConsecutiveFails})`);
    return false;
  } catch {
    warpStatus = 'stopped';
    warpSlot = null;
    warpConsecutiveFails++;
    const backoffMs = Math.min(60000 * warpConsecutiveFails, 3600000);
    warpSkipUntil = Date.now() + backoffMs;
    console.warn(`[WARP] Probe exception, retrying in ${backoffMs/1000}s (consecutive failures: ${warpConsecutiveFails})`);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════
//  ZenProxy Relay Fallback Channel
// ═══════════════════════════════════════════════════════════

async function proxyViaRelay(
  path: string, method: string, headers: Record<string, string>, body: string | undefined,
): Promise<{ status: number; body?: string; stream?: ReadableStream<Uint8Array>; streamHeaders?: Record<string, string> }> {
  const relayUrl = ZENPROXY_RELAY + path;
  const relayHeaders: Record<string, string> = { ...headers, 'x-zenproxy-key': ZENPROXY_KEY };
  try {
    const res = await fetch(relayUrl, {
      method,
      headers: relayHeaders,
      body,
      signal: AbortSignal.timeout(60000),
    });
    const bodyText = await res.text();
    return { status: res.status, body: bodyText };
  } catch (e: any) {
    console.error(`[ZenProxy] relay failed: ${e.message}`);
    return { status: 502, body: JSON.stringify({ error: 'relay_failed', message: e.message }) };
  }
}

// ═══════════════════════════════════════════════════════════
//  Per-Key Slot Pool Management
// ═══════════════════════════════════════════════════════════

async function allocateKeySlots(keyId: string): Promise<KeySlotPool | null> {
  if (keySlotPools.size >= MAX_ACTIVE_KEYS && !keySlotPools.has(keyId)) {
    console.log(`[Allocate] Active keys limit reached (${MAX_ACTIVE_KEYS}), rejecting key ${keyId.slice(0, 7)}...`);
    return null;
  }
  if (candidates.filter(c => !c.lockedBy).length < SLOTS_PER_KEY) {
    await loadCandidates();
  }
  const usedAddrs = new Set<string>();
  const existingPool = keySlotPools.get(keyId);
  if (existingPool) { for (const s of existingPool.slots) usedAddrs.add(s.addr); }

  const available = candidates.filter(c => !c.lockedBy && !usedAddrs.has(c.address));
  const gradeOrder: Record<string, number> = { S: 0, A: 1, B: 2, C: 3 };
  available.sort((a, b) => {
    const ga = gradeOrder[a.quality_grade] ?? 99;
    const gb = gradeOrder[b.quality_grade] ?? 99;
    if (ga !== gb) return ga - gb;
    return (a.latency || 999) - (b.latency || 999);
  });

  const pool = available.slice(0, SLOTS_PER_KEY * 3);
  if (pool.length === 0) {
    if (warpSlot) {
      const newPool: KeySlotPool = { keyId, slots: [warpSlot], rrCursor: 0, lastUsedAt: Date.now() };
      console.log(`[Allocate] Key ${keyId.slice(0, 7)}... No available candidates, using only WARP fallback`);
      return newPool;
    }
    console.log(`[Allocate] Key ${keyId.slice(0, 7)}... No available candidates and no WARP, allocation failed`);
    return null;
  }

  const newSlots: Slot[] = [];
  const groupSize = SLOTS_PER_KEY;
  for (let i = 0; i < pool.length && newSlots.length < SLOTS_PER_KEY; i += groupSize) {
    const group = pool.slice(i, i + groupSize);
    const results = await Promise.all(group.map(async (item) => {
      const r = await probe(item);
      return { item, ...r };
    }));
    for (const r of results) {
      if (newSlots.length >= SLOTS_PER_KEY) break;
      if (!r.ok) continue;
      const url = r.item.protocol === 'socks5' ? `socks5h://${r.item.address}` : `http://${r.item.address}`;
      newSlots.push({
        addr: r.item.address, url,
        proto: r.item.protocol as 'http' | 'socks5',
        latencyMs: r.latencyMs || 0,
        qualityGrade: r.item.quality_grade || 'C',
      });
      const cand = candidates.find(c => c.address === r.item.address);
      if (cand) cand.lockedBy = keyId;
      console.log(`[Allocate+] ${r.item.address} (${r.latencyMs}ms) → Key ${keyId.slice(0, 7)}...`);
    }
  }

  if (warpModeRuntime === 'on' && !warpSlot) { await probeWarp(); }

  if (newSlots.length === 0) {
    if (warpSlot) {
      const newPool: KeySlotPool = { keyId, slots: [warpSlot], rrCursor: 0, lastUsedAt: Date.now() };
      console.log(`[Allocate] Key ${keyId.slice(0, 7)}... All candidates failed, using WARP fallback`);
      return newPool;
    }
    console.log(`[Allocate] Key ${keyId.slice(0, 7)}... All candidates failed and no WARP, allocation failed`);
    return null;
  }

  const newPool: KeySlotPool = { keyId, slots: newSlots, rrCursor: 0, lastUsedAt: Date.now() };
  console.log(`[Allocate] Key ${keyId.slice(0, 7)}... Acquired ${newSlots.length} slots`);
  return newPool;
}

function releaseKeySlots(keyId: string): void {
  const pool = keySlotPools.get(keyId);
  if (!pool) return;
  for (const slot of pool.slots) {
    const cand = candidates.find(c => c.address === slot.addr);
    if (cand) cand.lockedBy = null;
  }
  const count = pool.slots.length;
  keySlotPools.delete(keyId);
  console.log(`[Release] Key ${keyId.slice(0,7)}... Released ${count} slots`);
}

function replaceFailedSlot(pool: KeySlotPool, failedAddr: string): void {
  const idx = pool.slots.findIndex(s => s.addr === failedAddr);
  if (idx >= 0) pool.slots.splice(idx, 1);
  const failedCand = candidates.find(c => c.address === failedAddr);
  if (failedCand) {
    failedCand.lockedBy = '__cooldown__';
    setTimeout(() => {
      if (failedCand.lockedBy === '__cooldown__') failedCand.lockedBy = null;
    }, 120000);
  }

  const lockedAddrs = new Set(pool.slots.map(s => s.addr));
  const replacement = candidates.find(c => !c.lockedBy && !lockedAddrs.has(c.address));
  if (!replacement) {
    console.log(`[Replace] ${failedAddr} failed, no available candidate to replace (remaining slots: ${pool.slots.length})`);
    return;
  }

  probe(replacement).then(r => {
    if (r.ok) {
      const url = replacement.protocol === 'socks5' ? `socks5h://${replacement.address}` : `http://${replacement.address}`;
      const newSlot: Slot = {
        addr: replacement.address, url,
        proto: replacement.protocol as 'http' | 'socks5',
        latencyMs: r.latencyMs || 0,
        qualityGrade: replacement.quality_grade || 'C',
      };
      pool.slots.push(newSlot);
      replacement.lockedBy = pool.keyId;
      console.log(`[Replace+] ${replacement.address} (${r.latencyMs}ms) → Key ${pool.keyId.slice(0, 7)}...`);
    } else {
      console.log(`[Replace] ${replacement.address} probe failed, not replaced`);
    }
  }).catch(e => {
    console.error(`[Replace] ${replacement.address} exception: ${e.message}`);
  });
}

async function getKeySlotPool(keyId: string): Promise<KeySlotPool | null> {
  const existing = keySlotPools.get(keyId);
  if (existing) {
    existing.lastUsedAt = Date.now();
    if (existing.slots.length > 0) {
      // If all slots are fallback and candidates available, force re-allocation
      const warpAddr = getWarpAddr();
      const allFallback = existing.slots.every(s => s.addr === warpAddr || customSlots.some(cs => cs.addr === s.addr));
      const hasAvailableCandidates = candidates.some(c => !c.lockedBy);
      if (allFallback && hasAvailableCandidates) {
        console.log(`[Allocate] Key ${keyId.slice(0,7)}... All fallback slots, candidate pool available, re-allocating`);
        keySlotPools.delete(keyId);
      } else {
        return existing;
      }
    }
    console.log(`[Allocate] Key ${keyId.slice(0, 7)}... Slots empty, re-allocating`);
    keySlotPools.delete(keyId);
  }
  const pool = await allocateKeySlots(keyId);
  if (!pool) return null;
  keySlotPools.set(keyId, pool);
  return pool;
}

// ═══════════════════════════════════════════════════════════
//  Periodic Candidate Refresh + WARP Health Check
// ═══════════════════════════════════════════════════════════

async function refreshCandidates(): Promise<void> {
  if (refreshing) return;
  refreshing = true;
  try {
    const oldCandidatesLen = candidates.length;
    await loadCandidates();
    // Candidate pool recovered from empty → clean all pure fallback pools
    if (oldCandidatesLen === 0 && candidates.length > 0) {
      console.log(`[Refresh] Candidate pool recovered (${candidates.length} items), cleaning fallback pools for re-allocation`);
      for (const [keyId, pool] of keySlotPools) {
        const allFallback = pool.slots.every(s => s.addr === getWarpAddr());
        if (allFallback) keySlotPools.delete(keyId);
      }
    }
    if (warpModeRuntime === 'on') {
      const warpOk = await probeWarp();
      if (!warpOk && warpStatus === 'running') {
        warpStatus = 'stopped';
        console.log(`[WARP] Disconnected, global fallback removed`);
      }
    }
  } catch (e: any) {
    console.error('[Refresh] error:', e.message);
  } finally {
    refreshing = false;
  }
}

// ═══════════════════════════════════════════════════════════
//  Request Forwarding (doHttps / doHttpsStream)
// ═══════════════════════════════════════════════════════════

function doHttps(
  path: string, method: string, headers: Record<string, string>,
  body: string | undefined, agent?: https.Agent,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const opts: any = { method, headers, timeout: TIMEOUT, rejectUnauthorized: false };
    if (agent) opts.agent = agent;
    const req = https.request(`${UPSTREAM}${path}`, opts, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode || 200, body: Buffer.concat(chunks).toString('utf-8') }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Timeout')));
    if (body) req.write(body);
    req.end();
  });
}

function doHttpsStream(
  path: string, method: string, headers: Record<string, string>,
  body: string | undefined, agent?: https.Agent,
): Promise<{ status: number; stream: ReadableStream<Uint8Array>; headers: Record<string, string> }> {
  return new Promise((resolve, reject) => {
    const opts: any = { method, headers, timeout: STREAM_TIMEOUT, rejectUnauthorized: false };
    if (agent) opts.agent = agent;
    const req = https.request(`${UPSTREAM}${path}`, opts, (res) => {
      const resHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (v) resHeaders[k] = Array.isArray(v) ? v[0] : v;
      }
      res.on('end', () => { try { if (agent) agent.destroy(); } catch {} });
      res.on('error', () => { try { if (agent) agent.destroy(); } catch {} });
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          res.on('data', (chunk: Buffer) => controller.enqueue(new Uint8Array(chunk)));
          res.on('end', () => { try { controller.close(); } catch {} });
          res.on('error', (e: Error) => { try { controller.error(e); } catch {} });
        },
      });
      resolve({ status: res.statusCode || 200, stream, headers: resHeaders });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Timeout')));
    if (body) req.write(body);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════
//  Audit Records
// ═══════════════════════════════════════════════════════════

function audit(status: number, latencyMs: number, slotAddr: string, path: string, body?: string, keyId?: string) {
  let model = '';
  let promptTokens = 0;
  let completionTokens = 0;
  let totalTokens = 0;
  let cacheCreation = 0;
  let cacheRead = 0;
  try {
    if (body) {
      const parsed = JSON.parse(body);
      model = parsed.model || '';
      if (parsed.usage) {
        promptTokens = parsed.usage.prompt_tokens || 0;
        completionTokens = parsed.usage.completion_tokens || 0;
        totalTokens = parsed.usage.total_tokens || 0;
      }
    }
  } catch {}
  auditLog.push({
    ts: Date.now(), keyId: keyId || 'unknown', model, promptTokens, completionTokens, totalTokens,
    cacheCreation, cacheRead, latencyMs, status, slotAddr,
  });
  if (auditLog.length > MAX_AUDIT) auditLog.shift();
  // Append to persistence file
  try {
    fs.appendFileSync(AUDIT_FILE, JSON.stringify({
      ts: Date.now(), keyId: keyId || 'unknown', model, promptTokens, completionTokens, totalTokens,
      cacheCreation, cacheRead, latencyMs, status, slotAddr,
    }) + '\n', 'utf-8');
  } catch {}
}

function loadAuditLog() {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return;
    const lines = fs.readFileSync(AUDIT_FILE, 'utf-8').split('\n').filter(Boolean);
    const count = Math.min(lines.length, 500);
    for (let i = lines.length - count; i < lines.length; i++) {
      try { auditLog.push(JSON.parse(lines[i])); } catch {}
    }
    if (auditLog.length > MAX_AUDIT) auditLog.splice(0, auditLog.length - MAX_AUDIT);
    console.log(`[Audit] Loaded ${auditLog.length} history records`);
  } catch (e: any) {
    console.error(`[Audit] Load failed: ${e.message}`);
  }
}

function extractUsageFromResponse(respBody: string): { tokens: number; model: string } {
  try {
    const parsed = JSON.parse(respBody);
    const model = parsed.model || '';
    const usage = parsed.usage;
    if (usage) {
      return {
        tokens: usage.total_tokens || (usage.prompt_tokens || 0) + (usage.completion_tokens || 0),
        model,
      };
    }
  } catch {}
  return { tokens: 0, model: '' };
}

// ═══════════════════════════════════════════════════════════
//  Core dispatch — Per-Key Pool Routing
// ═══════════════════════════════════════════════════════════

async function dispatch(
  path: string, method: string, headers: Record<string, string>,
  body: string | undefined, pool: KeySlotPool,
  retry = 0, triedAddrs = new Set<string>(),
): Promise<{ status: number; body?: string; stream?: ReadableStream<Uint8Array>; streamHeaders?: Record<string, string> }> {

  // Select slot: round-robin over pool.slots, skip tried ones
  let selectedSlot: Slot | null = null;
  for (let i = 0; i < pool.slots.length; i++) {
    const idx = (pool.rrCursor + i) % pool.slots.length;
    const s = pool.slots[idx];
    // Skip WARP slot when WARP is disabled
    if (warpModeRuntime !== 'on' && s.addr === getWarpAddr()) continue;
    if (!triedAddrs.has(s.addr)) {
      selectedSlot = s;
      pool.rrCursor = (idx + 1) % pool.slots.length;
      break;
    }
  }

  // No available slot → fallback chain
  if (!selectedSlot) {
    if (warpModeRuntime === 'on' && warpSlot && !triedAddrs.has(warpSlot.addr)) {
      console.log(`[Dispatch] pool slots exhausted, fallback → WARP`);
      selectedSlot = warpSlot;
    } else {
      for (const cs of customSlots) {
        if (!triedAddrs.has(cs.addr)) { selectedSlot = cs; break; }
      }
    }
  }

  if (!selectedSlot) {
    // ZenProxy fallback
    if (ZENPROXY_KEY) {
      console.log(`[Dispatch] all slots failed, fallback → ZenProxy relay`);
      return proxyViaRelay(path, method, headers, body);
    }
    // Direct connection fallback (zero-proxy mode)
    console.log(`[Dispatch] all proxies failed, fallback → Direct connection`);
    const start = Date.now();
    let agent: https.Agent | undefined;
    try {
      const isStream = path.includes('/messages') && (headers['accept'] === 'text/event-stream' || path.includes('stream'));
      if (isStream) {
        const result = await doHttpsStream(path, method, headers, body, undefined);
        const latencyMs = Date.now() - start;
        if (result.status >= 200 && result.status < 400) {
          stats.total++; stats.success++;
          audit(result.status, latencyMs, 'direct', path, body, pool.keyId);
          return { status: result.status, stream: result.stream, streamHeaders: result.headers };
        }
        stats.total++; stats.errors++;
        audit(result.status, latencyMs, 'direct', path, body, pool.keyId);
        return { status: result.status, body: `{"error":"upstream_error"}` };
      }
      const result = await doHttps(path, method, headers, body, undefined);
      const latencyMs = Date.now() - start;
      if (result.status >= 200 && result.status < 400) {
        stats.total++; stats.success++;
        const usage = extractUsageFromResponse(result.body);
        if (usage.tokens > 0) recordKeyUsage(pool.keyId, usage.tokens);
        audit(result.status, latencyMs, 'direct', path, result.body, pool.keyId);
        return { status: result.status, body: result.body };
      }
      stats.total++; stats.errors++;
      audit(result.status, latencyMs, 'direct', path, result.body, pool.keyId);
      return { status: result.status, body: result.body };
    } catch (e: any) {
      stats.total++; stats.errors++;
      audit(502, Date.now() - start, 'direct', path, JSON.stringify({ error: e.message }), pool.keyId);
      return { status: 502, body: JSON.stringify({ error: 'all_proxies_failed', message: 'All proxies and direct connection have failed' }) };
    }
  }

  triedAddrs.add(selectedSlot.addr);
  const agent = makeAgent(selectedSlot.url, selectedSlot.proto);
  const start = Date.now();

  try {
    const isStream = path.includes('/messages') && (headers['accept'] === 'text/event-stream' || path.includes('stream'));
    if (isStream) {
      const result = await doHttpsStream(path, method, headers, body, agent);
      const latencyMs = Date.now() - start;
      if (result.status >= 200 && result.status < 400) {
        stats.total++;
        stats.success++;
        console.log(`[Dispatch] ${selectedSlot.addr} stream OK ${result.status} (${latencyMs}ms) pool=${pool.keyId.slice(0,7)}...`);
        proxyFailCount.delete(selectedSlot.addr);
        return { status: result.status, stream: result.stream, streamHeaders: result.headers };
      }
      // Read error response body
      const reader = result.stream.getReader();
      let errBody = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        errBody += new TextDecoder().decode(value);
      }
      stats.total++;
      if (result.status === 429) stats.rateLimited++;
      else stats.errors++;
      console.error(`[Dispatch] ${selectedSlot.addr} stream ${result.status} (${latencyMs}ms) retry=${retry}`);
      const fails = (proxyFailCount.get(selectedSlot.addr) || 0) + 1;
      proxyFailCount.set(selectedSlot.addr, fails);
      if (fails >= PROXY_MAX_FAILS) {
        console.log(`[Dispatch] ${selectedSlot.addr} failed ${fails} consecutive times, marked unavailable`);
        const bc = candidates.find(c => c.address === selectedSlot.addr);
        if (bc) bc.lockedBy = '__blacklist__';
      }
      if (result.status === 429 || result.status >= 500) {
        replaceFailedSlot(pool, selectedSlot.addr);
      }
      audit(result.status, latencyMs, selectedSlot.addr, path, errBody, pool.keyId);
      if (retry < MAX_RETRIES) {
        return dispatch(path, method, headers, body, pool, retry + 1, triedAddrs);
      }
      return { status: result.status, body: errBody };
    } else {
      const result = await doHttps(path, method, headers, body, agent);
      const latencyMs = Date.now() - start;
      if (result.status >= 200 && result.status < 400) {
        stats.total++;
        stats.success++;
        const usage = extractUsageFromResponse(result.body);
        if (usage.tokens > 0) recordKeyUsage(pool.keyId, usage.tokens);
        console.log(`[Dispatch] ${selectedSlot.addr} OK ${result.status} (${latencyMs}ms) pool=${pool.keyId.slice(0,7)}...`);
        proxyFailCount.delete(selectedSlot.addr);
        audit(result.status, latencyMs, selectedSlot.addr, path, result.body, pool.keyId);
        return { status: result.status, body: result.body };
      }
      stats.total++;
      if (result.status === 429) stats.rateLimited++;
      else stats.errors++;
      console.error(`[Dispatch] ${selectedSlot.addr} ${result.status} (${latencyMs}ms) retry=${retry}`);
      const fails = (proxyFailCount.get(selectedSlot.addr) || 0) + 1;
      proxyFailCount.set(selectedSlot.addr, fails);
      if (fails >= PROXY_MAX_FAILS) {
        console.log(`[Dispatch] ${selectedSlot.addr} failed ${fails} consecutive times, marked unavailable`);
        const bc = candidates.find(c => c.address === selectedSlot.addr);
        if (bc) bc.lockedBy = '__blacklist__';
      }
      if (result.status === 429 || result.status >= 500) {
        replaceFailedSlot(pool, selectedSlot.addr);
      }
      audit(result.status, latencyMs, selectedSlot.addr, path, result.body, pool.keyId);
      if (retry < MAX_RETRIES) {
        return dispatch(path, method, headers, body, pool, retry + 1, triedAddrs);
      }
      return { status: result.status, body: result.body };
    }
  } catch (e: any) {
    stats.total++;
    stats.errors++;
    console.error(`[Dispatch] ${selectedSlot.addr} exception: ${e.message} retry=${retry}`);
    const fails = (proxyFailCount.get(selectedSlot.addr) || 0) + 1;
    proxyFailCount.set(selectedSlot.addr, fails);
    if (fails >= PROXY_MAX_FAILS) {
      console.log(`[Dispatch] ${selectedSlot.addr} failed ${fails} consecutive exceptions, marked unavailable`);
      const bc = candidates.find(c => c.address === selectedSlot.addr);
      if (bc) bc.lockedBy = '__blacklist__';
    }
    replaceFailedSlot(pool, selectedSlot.addr);
    audit(502, Date.now() - start, selectedSlot.addr, path, JSON.stringify({ error: e.message }), pool.keyId);
    if (retry < MAX_RETRIES) {
      return dispatch(path, method, headers, body, pool, retry + 1, triedAddrs);
    }
    return { status: 502, body: JSON.stringify({ error: 'proxy_error', message: e.message }) };
  } finally {
    try { agent.destroy(); } catch {}
  }
}

// ═══════════════════════════════════════════════════════════
//  HTTP Server
// ═══════════════════════════════════════════════════════════

function collectHeadersFromReq(nodeReq: http.IncomingMessage): Record<string, string> {
  const h: Record<string, string> = {};
  for (const k of FORWARD) {
    if (k === 'authorization') continue;
    const v = nodeReq.headers[k];
    if (v) h[k] = Array.isArray(v) ? v[0] : v;
  }
  h['authorization'] = 'Bearer public';
  if (!h['x-opencode-client']) h['x-opencode-client'] = 'desktop';
  if (!h['content-type']) h['content-type'] = 'application/json';
  if (!h['user-agent']) h['user-agent'] = 'OpenCode/1.0.0 (desktop)';
  return h;
}

function readBody(nodeReq: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    nodeReq.on('data', (c: Buffer) => chunks.push(c));
    nodeReq.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    nodeReq.on('error', reject);
  });
}

function sendJson(nodeRes: http.ServerResponse, status: number, data: any) {
  const body = JSON.stringify(data);
  nodeRes.writeHead(status, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
  });
  nodeRes.end(body);
}

function sendCors(nodeRes: http.ServerResponse) {
  nodeRes.writeHead(204, {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'access-control-allow-headers': 'content-type, authorization',
  });
  nodeRes.end();
}

const server = http.createServer(async (nodeReq, nodeRes) => {
  const url = new URL(nodeReq.url || '/', `http://${nodeReq.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  const search = url.search;
  const method = nodeReq.method || 'GET';

  // CORS
  if (method === 'OPTIONS') {
    sendCors(nodeRes);
    return;
  }

  // –– Static files (public/) ––
  // Root path → index.html
  if (pathname === '/' || pathname === '') {
    try {
      const data = fs.readFileSync(path.join(process.cwd(), 'public', 'index.html'));
      nodeRes.writeHead(200, { 'content-type': 'text/html' });
      nodeRes.end(data);
    } catch {
      nodeRes.writeHead(404);
      nodeRes.end('Not Found');
    }
    return;
  }
  if (pathname.startsWith('/public/')) {
    const filePath = path.join(process.cwd(), pathname);
    try {
      const data = fs.readFileSync(filePath);
      const ext = path.extname(filePath);
      const mimeMap: Record<string, string> = {
        '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
        '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml',
      };
      nodeRes.writeHead(200, { 'content-type': mimeMap[ext] || 'application/octet-stream' });
      nodeRes.end(data);
    } catch {
      nodeRes.writeHead(404);
      nodeRes.end('Not Found');
    }
    return;
  }

  // –– API: Status ––
  if (pathname === '/api/status' && method === 'GET') {
    const uptime = Math.floor((Date.now() - START_TIME) / 1000);
    const poolsInfo: any[] = [];
    for (const [keyId, pool] of keySlotPools) {
      poolsInfo.push({
        key: keyId.slice(0, 7) + '...' + keyId.slice(-4),
        name: apiKeys[keyId]?.name || 'unknown',
        enabled: apiKeys[keyId]?.enabled ?? false,
        slots: pool.slots.map(s => ({
          addr: s.addr,
          latencyMs: s.latencyMs,
          grade: s.qualityGrade,
        })),
        lastUsedAt: pool.lastUsedAt,
        requestCount: apiKeys[keyId]?.requestCount || 0,
      });
    }
    const totalSlots = SLOTS_PER_KEY * MAX_ACTIVE_KEYS;
    let slotsReady = 0;
    for (const pool of keySlotPools.values()) slotsReady += pool.slots.length;
    sendJson(nodeRes, 200, {
      ok: true,
      uptime,
      stats,
      activeKeys: keySlotPools.size,
      maxActiveKeys: MAX_ACTIVE_KEYS,
      slotCount: SLOTS_PER_KEY,
      slotsReady,
      pools: poolsInfo,
      warpAvailable: !!warpSlot,
      warpStatus,
      warpMode: warpModeRuntime,
      candidatesCount: candidates.length,
      candidates: candidates.length,
      customSlotsCount: customSlots.length,
      totalApiKeys: Object.keys(apiKeys).length,
    });
    return;
  }

  // –– API: Logs ––
  if (pathname === '/api/logs' && method === 'GET') {
    sendJson(nodeRes, 200, { logs: recentLogs.slice(-200) });
    return;
  }

  // –– API: Usage Audit ––
  if (pathname === '/api/audit' && method === 'GET') {
    const totalRequests = auditLog.length;
    let totalTokens = 0, totalPrompt = 0, totalCompletion = 0, cacheRead = 0;
    const keyMap: Record<string, { name: string; key: string; requests: number; totalTokens: number; lastUsedAt: number | null }> = {};
    const modelMap: Record<string, { model: string; requests: number; promptTokens: number; completionTokens: number; totalTokens: number; cacheRead: number }> = {};
    const dayMap: Record<string, { date: string; requests: number; totalTokens: number; promptTokens: number; completionTokens: number; cacheRead: number }> = {};

    for (const log of auditLog) {
      totalTokens += log.totalTokens || 0;
      totalPrompt += log.promptTokens || 0;
      totalCompletion += log.completionTokens || 0;
      cacheRead += log.cacheRead || 0;

      const keyId = log.keyId || 'unknown';
      if (!keyMap[keyId]) {
        keyMap[keyId] = { name: 'unknown', key: keyId, requests: 0, totalTokens: 0, lastUsedAt: null };
      }
      keyMap[keyId].requests++;
      keyMap[keyId].totalTokens += log.totalTokens || 0;
      if (log.ts && (!keyMap[keyId].lastUsedAt || log.ts > keyMap[keyId].lastUsedAt)) {
        keyMap[keyId].lastUsedAt = log.ts;
      }

      const mdl = log.model || 'unknown';
      if (!modelMap[mdl]) {
        modelMap[mdl] = { model: mdl, requests: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0, cacheRead: 0 };
      }
      modelMap[mdl].requests++;
      modelMap[mdl].promptTokens += log.promptTokens || 0;
      modelMap[mdl].completionTokens += log.completionTokens || 0;
      modelMap[mdl].totalTokens += log.totalTokens || 0;
      modelMap[mdl].cacheRead += log.cacheRead || 0;

      const day = new Date(log.ts || Date.now()).toISOString().split('T')[0];
      if (!dayMap[day]) {
        dayMap[day] = { date: day, requests: 0, totalTokens: 0, promptTokens: 0, completionTokens: 0, cacheRead: 0 };
      }
      dayMap[day].requests++;
      dayMap[day].totalTokens += log.totalTokens || 0;
      dayMap[day].promptTokens += log.promptTokens || 0;
      dayMap[day].completionTokens += log.completionTokens || 0;
      dayMap[day].cacheRead += log.cacheRead || 0;
    }

    const cacheHitRate = totalTokens > 0 ? cacheRead / totalTokens : 0;

    sendJson(nodeRes, 200, {
      summary: {
        totalRequests,
        totalTokens,
        totalPrompt,
        totalCompletion,
        cacheHitRate,
      },
      keys: Object.values(keyMap).sort((a, b) => b.requests - a.requests),
      models: Object.values(modelMap).sort((a, b) => b.requests - a.requests),
      days: Object.values(dayMap).sort((a, b) => b.date.localeCompare(a.date)),
    });
    return;
  }

  // –– Fetch model list from upstream, filter free models, and cache ––
async function fetchModelsFromUpstream(): Promise<any[]> {
  let agent: https.Agent | undefined;
  if (warpSlot) {
    agent = new SocksProxyAgent(warpSlot.url, { timeout: 10000 }) as unknown as https.Agent;
  }
  const result = await new Promise<any>((resolve, reject) => {
    const req = https.request(`${UPSTREAM}/v1/models`, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: 'Bearer public' },
      agent,
      rejectUnauthorized: false,
      timeout: 10000,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8')));
        } catch {
          resolve({ data: [] });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
  const freeModels = (result.data || []).filter((m: any) => m.id && m.id.endsWith('-free')).map((m: any) => ({
    ...m,
    id: m.id.replace(/-free$/, ''),
  }));
  cachedModels = freeModels;
  cachedModelsTime = Date.now();
  return freeModels;
}

// –– API: Models ––
  if (pathname === '/api/models' && method === 'GET') {
    try {
      if (cachedModels.length > 0 && Date.now() - cachedModelsTime < 300000) {
        sendJson(nodeRes, 200, { models: cachedModels });
        return;
      }
      const freeModels = await fetchModelsFromUpstream();
      sendJson(nodeRes, 200, { models: freeModels });
    } catch (e: any) {
      sendJson(nodeRes, 502, { error: e.message });
    }
    return;
  }

  // –– API: Key Management ––
  if (pathname === '/api/keys' && method === 'GET') {
    const keys = Object.values(apiKeys).map(r => ({
      key: r.key.slice(0, 7) + '...' + r.key.slice(-4),
      fullKey: r.key,
      name: r.name,
      enabled: r.enabled,
      createdAt: r.createdAt,
      lastUsedAt: r.lastUsedAt,
      totalRequests: r.totalRequests,
      totalTokens: r.totalTokens,
      maxConcurrency: r.maxConcurrency,
      maxRequests: r.maxRequests,
      requestCount: r.requestCount,
      expiresAt: r.expiresAt,
    }));
    sendJson(nodeRes, 200, { keys });
    return;
  }

  // POST /api/keys — Create new Key
  if (pathname === '/api/keys' && method === 'POST') {
    try {
      const body = JSON.parse(await readBody(nodeReq));
      const newKey = body.key || crypto.randomBytes(24).toString('hex');
      if (apiKeys[newKey]) {
        sendJson(nodeRes, 409, { error: 'Key already exists' });
        return;
      }
      apiKeys[newKey] = {
        key: newKey,
        name: body.name || 'unnamed',
        enabled: body.enabled !== false,
        createdAt: Date.now(),
        lastUsedAt: 0,
        totalRequests: 0,
        totalTokens: 0,
        maxConcurrency: body.maxConcurrency || 0,
        maxRequests: body.maxRequests || 0,
        requestCount: 0,
        expiresAt: body.expiresAt || 0,
      };
      saveKeys();
      sendJson(nodeRes, 201, { key: newKey, message: 'Created successfully' });
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // PUT /api/keys/:key — Update Key
  const putMatch = pathname.match(/^\/api\/keys\/(.+)$/);
  if (putMatch && method === 'PUT') {
    const targetKey = putMatch[1];
    const record = apiKeys[targetKey];
    if (!record) {
      sendJson(nodeRes, 404, { error: 'Key not found' });
      return;
    }
    try {
      const body = JSON.parse(await readBody(nodeReq));
      if (body.name !== undefined) record.name = body.name;
      if (body.enabled !== undefined) record.enabled = body.enabled;
      if (body.maxConcurrency !== undefined) record.maxConcurrency = body.maxConcurrency;
      if (body.maxRequests !== undefined) record.maxRequests = body.maxRequests;
      if (body.expiresAt !== undefined) record.expiresAt = body.expiresAt;
      saveKeys();
      // If disabled or quota exceeded → release slots
      if (!record.enabled) {
        releaseKeySlots(targetKey);
      } else if (record.maxRequests > 0 && record.requestCount >= record.maxRequests) {
        releaseKeySlots(targetKey);
      }
      sendJson(nodeRes, 200, { message: 'Updated successfully' });
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // DELETE /api/keys/:key — Delete Key
  if (putMatch && method === 'DELETE') {
    const targetKey = putMatch[1];
    if (!apiKeys[targetKey]) {
      sendJson(nodeRes, 404, { error: 'Key not found' });
      return;
    }
    releaseKeySlots(targetKey);
    delete apiKeys[targetKey];
    saveKeys();
    sendJson(nodeRes, 200, { message: 'Deleted successfully' });
    return;
  }

  // –– API: WARP Control ––
  if (pathname === '/api/warp' && method === 'POST') {
    try {
      const body = JSON.parse(await readBody(nodeReq));
      if (body.action === 'enable') {
        warpModeRuntime = 'on';
        warpHostRuntime = body.host || WARP_HOST;
        warpPortRuntime = body.port || WARP_SOCKS5_PORT;
        warpConsecutiveFails = 0;
        warpSkipUntil = 0;
        const ok = await probeWarp();
        sendJson(nodeRes, 200, { ok, warpStatus, message: ok ? 'WARP enabled' : 'WARP probe failed' });
      } else if (body.action === 'disable') {
        warpModeRuntime = 'off';
        warpSlot = null;
        warpStatus = 'stopped';
        warpConsecutiveFails = 0;
        warpSkipUntil = 0;
        sendJson(nodeRes, 200, { ok: true, message: 'WARP disabled' });
      } else {
        sendJson(nodeRes, 400, { error: 'Unknown action' });
      }
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // –– API: Refresh Candidates ––
  if (pathname === '/api/refresh' && method === 'POST') {
    refreshCandidates().then(() => {
      sendJson(nodeRes, 200, { ok: true, candidatesCount: candidates.length });
    }).catch(e => {
      sendJson(nodeRes, 500, { error: e.message });
    });
    return;
  }

  // –– API: Manually Allocate Slot ––
  if (pathname === '/api/slots/fill' && method === 'POST') {
    try {
      const body = JSON.parse(await readBody(nodeReq));
      const targetKey = body.key || API_KEY;
      const pool = await getKeySlotPool(targetKey);
      if (!pool) {
        sendJson(nodeRes, 503, { error: 'Unable to allocate slot' });
        return;
      }
      sendJson(nodeRes, 200, {
        ok: true,
        key: targetKey.slice(0, 7) + '...',
        slots: pool.slots.map(s => ({ addr: s.addr, latencyMs: s.latencyMs, grade: s.qualityGrade })),
      });
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // –– API: Proxy List ––
  if (pathname === '/api/proxies' && method === 'GET') {
    const list = candidates.map(c => ({
      address: c.address,
      protocol: c.protocol,
      quality_grade: c.quality_grade,
      latency: c.latency,
      lockedBy: c.lockedBy,
      active: !!c.lockedBy,
    }));
    sendJson(nodeRes, 200, { proxies: list, count: list.length });
    return;
  }

  // –– API: Batch Add Proxies ––
  if (pathname === '/api/proxies' && method === 'POST') {
    try {
      const body = JSON.parse(await readBody(nodeReq));
      const addrs: string[] = body.proxies || [];
      let added = 0;
      for (const addr of addrs) {
        const trimmed = addr.trim();
        if (!trimmed) continue;
        const isSocks = trimmed.startsWith('socks5://') || trimmed.startsWith('socks5h://');
        const cleanAddr = trimmed.replace(/^https?:\/\//, '').replace(/^socks5h?:\/\//, '');
        if (!candidates.find(c => c.address === cleanAddr) && !customProxyItems.find(c => c.address === cleanAddr)) {
          const item: ProxyItem = { address: cleanAddr, protocol: isSocks ? 'socks5' : 'http', latency: 0, quality_grade: 'C' };
          candidates.push({ ...item, lockedBy: null });
          customProxyItems.push(item);
          added++;
        }
      }
      if (added > 0) saveCustomProxies();
      sendJson(nodeRes, 200, { message: 'Added', count: added });
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // –– API: Delete Proxy ––
  const proxyDelMatch = pathname.match(/^\/api\/proxies\/(.+)$/);
  if (proxyDelMatch && method === 'DELETE') {
    const addr = decodeURIComponent(proxyDelMatch[1]);
    const idx = candidates.findIndex(c => c.address === addr);
    if (idx >= 0) {
      const locked = candidates[idx].lockedBy;
      if (locked) releaseKeySlots(locked);
      candidates.splice(idx, 1);
      // Remove from custom persistence
      const custIdx = customProxyItems.findIndex(c => c.address === addr);
      if (custIdx >= 0) {
        customProxyItems.splice(custIdx, 1);
        saveCustomProxies();
      }
      sendJson(nodeRes, 200, { message: 'Deleted' });
    } else {
      sendJson(nodeRes, 404, { error: 'not_found' });
    }
    return;
  }

  // –– API: Promote (move to head of queue) ––
  if (pathname === '/api/promote' && method === 'POST') {
    try {
      const body = JSON.parse(await readBody(nodeReq));
      const addr = body.addr;
      const idx = candidates.findIndex(c => c.address === addr);
      if (idx >= 0) {
        const [item] = candidates.splice(idx, 1);
        candidates.unshift(item);
        sendJson(nodeRes, 200, { message: 'Promoted', position: 0 });
      } else {
        sendJson(nodeRes, 200, { message: 'not_in_pool' });
      }
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // –– API: Proxy Source List ––
  if (pathname === '/api/sources' && method === 'GET') {
    const list = proxySources.map(s => ({
      name: s.name,
      type: s.type,
      count: candidates.filter(c => !c.lockedBy).length,
      error: null,
    }));
    sendJson(nodeRes, 200, { sources: list });
    return;
  }

  // –– API: Add Proxy Source ––
  if (pathname === '/api/sources' && method === 'POST') {
    try {
      const body = JSON.parse(await readBody(nodeReq));
      const name = body.name;
      if (!name || !body.url) {
        sendJson(nodeRes, 400, { error: 'name and url are required' });
        return;
      }
      if (proxySources.find(s => s.name === name)) {
        sendJson(nodeRes, 409, { error: 'Proxy source with this name already exists' });
        return;
      }
      const def = DEFAULT_SOURCES.find(d => d.name === name);
      proxySources.push({
        name, url: body.url,
        type: body.type || 'json',
        parser: def ? def.parser : DEFAULT_SOURCES[0].parser,
      });
      saveSources();
      sendJson(nodeRes, 200, { message: 'Added', name, url: body.url });
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // –– API: Delete Proxy Source ––
  const sourceDelMatch = pathname.match(/^\/api\/sources\/(.+)$/);
  if (sourceDelMatch && method === 'DELETE') {
    const name = decodeURIComponent(sourceDelMatch[1]);
    const idx = proxySources.findIndex(s => s.name === name);
    if (idx >= 0) {
      proxySources.splice(idx, 1);
      saveSources();
      sendJson(nodeRes, 200, { message: 'Deleted', name });
    } else {
      sendJson(nodeRes, 404, { error: 'not_found' });
    }
    return;
  }

  // –– API: Config (status/config) ––
  if (pathname === '/api/config' && method === 'GET') {
    sendJson(nodeRes, 200, {
      port: PORT,
      slotCount: SLOTS_PER_KEY,
      maxActiveKeys: MAX_ACTIVE_KEYS,
      warpMode: warpModeRuntime,
      warpHost: warpHostRuntime,
      warpPort: warpPortRuntime,
      warpStatus,
      proxyRefreshMs: PROXY_REFRESH_MS,
      proxyProbeTimeout: PROXY_PROBE_TIMEOUT,
    });
    return;
  }

  // –– API: Update Config ––
  if (pathname === '/api/config' && method === 'POST') {
    try {
      const body = JSON.parse(await readBody(nodeReq));
      if (body.warpMode !== undefined) {
        const oldMode = warpModeRuntime;
        warpModeRuntime = body.warpMode;
        warpConsecutiveFails = 0;
        warpSkipUntil = 0;
        if (body.warpMode === 'on') {
          probeWarp();
        } else {
          warpStatus = 'stopped';
          warpSlot = null;
          // Clean up WARP slots from all pools
          for (const [, pool] of keySlotPools) {
            const removeIdx = pool.slots.findIndex(s => s.addr === getWarpAddr());
            if (removeIdx >= 0) pool.slots.splice(removeIdx, 1);
          }
        }
        console.log(`[Config] WARP mode: ${oldMode} → ${body.warpMode}`);
      }
      sendJson(nodeRes, 200, { message: 'Configuration updated', warpMode: warpModeRuntime });
    } catch (e: any) {
      sendJson(nodeRes, 400, { error: e.message });
    }
    return;
  }

  // –– API: Load Candidate Pool ––
  if (pathname === '/api/candidates/load' && method === 'POST') {
    refreshCandidates().then(() => {
      sendJson(nodeRes, 200, { message: 'Refreshed', count: candidates.length });
    }).catch(e => {
      sendJson(nodeRes, 500, { error: e.message });
    });
    return;
  }

  // –– API: Refresh Proxy Sources (same as loading candidate pool) ––
  if (pathname === '/api/sources/refresh' && method === 'POST') {
    refreshCandidates().then(() => {
      sendJson(nodeRes, 200, { message: 'Refreshed', count: candidates.length });
    }).catch(e => {
      sendJson(nodeRes, 500, { error: e.message });
    });
    return;
  }

  // –– API: Daily Audit Details ––
  if (pathname === '/api/audit/daily' && method === 'GET') {
    const url = new URL(nodeReq.url || '', 'http://localhost');
    const date = url.searchParams.get('date') || new Date().toISOString().split('T')[0];
    const entries = auditLog
      .filter(log => {
        const logDate = new Date(log.ts || 0).toISOString().split('T')[0];
        return logDate === date;
      })
      .map(log => ({
        time: new Date(log.ts || 0).toLocaleTimeString(),
        model: log.model || 'unknown',
        promptTokens: log.promptTokens || 0,
        completionTokens: log.completionTokens || 0,
        totalTokens: log.totalTokens || 0,
        cacheRead: log.cacheRead || 0,
        latencyMs: log.latencyMs || 0,
        status: log.status || 0,
      }))
      .sort((a, b) => a.time.localeCompare(b.time));
    sendJson(nodeRes, 200, { entries });
    return;
  }

  // –– Proxy Forwarding (/v1/* | /openai/v1/*) ––
  if (pathname.startsWith('/v1/') || pathname.startsWith('/openai/v1/')) {
    // OpenAI compatible path → normalize to /v1/
    const upstreamPath = pathname.replace(/^\/openai/, '');
    // Extract authorization Key
    const authHeader = nodeReq.headers['authorization'] || '';
    const authKey = authHeader.replace(/^Bearer\s+/i, '');
    if (!authKey) {
      sendJson(nodeRes, 401, { error: 'unauthorized', message: 'Missing Authorization header' });
      return;
    }
    const kv = validateKey(authKey);
    if (!kv.ok) {
      sendJson(nodeRes, 403, { error: 'forbidden', message: kv.reason });
      return;
    }

    acquireKey(authKey);
    const startTime = Date.now();

    const reqHeaders = collectHeadersFromReq(nodeReq);
    const bodyStr = method !== 'GET' && method !== 'HEAD' ? await readBody(nodeReq) : undefined;

    // Intercept /v1/models → return cached free models (no slot allocation needed)
    if (upstreamPath === '/v1/models' && method === 'GET') {
      try {
        if (cachedModels.length > 0 && Date.now() - cachedModelsTime < 300000) {
          sendJson(nodeRes, 200, { object: 'list', data: cachedModels });
          releaseKey(authKey);
          return;
        }
        const result = await fetchModelsFromUpstream();
        sendJson(nodeRes, 200, { object: 'list', data: result });
        releaseKey(authKey);
        return;
      } catch (e: any) {
        sendJson(nodeRes, 502, { error: e.message });
        releaseKey(authKey);
        return;
      }
    }

    try {
      // Get or create Key slot pool
      const pool = await getKeySlotPool(authKey);
      if (!pool) {
        sendJson(nodeRes, 503, { error: 'service_unavailable', message: 'Unable to allocate proxy slot, please try again later' });
        return;
      }

      const result = await dispatch(upstreamPath + search, method, reqHeaders, bodyStr, pool);

      if (result.stream) {
        // Streaming response
        nodeRes.writeHead(result.status, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          'connection': 'keep-alive',
          'access-control-allow-origin': '*',
          ...result.streamHeaders,
        });
        const reader = result.stream.getReader();
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            nodeRes.write(value);
          }
        } catch {}
        nodeRes.end();
      } else {
        // Standard response
        const respBody = result.body || '{}';
        const usage = extractUsageFromResponse(respBody);
        if (usage.tokens > 0) recordKeyUsage(authKey, usage.tokens);
        nodeRes.writeHead(result.status, {
          'content-type': 'application/json',
          'access-control-allow-origin': '*',
        });
        nodeRes.end(respBody);
      }
    } catch (e: any) {
      console.error(`[Request] Exception: ${e.message}`);
      sendJson(nodeRes, 502, { error: 'gateway_error', message: e.message });
    } finally {
      releaseKey(authKey);
    }
    return;
  }

  // –– 404 ––
  sendJson(nodeRes, 404, { error: 'not_found' });
});

// ═══════════════════════════════════════════════════════════
//  Scheduled Tasks
// ═══════════════════════════════════════════════════════════

// Periodically refresh candidate pool
setInterval(() => {
  refreshCandidates();
}, PROXY_REFRESH_MS);

// Periodically clean up expired/idle Key Slot Pools
setInterval(() => {
  const now = Date.now();
  for (const [keyId, pool] of keySlotPools) {
    const record = apiKeys[keyId];
    if (!record || !record.enabled ||
        (record.expiresAt > 0 && now > record.expiresAt) ||
        (record.maxRequests > 0 && record.requestCount >= record.maxRequests)) {
      releaseKeySlots(keyId);
      continue;
    }
    if (now - pool.lastUsedAt > KEY_IDLE_RELEASE_MS) {
      releaseKeySlots(keyId);
      console.log(`[Release] Key ${keyId.slice(0,7)}... Idle timeout released`);
    }
  }
}, POOL_CLEANUP_MS);

// Automatic Background Scraper (ProxyHub / public feeds)
const AUTO_SCRAPE_HOURS = parseFloat(process.env.AUTO_SCRAPE_HOURS || '4');
const SCRAPER_SCRIPT = path.join(process.cwd(), 'scripts', 'push_proxyhub.py');

function runBackgroundScraper() {
  if (!fs.existsSync(SCRAPER_SCRIPT)) return;
  console.log('[AutoScraper] Starting scheduled ProxyHub scraping in background...');
  try {
    const proc = spawn('python3', [SCRAPER_SCRIPT, '5'], {
      env: { ...process.env, GATE_URL: `http://127.0.0.1:${PORT}/api/proxies` },
      stdio: 'ignore'
    });
    proc.on('close', (code) => {
      console.log(`[AutoScraper] Background ProxyHub crawler finished (exit code ${code})`);
    });
  } catch (e: any) {
    console.error(`[AutoScraper] Failed to spawn scraper: ${e.message}`);
  }
}

if (AUTO_SCRAPE_HOURS > 0) {
  const scrapeMs = Math.round(AUTO_SCRAPE_HOURS * 3600 * 1000);
  // Initial run after 20 seconds
  setTimeout(runBackgroundScraper, 20000);
  // Recurring interval
  setInterval(runBackgroundScraper, scrapeMs);
}

// ═══════════════════════════════════════════════════════════
//  Startup
// ═══════════════════════════════════════════════════════════

async function main() {
  console.log('═══════════════════════════════════════════════════');
  console.log('  ZenGate — Per-Key IP Pool Reverse Proxy Gateway');
  console.log('═══════════════════════════════════════════════════');

  // Load keys
  loadKeys();

  // Load proxy source config
  loadSources();

  // Load custom persisted proxies
  loadCustomProxies();

  // Load historical audit logs (last 500 records)
  loadAuditLog();

  // Load candidate proxies
  console.log('[Startup] Loading candidate proxies...');
  await loadCandidates();

  // Probe WARP
  if (warpModeRuntime === 'on') {
    console.log('[Startup] Probing WARP...');
    await probeWarp();
  }

  // Initialize custom proxies
  await initCustomSlots();

  // Start HTTP server
  server.listen(PORT, () => {
    console.log(`[Startup] Listening on port ${PORT}`);
    console.log(`[Startup] Candidate proxies: ${candidates.length} items`);
    console.log(`[Startup] Fallback proxies: ${customSlots.length} items`);
    console.log(`[Startup] WARP: ${warpStatus}`);
    console.log(`[Startup] Max active keys: ${MAX_ACTIVE_KEYS}`);
    console.log(`[Startup] Slots per key: ${SLOTS_PER_KEY}`);
    console.log('═══════════════════════════════════════════════════');
  });
}

main().catch(e => {
  console.error('[Startup] Fatal error:', e);
  process.exit(1);
});