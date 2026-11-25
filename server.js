
import express from 'express';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';
import { APP_CONFIG } from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const REQUIRED = ['SUPABASE_URL','SUPABASE_KEY','BOT_TOKEN','JWT_SECRET','WEBHOOK_SECRET','OXAPAY_API_KEY'];
for (const k of REQUIRED) if (!process.env[k]) { console.error('Missing env:',k); process.exit(1); }
if (String(process.env.SUPABASE_KEY).length < 40) console.error('SUPABASE_KEY looks invalid');

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({ origin: (origin, cb) => {
  if (!origin) return cb(null, true);
  if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
  return cb(null, false);
}, credentials: true }));

app.post('/webhook', express.raw({ type: 'application/json', limit: '256kb' }), async (req, res) => {
  try {
    const secret = req.headers['x-telegram-bot-api-secret-token'];
    if (!process.env.WEBHOOK_SECRET || !secret || !timingSafeEqualStr(secret, process.env.WEBHOOK_SECRET)) return res.sendStatus(403);
    let update; try { update = JSON.parse(req.body.toString('utf8')); } catch { return res.sendStatus(400); }
    if (update?.message?.chat?.type === 'private') await handlePrivateMessage(update.message);
    return res.sendStatus(200);
  } catch (e) { console.error('[webhook]', e?.message); return res.sendStatus(500); }
});

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', index: false }));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY, { auth: { persistSession: false } });
const BOT_TOKEN = process.env.BOT_TOKEN, JWT_SECRET = process.env.JWT_SECRET;

const PUBLIC_CONFIG = () => ({
  MINIMUM_WITHDRAW: APP_CONFIG.MINIMUM_WITHDRAW, MAXIMUM_WITHDRAW: APP_CONFIG.MAXIMUM_WITHDRAW,
  MIN_CLAIM_GRAM: APP_CONFIG.MIN_CLAIM_GRAM, SOCIAL_TASK_REWARD: APP_CONFIG.SOCIAL_TASK_REWARD,
  PRICE_PER_100: APP_CONFIG.PRICE_PER_100, REFERRAL_REWARD_GRAM: APP_CONFIG.REFERRAL_REWARD_GRAM,
  REFERRAL_TASKS_PERCENTAGE: APP_CONFIG.REFERRAL_TASKS_PERCENTAGE,
  DEFAULT_USER_AVATAR: APP_CONFIG.DEFAULT_USER_AVATAR, SPECIAL_TASKS: APP_CONFIG.SPECIAL_TASKS,
});

const nowMs = () => Date.now();
function timingSafeEqualStr(a, b) { try { const ba = Buffer.from(String(a)), bb = Buffer.from(String(b)); return ba.length === bb.length && crypto.timingSafeEqual(ba, bb); } catch { return false; } }
function safeErr(res, code = 500) { return res.status(code).json({ error: code === 500 ? 'Something went wrong. Please try again.' : 'Request failed.' }); }
function logFail(endpoint, userId, err) { console.error(`[${endpoint}]`, JSON.stringify({ userId: userId || 'unknown', error: err?.message || String(err) })); }
const isInt = v => Number.isInteger(v);
const isFiniteNum = v => typeof v === 'number' && Number.isFinite(v);
function validChannel(c) { return typeof c === 'string' && /^[A-Za-z0-9_]{5,64}$/.test(c); }
function validCode(c) { return typeof c === 'string' && /^[A-Za-z0-9_-]{3,32}$/.test(c); }
function validWallet(w) { return typeof w === 'string' && /^[A-Za-z0-9:_\-]{20,80}$/.test(w); }
function escapeHtml(s) { return String(s ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])); }
async function fetchTimeout(url, opts = {}, ms = 5000) { const c = new AbortController(); const t = setTimeout(() => c.abort(), ms); try { return await fetch(url, { ...opts, signal: c.signal }); } finally { clearTimeout(t); } }

function ttlCache(max = 2000, ttl = 30000) { const m = new Map(); return { get(k) { const v = m.get(k); if (!v) return null; if (Date.now() - v.t > ttl) { m.delete(k); return null; } return v.d; }, set(k, d) { if (m.size >= max) m.delete(m.keys().next().value); m.set(k, { d, t: Date.now() }); }, del(k) { m.delete(k); } }; }
const userCache = ttlCache(2000, 3000);
const botAdminCache = ttlCache(500, 5 * 60 * 1000);
const memberCache = ttlCache(2000, 5 * 60 * 1000);
const cooldowns = ttlCache(5000, 60000);
function checkCooldown(userId, endpoint, ms = 1500) { const k = `${userId}_${endpoint}`; if (cooldowns.get(k)) return false; cooldowns.set(k, true); setTimeout(() => cooldowns.del(k), ms); return true; }
function checkTaskCompletionCooldown(userId) { const k = `task_${userId}`; const last = cooldowns.get(k); if (last) return { allowed: false, remaining: 10 }; return { allowed: true, remaining: 0 }; }
function setTaskCompletionCooldown(userId) { cooldowns.set(`task_${userId}`, true); setTimeout(() => cooldowns.del(`task_${userId}`), 10000); }
function checkPromoCooldown(userId) { const k = `promo_${userId}`; if (cooldowns.get(k)) return { allowed: false, remaining: 5 }; return { allowed: true, remaining: 0 }; }
function setPromoCooldown(userId) { cooldowns.set(`promo_${userId}`, true); setTimeout(() => cooldowns.del(`promo_${userId}`), 5000); }

const mkLimiter = max => rateLimit({ windowMs: 60 * 1000, max, keyGenerator: req => String(req._userId || req.ip), standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Please wait.' } });
const generalLimiter = mkLimiter(120), strictLimiter = mkLimiter(30), veryStrictLimiter = mkLimiter(5);
app.use('/api/', generalLimiter);

let cachedBotId = null;
async function getBotId() { if (cachedBotId) return cachedBotId; const r = await fetchTimeout(`https://api.telegram.org/bot${BOT_TOKEN}/getMe`); const j = await r.json().catch(() => ({})); if (j.ok) cachedBotId = j.result.id; return cachedBotId; }
async function checkBotIsAdminInChannel(channel) { if (!validChannel(channel)) return false; const c = botAdminCache.get(channel); if (c !== null) return c; try { const botId = await getBotId(); if (!botId) return false; const r = await fetchTimeout(`https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channel}&user_id=${botId}`); const j = await r.json().catch(() => ({})); const ok = j.ok && ['administrator', 'creator'].includes(j.result?.status); botAdminCache.set(channel, ok); return ok; } catch { return false; } }
async function checkUserInChannel(userId, channel) { if (!validChannel(channel)) return false; const k = `${userId}_${channel}`; const c = memberCache.get(k); if (c !== null) return c; try { const r = await fetchTimeout(`https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channel}&user_id=${userId}`); const j = await r.json().catch(() => ({})); const ok = j.ok && ['member', 'administrator', 'creator'].includes(j.result?.status); memberCache.set(k, ok); return ok; } catch { return false; } }

const USER_COLS = 'id,username,first_name,photo_url,gram_balance,referral_gram_earnings,level,total_tasks_completed,referral_reward_given,state,verified,verification_completed,total_referrals,verified_referrals,last_withdraw_time,referred_by,referred_by_verified,wallet,task_count,device_id,completed_special_tasks,last_promo_time,created_at';
async function getUser(id) { const c = userCache.get(`u_${id}`); if (c) return c; const { data, error } = await supabase.from('users').select(USER_COLS).eq('id', id).single(); if (error) return null; userCache.set(`u_${id}`, data); return data; }
async function createUser(d) { const { data, error } = await supabase.from('users').insert([d]).select(USER_COLS).single(); if (error) throw error; return data; }
async function updateUser(id, updates) { const { data, error } = await supabase.from('users').update(updates).eq('id', id).select(USER_COLS).single(); if (error) throw error; userCache.del(`u_${id}`); return data; }
async function incrementGram(userId, amount) { const { error } = await supabase.rpc('increment_gram', { uid: userId, amt: amount }); if (!error) userCache.del(`u_${userId}`); return !error; }
async function addReferralCommission(referrerId, amount, type) { if (!referrerId || !(amount > 0)) return; const { error } = await supabase.rpc('add_referral_commission', { uid: referrerId, amt: amount }); if (!error) userCache.del(`u_${referrerId}`); }
async function isMemoUsed(memo) { const { data } = await supabase.from('confirmed_memos').select('memo').eq('memo', memo).maybeSingle(); return !!data; }
async function recordMemo(memo, userId) { const { error } = await supabase.from('confirmed_memos').insert([{ memo, user_id: userId, used_at: nowMs() }]); return !error; }
async function getTasks(category, userId) { let q = supabase.from('tasks').select('id,name,url,category,reward,total,verification,owner,status,total_completed,created_at').order('created_at', { ascending: false }).limit(100); if (category) q = q.eq('category', category); const { data: tasks } = await q; const { data: completed } = await supabase.from('user_completed_tasks').select('task_id').eq('user_id', userId); const done = new Set((completed || []).map(t => t.task_id)); return (tasks || []).filter(t => !done.has(t.id) && (t.total_completed || 0) < t.total); }
async function getCompletedTasks(userId) { const { data } = await supabase.from('user_completed_tasks').select('task_id').eq('user_id', userId); return (data || []).map(t => t.task_id); }
async function getWithdrawals(userId) { const { data } = await supabase.from('withdrawals').select('id,user_id,amount,fees,gram_amount,wallet,status,timestamp,tx_id,tx_hash').eq('user_id', userId).order('timestamp', { ascending: false }).limit(10); return data || []; }
async function getReferrals(userId) { const { data } = await supabase.from('users').select('id,first_name,username,created_at,verified').eq('referred_by', userId).limit(100); return data || []; }
async function getPromoCode(code) { const { data } = await supabase.from('promo_codes').select('code,reward_amount,total_uses,max_uses,status,owner').eq('code', code).single(); return data || null; }
async function getActivePromoCodes(userId) { const { data: codes } = await supabase.from('promo_codes').select('code,reward_amount,total_uses,max_uses,status,owner').eq('status', 'active').gt('max_uses', 0).limit(100); const { data: used } = await supabase.from('used_promo_codes').select('code').eq('user_id', userId); const usedSet = new Set((used || []).map(u => u.code)); return (codes || []).filter(c => !usedSet.has(c.code) && (c.total_uses || 0) < c.max_uses && c.owner !== userId).map(c => ({ ...c, is_used: false })); }
async function incrementPromoUses(code) { const { data, error } = await supabase.rpc('increment_promo_uses', { p_code: code }); if (error) throw error; return data; }
async function usePromoCode(userId, code) { const { data, error } = await supabase.from('used_promo_codes').insert([{ user_id: userId, code, used_at: nowMs() }]).select().single(); if (error) throw error; return data; }
async function createWithdrawal(d) { const { data, error } = await supabase.from('withdrawals').insert([d]).select().single(); if (error) throw error; return data; }
async function sendTelegramNotification(userId, title, message, inlineButton = null) { if (!BOT_TOKEN || !userId) return; try { const payload = { chat_id: userId, text: escapeHtml(message), parse_mode: 'HTML', disable_web_page_preview: true }; if (inlineButton) payload.reply_markup = { inline_keyboard: [[{ text: inlineButton.text, url: inlineButton.url }]] }; await fetchTimeout(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); } catch {} }

class OxaPay {
  constructor(config) { this.apiKey = config.apiKey; this.sandbox = config.sandbox || false; this.baseUrl = this.sandbox ? 'https://sandbox.oxapay.com/v1' : 'https://api.oxapay.com/v1'; }
  async request(endpoint, data) { const url = `${this.baseUrl}${endpoint}`; const headers = { 'Content-Type': 'application/json', 'payout_api_key': this.apiKey }; try { const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(data) }); const responseText = await response.text(); let result; try { result = JSON.parse(responseText); } catch (e) { throw new Error('Invalid response from OxaPay'); } if (!response.ok || result.status !== 200) throw new Error(result.message || result.error || `HTTP ${response.status}`); return result; } catch (error) { throw error; } }
  async createPayout(data) { try { const payload = { address: data.toAddress, amount: data.amount, currency: data.currency || 'GRAM', network: data.network || 'TON', description: data.description || 'Withdrawal' }; const result = await this.request('/payout', payload); const trackId = result?.data?.track_id || result?.track_id; const status = result?.data?.status || result?.status || 'processing'; const txHash = result?.data?.tx_hash || result?.tx_hash || null; return { ...result, trackId: trackId || 'N/A', status, txHash, success: true }; } catch (error) { throw error; } }
  async getPayoutStatus(trackId) { const url = `${this.baseUrl}/payout/${trackId}`; const headers = { 'payout_api_key': this.apiKey, 'Content-Type': 'application/json' }; try { const response = await fetch(url, { method: 'GET', headers }); const responseText = await response.text(); let result; try { result = JSON.parse(responseText); } catch (e) { throw new Error('Invalid response from OxaPay'); } if (!response.ok || result.status !== 200) throw new Error(result.message || result.error || `HTTP ${response.status}`); return result; } catch (error) { throw error; } }
}
const getOxapay = () => new OxaPay({ apiKey: process.env.OXAPAY_API_KEY, sandbox: process.env.NODE_ENV !== 'production' });

function validateTelegramInitData(initData, botToken) {
  if (!initData || !botToken) return { valid: false, error: 'Missing initData or bot token' };
  try {
    const urlParams = new URLSearchParams(initData); const hash = urlParams.get('hash');
    if (!hash) return { valid: false, error: 'Missing hash' };
    urlParams.delete('hash');
    const dataCheckString = Array.from(urlParams.entries()).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    if (!timingSafeEqualStr(calculatedHash, hash)) return { valid: false, error: 'Invalid hash' };
    const authDate = parseInt(urlParams.get('auth_date')); if (Math.floor(Date.now() / 1000) - authDate > 86400) return { valid: false, error: 'initData expired' };
    let user = null; const uj = urlParams.get('user'); if (uj) { try { user = JSON.parse(uj); } catch { return { valid: false, error: 'Invalid user data' }; } }
    return { valid: true, user, authDate, queryId: urlParams.get('query_id') };
  } catch (e) { return { valid: false, error: e.message }; }
}
function generateJWT(userId, telegramId) { return jwt.sign({ userId, telegramId, iat: Math.floor(Date.now() / 1000) }, JWT_SECRET, { expiresIn: '7d' }); }
function verifyJWT(t) { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } }
function authenticate(req, res, next) { let token = req.cookies?.token; if (!token) { const h = req.headers.authorization; if (h?.startsWith('Bearer ')) token = h.split(' ')[1]; } if (!token) return res.status(401).json({ error: 'No token provided' }); const d = verifyJWT(token); if (!d) return res.status(401).json({ error: 'Invalid or expired token' }); req._userId = d.userId; req._telegramId = d.telegramId; next(); }

let pendingRunning = false;
async function checkPendingWithdrawals() {
  if (pendingRunning) return; pendingRunning = true;
  try {
    const { data: withdrawals, error } = await supabase.from('withdrawals').select('id,user_id,gram_amount,wallet,status,tx_id,tx_hash').in('status', ['pending', 'processing']).limit(50);
    if (error || !withdrawals?.length) return;
    const oxapay = getOxapay();
    for (const w of withdrawals) {
      try {
        if (!w.tx_id || w.tx_id === 'N/A') continue;
        const st = await oxapay.getPayoutStatus(w.tx_id);
        const s = st?.data?.status || st?.status; const txHash = st?.data?.tx_hash || st?.txHash || w.tx_hash || null;
        if (s === 'completed' || s === 'paid' || s === 'success') await supabase.from('withdrawals').update({ status: 'completed', tx_hash: txHash }).eq('id', w.id);
        else if (s === 'failed' || s === 'cancelled') await supabase.from('withdrawals').update({ status: 'failed' }).eq('id', w.id);
      } catch {}
    }
  } catch {} finally { pendingRunning = false; }
}
setInterval(checkPendingWithdrawals, 5 * 60 * 1000);
setTimeout(checkPendingWithdrawals, 10000);

async function handlePrivateMessage(msg) {
  const chatId = msg.chat.id, firstName = msg.chat.first_name || 'User', username = msg.chat.username || '';
  const text = msg.text || ''; let referrerId = null;
  if (text.startsWith('/start')) { const parts = text.split(' '); if (parts[1] && !isNaN(parts[1])) referrerId = parseInt(parts[1]); }
  let user = await getUser(chatId);
  if (!user) {
    try {
      user = await createUser({ id: chatId, username, first_name: firstName, photo_url: APP_CONFIG.DEFAULT_USER_AVATAR, created_at: nowMs(), gram_balance: 0, referral_gram_earnings: 0, level: 1, total_tasks_completed: 0, referral_reward_given: false, state: 'active', verified: false, verification_completed: false, total_referrals: 0, verified_referrals: 0, last_withdraw_time: 0, referred_by_verified: false, wallet: null, task_count: 0, device_id: null, ip_address: null, referred_by: referrerId || null });
      if (referrerId && referrerId !== chatId) { const ref = await getUser(referrerId); if (ref) await supabase.rpc('increment_total_referrals', { uid: referrerId }); }
    } catch (e) { logFail('/webhook', chatId, e); }
  }
  const appLink = `https:  await fetchTimeout(`https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: chatId, photo: 'https://slho.shop/i/7940', caption: `<b>🏴‍☠️ Welcome to PIRATES DROP\n\n⚡ INVITE &amp; EARN &amp; GROW\n\n💎 JOIN &amp; EARN FREE GRAM!</b>`, parse_mode: 'HTML', reply_markup: { inline_keyboard: [[{ text: '🏴‍☠️ Start App', url: appLink }]] } }) }).catch(() => {});
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/health', (req, res) => res.status(200).send('OK'));
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: nowMs() }));
app.get('/api/config', (req, res) => res.json(PUBLIC_CONFIG()));

app.post('/api/check-bot-admin', authenticate, async (req, res) => { try { const { channel } = req.body; if (!validChannel(channel)) return res.status(400).json({ error: 'Channel is required' }); res.json({ isAdmin: await checkBotIsAdminInChannel(channel) }); } catch (e) { logFail('/api/check-bot-admin', req._userId, e); safeErr(res); } });
app.post('/api/check-membership', authenticate, async (req, res) => { try { const { channel } = req.body; if (!validChannel(channel)) return res.status(400).json({ error: 'Channel is required' }); if (!BOT_TOKEN) return res.json({ isMember: true, error: 'bot_not_configured' }); if (!(await checkBotIsAdminInChannel(channel))) return res.json({ isMember: true, error: 'bot_not_admin' }); res.json({ isMember: await checkUserInChannel(req._userId, channel) }); } catch (e) { logFail('/api/check-membership', req._userId, e); safeErr(res); } });

app.post('/api/auth', strictLimiter, async (req, res) => {
  try {
    const { initData, userId, photoUrl, deviceId } = req.body;
    if (!initData || typeof initData !== 'string' || initData.length > 8192) return res.status(400).json({ error: 'Missing initData' });
    const v = validateTelegramInitData(initData, BOT_TOKEN); if (!v.valid) return res.status(403).json({ error: 'Invalid Telegram data' });
    const tg = v.user; if (!tg?.id) return res.status(403).json({ error: 'No user data in initData' });
    if (userId && tg.id !== userId) return res.status(403).json({ error: 'User ID mismatch' });
    let user = await getUser(tg.id);
    if (!user) {
      const userData = { id: tg.id, username: tg.username || '', first_name: tg.first_name || 'User', photo_url: photoUrl || tg.photo_url || APP_CONFIG.DEFAULT_USER_AVATAR, created_at: nowMs(), gram_balance: 0, referral_gram_earnings: 0, level: 1, total_tasks_completed: 0, referral_reward_given: false, state: 'active', verified: false, verification_completed: false, total_referrals: 0, verified_referrals: 0, last_withdraw_time: 0, referred_by_verified: false, wallet: null, task_count: 0, device_id: deviceId || null, ip_address: req.ip || null };
      try {
        user = await createUser(userData);
        const sp = new URLSearchParams(initData).get('start_param'); if (sp && !isNaN(sp)) { const rid = parseInt(sp); if (rid !== tg.id) { const ref = await getUser(rid); if (ref) { await updateUser(tg.id, { referred_by: rid }); await supabase.rpc('increment_total_referrals', { uid: rid }); } } }
      } catch (e) { user = await getUser(tg.id); if (!user) return safeErr(res); }
    } else {
      const updates = {}; if (tg.username && tg.username !== user.username) updates.username = tg.username; if (tg.first_name && tg.first_name !== user.first_name) updates.first_name = tg.first_name; if (photoUrl && photoUrl !== user.photo_url) updates.photo_url = photoUrl; if (deviceId && deviceId !== user.device_id) updates.device_id = deviceId; if (Object.keys(updates).length) user = await updateUser(tg.id, updates);
    }
    if (user.state === 'ban') return res.status(403).json({ error: 'Account banned', banned: true });
    const token = generateJWT(user.id, user.id);
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ success: true, user, token, authenticated: true });
  } catch (e) { logFail('/api/auth', req.body?.userId, e); safeErr(res); }
});
app.post('/api/refresh', authenticate, async (req, res) => { try { const user = await getUser(req._userId); if (!user) return res.status(404).json({ error: 'User not found' }); if (user.state === 'ban') return res.status(403).json({ error: 'Account banned' }); const token = generateJWT(req._userId, req._userId); res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 }); res.json({ success: true, token }); } catch (e) { logFail('/api/refresh', req._userId, e); safeErr(res); } });

app.post('/api/get-user', authenticate, async (req, res) => {
  try { const userId = req._userId; const user = await getUser(userId); if (!user) return res.status(404).json({ error: 'User not found' }); if (user.state === 'ban') return res.status(403).json({ error: 'Account banned', banned: true });
    const [completedTasks, withdrawals, referrals] = await Promise.all([getCompletedTasks(userId), getWithdrawals(userId), getReferrals(userId)]);
    res.json({ user, completedTasks, withdrawals, referrals }); } catch (e) { logFail('/api/get-user', req._userId, e); safeErr(res); }
});
app.post('/api/update-user', authenticate, async (req, res) => res.json({ success: true }));

app.post('/api/complete-task', authenticate, strictLimiter, async (req, res) => {
  try {
    const userId = req._userId; const { taskId, taskType } = req.body;
    if (typeof taskId !== 'string' || taskId.length > 128) return res.status(400).json({ error: 'Task not found' });
    const cd = checkTaskCompletionCooldown(userId); if (!cd.allowed) return res.status(429).json({ error: `Please wait ${cd.remaining} seconds before completing another task` });
    const user = await getUser(userId); if (!user) return res.status(404).json({ error: 'User not found' });
    let reward = 0;
    if (taskType === 'special') {
      const task = APP_CONFIG.SPECIAL_TASKS.find(t => t.id === taskId); if (!task) return res.status(404).json({ error: 'Task not found' });
      if ((user.completed_special_tasks || []).includes(taskId)) return res.status(400).json({ error: 'Task already completed!' });
      const ch = task.url.match(/t\.me\/([^\/\?]+)/)?.[1]; if (ch && await checkBotIsAdminInChannel(ch) && !(await checkUserInChannel(userId, ch))) return res.status(400).json({ error: 'Join the channel first' });
      reward = task.reward;
      const { data: upd, error } = await supabase.rpc('complete_special_task', { uid: userId, p_task_id: taskId });
      if (error || !upd) return res.status(400).json({ error: 'Task already completed!' });
    } else {
      const { data: task } = await supabase.from('tasks').select('id,reward,total,total_completed,url,verification').eq('id', taskId).single();
      if (!task) return res.status(404).json({ error: 'Task not found' });
      if ((task.total_completed || 0) >= task.total) return res.status(400).json({ error: 'Task is full!' });
      if (task.verification && task.url) { const ch = task.url.match(/t\.me\/([^\/\?]+)/)?.[1]; if (ch && !(await checkUserInChannel(userId, ch))) return res.status(400).json({ error: 'Join the channel first' }); }
      const { error: insErr } = await supabase.from('user_completed_tasks').insert([{ user_id: userId, task_id: taskId, completed_at: nowMs() }]);
      if (insErr) return res.status(400).json({ error: 'Task already completed!' });
      const { data: updatedTask } = await supabase.rpc('increment_task_completed', { p_task_id: taskId });
      if (!updatedTask) return res.status(400).json({ error: 'Task is full!' });
      reward = task.reward || APP_CONFIG.SOCIAL_TASK_REWARD;
    }
    setTaskCompletionCooldown(userId);
    await incrementGram(userId, reward);
    await supabase.rpc('increment_tasks_completed', { uid: userId });
    const freshUser = await getUser(userId);
    if (user.referred_by && taskType !== 'special') await addReferralCommission(user.referred_by, reward * (APP_CONFIG.REFERRAL_TASKS_PERCENTAGE / 100), 'gram');
    res.json({ success: true, user: freshUser, reward });
  } catch (e) { logFail('/api/complete-task', req._userId, e); safeErr(res); }
});

app.post('/api/verify-account', authenticate, strictLimiter, async (req, res) => {
  try {
    const userId = req._userId; const user = await getUser(userId); if (!user) return res.status(404).json({ error: 'User not found' }); if (user.verified) return res.status(400).json({ error: 'Account already verified' });
    for (const task of APP_CONFIG.SPECIAL_TASKS) { const ch = task.url.match(/t\.me\/([^\/\?]+)/)?.[1]; if (ch && await checkBotIsAdminInChannel(ch) && !(await checkUserInChannel(userId, ch))) return res.status(400).json({ error: 'Please join all required channels first' }); }
    const updatedUser = await updateUser(userId, { verified: true, verification_completed: true });
    if (user.referred_by && !user.referral_reward_given) { const ref = await getUser(user.referred_by); if (ref?.state !== 'ban') { await supabase.rpc('reward_referrer_on_verify', { referrer_id: user.referred_by, reward: APP_CONFIG.REFERRAL_REWARD_GRAM }); await updateUser(userId, { referral_reward_given: true }); } }
    res.json({ success: true, user: updatedUser }); } catch (e) { logFail('/api/verify-account', req._userId, e); safeErr(res); }
});

app.post('/api/claim-referral-earnings', authenticate, strictLimiter, async (req, res) => {
  try { const userId = req._userId; const user = await getUser(userId); if (!user) return res.status(404).json({ error: 'User not found' }); const amount = user.referral_gram_earnings || 0; if (amount < APP_CONFIG.MIN_CLAIM_GRAM) return res.status(400).json({ error: `Minimum claim: ${APP_CONFIG.MIN_CLAIM_GRAM} GRAM` });
    const { data: locked } = await supabase.from('users').update({ referral_gram_earnings: 0 }).eq('id', userId).eq('referral_gram_earnings', user.referral_gram_earnings).select('id').single();
    if (!locked) return res.status(429).json({ error: 'Please try again.' });
    await incrementGram(userId, amount); res.json({ success: true, user: await getUser(userId), claimed: amount }); } catch (e) { logFail('/api/claim-referral-earnings', req._userId, e); safeErr(res); }
});

app.post('/api/tasks/:category', authenticate, async (req, res) => { try { const cat = ['community', 'social', 'daily'].includes(req.params.category) ? req.params.category : null; res.json({ tasks: await getTasks(cat, req._userId) }); } catch (e) { logFail('/api/tasks', req._userId, e); safeErr(res); } });
app.post('/api/my-tasks', authenticate, async (req, res) => { try { const { data: tasks } = await supabase.from('tasks').select('id,name,url,category,reward,total,total_completed,status,created_at').eq('owner', req._userId).eq('category', 'community').order('created_at', { ascending: false }).limit(50); res.json({ tasks: tasks || [] }); } catch (e) { logFail('/api/my-tasks', req._userId, e); safeErr(res); } });
app.post('/api/delete-task', authenticate, async (req, res) => { try { const { taskId } = req.body; if (typeof taskId !== 'string') return res.status(404).json({ error: 'Task not found' }); const { data: task } = await supabase.from('tasks').select('owner').eq('id', taskId).single(); if (!task) return res.status(404).json({ error: 'Task not found' }); if (task.owner !== req._userId) return res.status(403).json({ error: 'Not authorized' }); await supabase.from('tasks').delete().eq('id', taskId); await supabase.from('user_completed_tasks').delete().eq('task_id', taskId); res.json({ success: true }); } catch (e) { logFail('/api/delete-task', req._userId, e); safeErr(res); } });
app.post('/api/promo-codes', authenticate, async (req, res) => { try { res.json({ codes: await getActivePromoCodes(req._userId) }); } catch (e) { logFail('/api/promo-codes', req._userId, e); safeErr(res); } });

app.post('/api/claim-promo-code', authenticate, strictLimiter, async (req, res) => {
  try {
    const userId = req._userId; const { code } = req.body; if (!validCode(code)) return res.status(400).json({ error: 'Invalid promo code' });
    const pc = checkPromoCooldown(userId); if (!pc.allowed) return res.status(429).json({ error: `Please wait ${pc.remaining} seconds before using another promo code` });
    const promo = await getPromoCode(code); if (!promo || promo.status !== 'active') return res.status(404).json({ error: 'Invalid promo code' });
    if (promo.owner === userId) return res.status(400).json({ error: 'You cannot use your own code' });
    if ((promo.total_uses || 0) >= promo.max_uses) return res.status(400).json({ error: 'Promo code expired' });
    try { await usePromoCode(userId, code); } catch { return res.status(400).json({ error: 'Promo code already used' }); }
    await incrementPromoUses(code);
    setPromoCooldown(userId);
    await incrementGram(userId, promo.reward_amount);
    await updateUser(userId, { last_promo_time: nowMs() });
    res.json({ success: true, user: await getUser(userId), reward: `+${promo.reward_amount} GRAM`, rewardAmount: promo.reward_amount });
  } catch (e) { logFail('/api/claim-promo-code', req._userId, e); safeErr(res); }
});

app.post('/api/check-payment', authenticate, async (req, res) => {
  try {
    const userId = req._userId; const { memo, taskData } = req.body;
    if (typeof memo !== 'string' || memo.length < 3 || memo.length > 128) return res.json({ success: false, error: 'Failed to create task.' });
    const user = await getUser(userId); if (!user) return res.status(404).json({ error: 'User not found' });
    const address = APP_CONFIG.PAYMENT_WALLET || APP_CONFIG.TON_WALLET_ADDRESS; if (!address) return res.status(500).json({ error: 'Payment wallet not configured' });
    if (await isMemoUsed(memo)) return res.json({ success: false, error: 'Transaction already used' });
    const response = await fetchTimeout(`https://toncenter.com/api/v2/getTransactions?address=${encodeURIComponent(address)}&limit=3`, {}, 8000);
    const data = await response.json().catch(() => ({})); if (!data.ok) return res.status(500).json({ error: 'Payment API error' });
    const foundTx = (data.result || []).find(tx => tx.in_msg?.message === memo);
    if (!foundTx) return res.json({ success: false, error: 'Payment not found' });
    const txAmount = parseFloat(foundTx.in_msg?.value) / 1e9 || 0;
    const totalNum = parseInt(taskData?.total); if (!(totalNum >= 100 && totalNum <= 5000)) return res.json({ success: false, error: 'Failed to create task.' });
    const requiredAmount = (totalNum / 100) * (APP_CONFIG.PRICE_PER_100 || 0.20);
    if (txAmount < requiredAmount * 0.98) return res.json({ success: false, error: 'Insufficient payment amount' });
    let verification = taskData?.verification || false;
    if (verification && taskData?.link) { const ch = taskData.link.match(/t\.me\/([^\/\?]+)/)?.[1]; if (ch && !(await checkBotIsAdminInChannel(ch))) return res.json({ success: false, error: 'Bot is not admin in the channel. Please add bot as admin.' }); }
    if (!(await recordMemo(memo, userId))) return res.json({ success: false, error: 'Transaction already used' });
    const taskToAdd = { id: memo, name: String(taskData.name || '').slice(0, 100), url: String(taskData.link || '').slice(0, 500), category: 'community', reward: APP_CONFIG.SOCIAL_TASK_REWARD, total: totalNum, verification, owner: userId, status: 'active', created_at: nowMs(), total_completed: 0, notified: false };
    const { data: taskResult, error: taskError } = await supabase.from('tasks').insert([taskToAdd]).select().single();
    if (taskError) return res.status(500).json({ error: 'Failed to add task' });
    await supabase.rpc('increment_task_count', { uid: userId });
    return res.json({ success: true, task: taskResult, message: 'Payment verified and task added' });
  } catch (e) { logFail('/api/check-payment', req._userId, e); safeErr(res); }
});

app.post('/api/withdraw-gram', authenticate, veryStrictLimiter, async (req, res) => {
  const userId = req._userId;
  if (cooldowns.get(`wd_${userId}`)) return res.status(429).json({ error: 'Withdrawal already in progress. Please wait.' });
  cooldowns.set(`wd_${userId}`, true);
  try {
    const { gramAmount, walletAddress } = req.body;
    const gram = Number(gramAmount);
    if (!isFiniteNum(gram) || gram <= 0) return res.status(400).json({ error: 'Invalid amount' });
    if (!validWallet(walletAddress)) return res.status(400).json({ error: 'Invalid wallet address' });
    const user = await getUser(userId); if (!user) return res.status(404).json({ error: 'User not found' });
    const now = nowMs();
    if (now - (user.last_withdraw_time || 0) < 24 * 60 * 60 * 1000) return res.status(400).json({ error: 'You can withdraw once per day' });
    if (gram < APP_CONFIG.MINIMUM_WITHDRAW) return res.status(400).json({ error: `Minimum withdrawal: ${APP_CONFIG.MINIMUM_WITHDRAW} GRAM` });
    if (gram > APP_CONFIG.MAXIMUM_WITHDRAW) return res.status(400).json({ error: `Maximum withdrawal: ${APP_CONFIG.MAXIMUM_WITHDRAW} GRAM` });
    if ((user.gram_balance || 0) < gram) return res.status(400).json({ error: 'Insufficient GRAM balance' });
    if (!user.verified) return res.status(400).json({ error: 'Account not verified' });
    if ((user.verified_referrals || 0) < 3) return res.status(400).json({ error: 'Error, please try again later' });
    if ((user.total_referrals || 0) <= (user.verified_referrals || 0)) return res.status(400).json({ error: 'Connot withdraw, fake referrals' });
    const fees = gram * (APP_CONFIG.WITHDRAW_FEE_PERCENTAGE || 0) / 100; const netGram = gram - fees;
    const { data: lockResult, error: lockError } = await supabase.from('users').update({ gram_balance: (user.gram_balance || 0) - gram, last_withdraw_time: now }).eq('id', userId).eq('gram_balance', user.gram_balance).select().single();
    if (lockError || !lockResult) return res.status(429).json({ error: 'Please try again later.' });
    userCache.del(`u_${userId}`);
    try {
      const payout = await getOxapay().createPayout({ toAddress: walletAddress, amount: netGram, currency: 'GRAM', network: 'TON', description: `Withdraw ${netGram} GRAM for user ${userId}` });
      if (!payout?.success) { await supabase.rpc('refund_withdrawal', { uid: userId, amt: gram, prev_time: user.last_withdraw_time || 0 }); return res.status(500).json({ error: payout?.message || payout?.error || 'Payout failed' }); }
      const withdrawal = await createWithdrawal({ user_id: userId, amount: gram, fees, gram_amount: netGram, wallet: walletAddress, status: 'processing', timestamp: now, tx_id: payout?.data?.track_id || payout?.trackId || 'N/A', tx_hash: payout?.data?.tx_hash || payout?.txHash || null });
      res.json({ success: true, user: lockResult, withdrawal, gramAmount: netGram, trackId: payout?.data?.track_id || payout?.trackId || 'N/A', status: 'processing', txHash: payout?.data?.tx_hash || payout?.txHash || null });
    } catch (payoutError) { await supabase.rpc('refund_withdrawal', { uid: userId, amt: gram, prev_time: user.last_withdraw_time || 0 }); logFail('/api/withdraw-gram', userId, payoutError); return res.status(500).json({ error: 'Payouts not available now.' }); }
  } catch (e) { logFail('/api/withdraw-gram', userId, e); safeErr(res); } finally { setTimeout(() => cooldowns.del(`wd_${userId}`), 3000); }
});

const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, '0.0.0.0', () => console.log(`PIRATES DROP server running on port ${PORT}`));
server.on('error', e => console.error('Server error:', e));
process.on('SIGTERM', () => server.close(() => process.exit(0)));
