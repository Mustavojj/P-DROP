const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();
const app = express();
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('Content-Security-Policy', "default-src 'self'"); next(); });
app.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }));
app.use(express.json({ limit: '20kb' }));
app.use(cookieParser());
app.set('trust proxy', 1);
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const JWT_SECRET = process.env.JWT_SECRET || 'pirates-secret-key-change-in-production';
const BOT_TOKEN = process.env.BOT_TOKEN;
const KOPR_ICON = "https://i.postimg.cc/jSGywN96/In-Collage-20261125-193120332.png";
const APP_CONFIG = {
    BOT_LINK: 'https://t.me/KoprBot?start=',
    TON_WALLET_ADDRESS: 'UQD9Q3Jz2a1b0fI7tHhF3Xz1kT6Qj2vE0dC0f1A2B3C4D5E6F7G8H9I',
    PAYMENT_WALLET: 'UQD9Q3Jz2a1b0fI7tHhF3Xz1kT6Qj2vE0dC0f1A2B3C4D5E6F7G8H9I',
    OFFICIAL_CHANNEL_URL: 'https://t.me/Kopr',
    PAYOUTS_CHANNEL_URL: 'https://t.me/KoprPayouts',
    GRAM_ICON: 'https://i.postimg.cc/gktVp1HT/Glossy-Blue-Star-Gem-Badge-0d9c38f5.webp',
    TASK_IMAGE: 'https://i.postimg.cc/gktVp1HT/Glossy-Blue-Star-Gem-Badge-0d9c38f5.webp',
    KOPR_ICON: KOPR_ICON,
    VERIFY_BONUS: 0,
    REFERRAL_REWARD_GRAM: 0.01,
    REFERRAL_REWARD_KOPR: 500,
    REFERRAL_TASKS_PERCENTAGE: 15,
    MIN_CLAIM_GRAM: 0.001,
    SOCIAL_TASK_REWARD: 0.001,
    TASK_REWARD_KOPR: 100,
    PRICE_PER_100: 0.20,
    VERIFY_TASK_PRICE: 10,
    MINING_DAILY_RATE: 0.05,
    MINING_BASE_DAILY: 24,
    MIN_CLAIM_MINING_KOPR: 1,
    KOPR_USD_PRICE: 0.001,
    GRAM_USD_PRICE: 0.95,
    TASK_VERIFICATION_DELAY: 10,
    MINIMUM_WITHDRAW: 0.10,
    MAXIMUM_WITHDRAW: 100,
    WITHDRAWAL_FEES: 0.01,
    SPECIAL_TASKS: [
        { id: 'task_join_pirates', title: 'Join Kopr Drop', description: '', url: 'https://t.me/Kopr', icon: 'fa-users', reward: 0 },
        { id: 'task_join_payouts', title: 'Join Payouts Channel', description: '', url: 'https://t.me/KoprPayouts', icon: 'fa-money-bill-wave', reward: 0 },
        { id: 'task_join_ultra', title: 'Join Ultra Wallet', description: '', url: 'https://t.me/UltraWallet', icon: 'fa-wallet', reward: 0 },
        { id: 'task_join_moneyhub', title: 'Join Money Hub', description: '', url: 'https://t.me/MoneyHub', icon: 'fa-coins', reward: 0 },
        { id: 'task_join_masterx', title: 'Join Master X', description: '', url: 'https://t.me/MasterX', icon: 'fa-star', reward: 0 }
    ]
};
let gramPriceCache = { price: 0.95, fetchedAt: 0 };
async function getGramUsdPrice() {
    const now = Date.now();
    if (gramPriceCache.price && (now - gramPriceCache.fetchedAt) < 300000) {
        return gramPriceCache.price;
    }
    try {
        const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=gram&vs_currencies=usd');
        const data = await response.json();
        const price = data && data.gram && data.gram.usd;
        if (price && price > 0) {
            gramPriceCache = { price: price, fetchedAt: now };
            return price;
        }
    } catch (e) {}
    return gramPriceCache.price || APP_CONFIG.GRAM_USD_PRICE || 0.95;
}
function getCurrentTime() {
    return Date.now();
}
function getLastClaimTime(user) { return user.last_claim_time || user.mining_last_claim || user.created_at || Date.now(); }
function getKoprBalance(user) { const v = user.kopr_balance; if (typeof v === 'number') return v; return 0; }
function getMiningPending(user, nowMs) {
    if (!user) return 0;
    const now = nowMs || Date.now();
    const balance = getKoprBalance(user);
    const base = APP_CONFIG.MINING_BASE_DAILY || 24;
    const rate = APP_CONFIG.MINING_DAILY_RATE || 0.05;
    const daily = base + balance * rate;
    const last = getLastClaimTime(user);
    if (last > now) return 0;
    const elapsedDays = Math.max(0, Math.min(30, (now - last) / 86400000));
    return daily * elapsedDays;
}
function isValidId(v) { return typeof v === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(v); }
function isValidUrl(v) { try { const u = new URL(v); return u.protocol === 'https:' && v.length <= 500; } catch (e) { return false; } }
const withdrawLocks = new Map();
const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 200,
    message: { error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false
});
const strictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false
});
const veryStrictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Too many requests' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(generalLimiter);
function generateJWT(userId, deviceId) {
    return jwt.sign({ userId, deviceId }, JWT_SECRET, { expiresIn: '7d' });
}
function authenticate(req, res, next) {
    try {
        let token = req.headers.authorization?.replace('Bearer ', '') || req.cookies?.token;
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }
        const decoded = jwt.verify(token, JWT_SECRET);
        req._userId = decoded.userId;
        req._deviceId = decoded.deviceId;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(401).json({ error: 'Invalid token' });
    }
}
const userCooldowns = new Map();
function checkCooldown(userId, path) {
    const now = Date.now();
    const key = `${userId}:${path}`;
    const last = userCooldowns.get(key);
    if (last && (now - last) < 2000) {
        return false;
    }
    userCooldowns.set(key, now);
    return true;
}
const promoCooldowns = new Map();
function checkPromoCooldown(userId) {
    const now = Date.now();
    const last = promoCooldowns.get(userId);
    if (last && (now - last) < 30000) {
        return { allowed: false, remaining: Math.ceil((30000 - (now - last)) / 1000) };
    }
    return { allowed: true };
}
function setPromoCooldown(userId) {
    promoCooldowns.set(userId, Date.now());
}
async function logFailure(endpoint, userId, ip, error, extra = {}) {
    try {
        await supabase.from('failures').insert([{
            endpoint,
            user_id: userId || null,
            ip: ip || null,
            error: error?.message || String(error),
            extra: extra,
            created_at: getCurrentTime()
        }]);
    } catch (e) {}
}
async function getUser(userId) {
    const { data, error } = await supabase.from('users').select('*').eq('id', userId).single();
    if (error) return null;
    return data;
}
async function updateUser(userId, updates) {
    const { data, error } = await supabase.from('users').update(updates).eq('id', userId).select().single();
    if (error) throw error;
    return data;
}
async function incrementGram(userId, amount) {
    try {
        const { data, error } = await supabase.rpc('increment_gram', { user_id: userId, amount: amount });
        if (error) throw error;
        return data;
    } catch (e) {
        const user = await getUser(userId);
        if (!user) return null;
        await updateUser(userId, { gram_balance: (user.gram_balance || 0) + amount });
        return true;
    }
}
async function incrementKopr(userId, amount) {
    try {
        const { data, error } = await supabase.rpc('increment_kopr', { user_id: userId, amount: amount });
        if (error) throw error;
        return data;
    } catch (e) {
        const user = await getUser(userId);
        if (!user) return null;
        await updateUser(userId, { kopr_balance: (user.kopr_balance || 0) + amount });
        return true;
    }
}
async function incrementPromoUses(code) {
    const { data: promo } = await supabase.from('promo_codes').select('*').eq('code', code).single();
    if (promo) {
        await supabase.from('promo_codes').update({ total_uses: (promo.total_uses || 0) + 1 }).eq('code', code);
    }
}
async function getActivePromoCodes(userId) {
    const { data } = await supabase.from('promo_codes').select('*').eq('status', 'active').order('created_at', { ascending: false });
    return data || [];
}
async function getPromoCode(code) {
    const { data } = await supabase.from('promo_codes').select('*').eq('code', code).single();
    return data;
}
async function checkUserInChannel(userId, chatId) {
    try {
        if (!BOT_TOKEN) return false;
        const cleanChatId = chatId.startsWith('@') ? chatId : `@${chatId}`;
        const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(cleanChatId)}&user_id=${userId}`);
        const data = await response.json();
        if (!data.ok) return false;
        const status = data.result?.status;
        return ['creator', 'administrator', 'member', 'restricted'].includes(status);
    } catch (e) {
        return false;
    }
}
async function checkBotIsAdminInChannel(chatId) {
    try {
        if (!BOT_TOKEN) return false;
        const cleanChatId = chatId.startsWith('@') ? chatId : `@${chatId}`;
        const meRes = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getMe`);
        const meData = await meRes.json();
        const botId = meData?.result?.id;
        if (!botId) return false;
        const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(cleanChatId)}&user_id=${botId}`);
        const data = await response.json();
        if (!data.ok) return false;
        const status = data.result?.status;
        return ['creator', 'administrator'].includes(status);
    } catch (e) {
        return false;
    }
}
async function getTasks(category, userId) {
    const { data, error } = await supabase.from('tasks').select('*').eq('category', category).eq('status', 'active').order('created_at', { ascending: true });
    if (error) throw error;
    let tasks = data || [];
    if (category !== 'verify') {
        tasks = tasks.filter(t => (t.total_completed || 0) < (t.total || 0));
    }
    if (userId) {
        const { data: completed } = await supabase.from('user_completed_tasks').select('task_id').eq('user_id', userId);
        const completedIds = new Set((completed || []).map(c => c.task_id));
        tasks = tasks.filter(t => !completedIds.has(t.id));
    }
    return tasks;
}
async function getCompletedTasks(userId) {
    const { data } = await supabase.from('user_completed_tasks').select('task_id').eq('user_id', userId);
    return new Set((data || []).map(c => c.task_id));
}
async function createWithdrawal(data) {
    const { data: result, error } = await supabase.from('withdrawals').insert([data]).select().single();
    if (error) throw error;
    return result;
}
async function isMemoUsed(memo) {
    const { data } = await supabase.from('used_memos').select('memo').eq('memo', memo).maybeSingle();
    return !!data;
}
async function recordMemo(memo, userId) {
    await supabase.from('used_memos').insert([{ memo, user_id: userId, created_at: getCurrentTime() }]);
}
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});
app.get('/api/config', (req, res) => {
    res.json(APP_CONFIG);
});
app.get('/api/prices', async (req, res) => {
    const gramUsd = await getGramUsdPrice();
    res.json({ gramUsd: gramUsd, koprUsd: APP_CONFIG.KOPR_USD_PRICE || 0.001, koprIcon: APP_CONFIG.KOPR_ICON });
});
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});
app.use(express.static(__dirname));
class OxaPay {
    constructor({ apiKey, sandbox }) {
        this.apiKey = apiKey;
        this.baseUrl = sandbox ? 'https://api-sandbox.oxapay.com/merchants' : 'https://api.oxapay.com/merchants';
    }
    async request(endpoint, payload) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'payout_api_key': this.apiKey,
            'Content-Type': 'application/json'
        };
        const response = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(payload)
        });
        const responseText = await response.text();
        let result;
        try {
            result = JSON.parse(responseText);
        } catch (e) {
            throw new Error('Invalid response from OxaPay');
        }
        if (!response.ok || result.status !== 200) {
            throw new Error(result.message || result.error || `HTTP ${response.status}`);
        }
        return result;
    }
    async createPayout(data) {
        try {
            const payload = {
                address: data.toAddress,
                amount: data.amount,
                currency: data.currency || 'GRAM',
                network: data.network || 'TON',
                description: data.description || 'Withdrawal'
            };
            const result = await this.request('/payout', payload);
            const trackId = result?.data?.track_id || result?.track_id;
            const status = result?.data?.status || result?.status || 'processing';
            const txHash = result?.data?.tx_hash || result?.tx_hash || null;
            return {
                ...result,
                trackId: trackId || 'N/A',
                status: status,
                txHash: txHash,
                success: true
            };
        } catch (error) {
            throw error;
        }
    }
    async getPayoutStatus(trackId) {
        const url = `${this.baseUrl}/payout/${trackId}`;
        const headers = {
            'payout_api_key': this.apiKey,
            'Content-Type': 'application/json'
        };
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: headers
            });
            const responseText = await response.text();
            let result;
            try {
                result = JSON.parse(responseText);
            } catch (e) {
                throw new Error('Invalid response from OxaPay');
            }
            if (!response.ok || result.status !== 200) {
                throw new Error(result.message || result.error || `HTTP ${response.status}`);
            }
            return result;
        } catch (error) {
            throw error;
        }
    }
}
async function checkPendingWithdrawals() {
    try {
        const { data: withdrawals, error } = await supabase
            .from('withdrawals')
            .select('*')
            .in('status', ['pending', 'processing'])
            .limit(50);
        if (error) return;
        if (!withdrawals || withdrawals.length === 0) return;
        const oxapay = new OxaPay({
            apiKey: process.env.OXAPAY_API_KEY,
            sandbox: process.env.NODE_ENV !== 'production'
        });
        for (const w of withdrawals) {
            try {
                if (!w.tx_id) continue;
                const result = await oxapay.getPayoutStatus(w.tx_id);
                const status = result?.data?.status || result?.status;
                if (status && status !== w.status) {
                    await supabase.from('withdrawals').update({ status: status }).eq('id', w.id);
                }
            } catch (e) {}
        }
    } catch (e) {}
}
setInterval(checkPendingWithdrawals, 5 * 60 * 1000);
app.post('/api/auth', async (req, res) => {
    try {
        const { user: telegramUser, deviceId, referredBy } = req.body;
        if (!telegramUser || !telegramUser.id) {
            return res.status(400).json({ error: 'Invalid user data' });
        }
        let existingUser = await getUser(telegramUser.id);
        if (!existingUser) {
            const newUser = {
                id: telegramUser.id,
                username: telegramUser.username || null,
                first_name: telegramUser.first_name || null,
                photo_url: telegramUser.photo_url || null,
                device_id: deviceId || null,
                referred_by: referredBy || null,
                gram_balance: 0,
                kopr_balance: 0,
                referral_gram_earnings: 0,
                referral_kopr_earnings: 0,
                last_claim_time: getCurrentTime(), mining_last_claim: getCurrentTime(),
                verified: false,
                verification_completed: false,
                total_referrals: 0,
                verified_referrals: 0,
                total_tasks_completed: 0,
                task_count: 0,
                state: 'active',
                created_at: getCurrentTime()
            };
            const { data, error } = await supabase.from('users').insert([newUser]).select().single();
            if (error) throw error;
            existingUser = data;
            if (referredBy) {
                const referrer = await getUser(referredBy);
                if (referrer) {
                    await updateUser(referredBy, { total_referrals: (referrer.total_referrals || 0) + 1 });
                }
            }
        }
        let user = existingUser;
        const photoUrl = telegramUser.photo_url || null;
        if (photoUrl || deviceId || telegramUser.username || telegramUser.first_name) {
            const updates = {};
            if (telegramUser.username && telegramUser.username !== user.username) {
                updates.username = telegramUser.username;
            }
            if (telegramUser.first_name && telegramUser.first_name !== user.first_name) {
                updates.first_name = telegramUser.first_name;
            }
            if (photoUrl && photoUrl !== user.photo_url) {
                updates.photo_url = photoUrl;
            }
            if (deviceId && deviceId !== user.device_id) {
                updates.device_id = deviceId;
            }
            if (Object.keys(updates).length > 0) {
                user = await updateUser(telegramUser.id, updates);
            }
        }
        if (user.state === 'ban') {
            logFailure('/api/auth', telegramUser.id, req.ip, new Error('Account banned'));
            return res.status(403).json({ error: 'Account banned', banned: true });
        }
        const token = generateJWT(user.id, user.id);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({
            success: true,
            user,
            token,
            authenticated: true
        });
    } catch (error) {
        logFailure('/api/auth', req.body?.userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/refresh', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.state === 'ban') {
            return res.status(403).json({ error: 'Account banned' });
        }
        const token = generateJWT(userId, userId);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({ success: true, user, token, authenticated: true });
    } catch (error) {
        logFailure('/api/refresh', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/get-user', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { data: withdrawals } = await supabase.from('withdrawals').select('*').eq('user_id', userId).order('timestamp', { ascending: false }).limit(10);
        const completedTasks = await getCompletedTasks(userId);
        res.json({
            success: true,
            user,
            withdrawals: withdrawals || [],
            completedTasks: Array.from(completedTasks),
            miningPending: getMiningPending(user)
        });
    } catch (error) {
        logFailure('/api/get-user', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/check-membership', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { channel } = req.body;
        const isMember = await checkUserInChannel(userId, channel);
        res.json({ isMember });
    } catch (error) {
        logFailure('/api/check-membership', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/check-bot-admin', authenticate, async (req, res) => {
    try {
        const { channel } = req.body;
        const isAdmin = await checkBotIsAdminInChannel(channel);
        res.json({ isAdmin });
    } catch (error) {
        logFailure('/api/check-bot-admin', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/mining-info', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const serverNow = Date.now();
        const pending = getMiningPending(user, serverNow);
        const koprBalance = getKoprBalance(user);
        res.json({
            success: true,
            koprBalance: koprBalance,
            pending: pending,
            dailyReward: (APP_CONFIG.MINING_BASE_DAILY || 24) + koprBalance * (APP_CONFIG.MINING_DAILY_RATE || 0.05),
            dailyRate: APP_CONFIG.MINING_DAILY_RATE || 0.05,
            canClaim: pending >= (APP_CONFIG.MIN_CLAIM_MINING_KOPR || 1),
            minClaim: APP_CONFIG.MIN_CLAIM_MINING_KOPR || 1,
            lastClaim: getLastClaimTime(user),
            last_claim_time: getLastClaimTime(user),
            serverNow: serverNow
        });
    } catch (error) {
        logFailure('/api/mining-info', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/claim-mining', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const serverNow = Date.now();
        const lastClaim = getLastClaimTime(user);
        if (lastClaim > serverNow) return res.status(400).json({ error: 'Invalid claim time' });
        const elapsedMs = serverNow - lastClaim;
        if (elapsedMs < 0 || elapsedMs > 30 * 86400000) return res.status(400).json({ error: 'Invalid claim window' });
        const pending = getMiningPending(user, serverNow);
        const minClaim = APP_CONFIG.MIN_CLAIM_MINING_KOPR || 1;
        if (pending < minClaim) {
            return res.status(400).json({ error: `Minimum claim: ${minClaim} KOPR` });
        }
        const expectedDaily = (APP_CONFIG.MINING_BASE_DAILY || 24) + getKoprBalance(user) * (APP_CONFIG.MINING_DAILY_RATE || 0.05);
        const maxAllowed = expectedDaily * Math.min(30, elapsedMs / 86400000) + 0.001;
        if (pending > maxAllowed) return res.status(400).json({ error: 'Invalid claim amount' });
        const { data: locked } = await supabase
            .from('users')
            .update({ last_claim_time: serverNow, mining_last_claim: serverNow })
            .eq('id', userId)
            .eq('last_claim_time', lastClaim)
            .select()
            .single();
        if (!locked) {
            await updateUser(userId, { last_claim_time: serverNow, mining_last_claim: serverNow });
        }
        await incrementKopr(userId, pending);
        const freshUser = await getUser(userId);
        res.json({
            success: true,
            user: freshUser,
            claimed: pending
        });
    } catch (error) {
        logFailure('/api/claim-mining', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/complete-task', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId, taskType, channel } = req.body;
        if (!isValidId(taskId) || !['special', 'community', 'partner', 'verify'].includes(taskType)) return res.status(400).json({ error: 'Invalid task' });
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (taskType === 'special') {
            const task = APP_CONFIG.SPECIAL_TASKS.find(t => t.id === taskId);
            if (!task) return res.status(404).json({ error: 'Task not found' });
            const completed = user.completed_special_tasks || [];
            if (completed.includes(taskId)) {
                return res.status(400).json({ error: 'Task already completed' });
            }
            let isMember = true;
            if (task.url && task.url.includes('t.me/')) {
                const chatId = task.url.split('t.me/')[1].split('/')[0].split('?')[0];
                isMember = await checkUserInChannel(userId, chatId);
                if (!isMember) {
                    return res.status(400).json({ error: 'Not a member of the channel' });
                }
            }
            const updatedCompleted = [...completed, taskId];
            await updateUser(userId, {
                completed_special_tasks: updatedCompleted,
                total_tasks_completed: (user.total_tasks_completed || 0) + 1,
                task_count: (user.task_count || 0) + 1
            });
            const freshUser = await getUser(userId);
            res.json({
                success: true,
                user: freshUser,
                reward: 0,
                koprReward: 0
            });
            return;
        }
        const { data: task } = await supabase.from('tasks').select('*').eq('id', taskId).single();
        if (!task) return res.status(404).json({ error: 'Task not found' });
        const completedTasks = await getCompletedTasks(userId);
        if (completedTasks.has(taskId)) {
            return res.status(400).json({ error: 'Task already completed' });
        }
        if (task.category !== 'verify' && (task.total_completed || 0) >= (task.total || 0)) {
            return res.status(400).json({ error: 'Task is full' });
        }
        if (task.verification && task.url) {
            const match = task.url.match(/t\.me\/([^\/\?]+)/);
            if (match) {
                const isMember = await checkUserInChannel(userId, match[1]);
                if (!isMember) {
                    return res.status(400).json({ error: 'Not a member of the channel' });
                }
            }
        }
        if (channel) {
            const isMember = await checkUserInChannel(userId, channel);
            if (!isMember) {
                return res.status(400).json({ error: 'Not a member of the channel' });
            }
        }
        let rewardGram = 0;
        let rewardKopr = 0;
        if (task.category !== 'verify') {
            rewardGram = task.reward || APP_CONFIG.SOCIAL_TASK_REWARD || 0.001;
            rewardKopr = task.reward_kopr || APP_CONFIG.TASK_REWARD_KOPR || 100;
        }
        await supabase.from('user_completed_tasks').insert([{
            user_id: userId,
            task_id: taskId,
            completed_at: getCurrentTime()
        }]);
        if (task.category !== 'verify') {
            await supabase.from('tasks').update({ total_completed: (task.total_completed || 0) + 1 }).eq('id', taskId);
        }
        if (rewardGram > 0) {
            await incrementGram(userId, rewardGram);
        }
        if (rewardKopr > 0) {
            await incrementKopr(userId, rewardKopr);
        }
        await updateUser(userId, {
            total_tasks_completed: (user.total_tasks_completed || 0) + 1,
            task_count: (user.task_count || 0) + 1
        });
        if (rewardGram > 0 && user.referred_by) {
            const referrer = await getUser(user.referred_by);
            if (referrer) {
                const commission = rewardGram * ((APP_CONFIG.REFERRAL_TASKS_PERCENTAGE || 15) / 100);
                if (commission > 0) {
                    await incrementGram(referrer.id, commission);
                    await updateUser(referrer.id, { referral_gram_earnings: (referrer.referral_gram_earnings || 0) + commission });
                }
            }
        }
        const freshUser = await getUser(userId);
        res.json({
            success: true,
            user: freshUser,
            reward: rewardGram,
            koprReward: rewardKopr
        });
    } catch (error) {
        logFailure('/api/complete-task', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/verify-account', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.verified) {
            return res.status(400).json({ error: 'Account already verified' });
        }
        for (const task of APP_CONFIG.SPECIAL_TASKS) {
            if (task.url && task.url.includes('t.me/')) {
                const chatId = task.url.split('t.me/')[1].split('/')[0].split('?')[0];
                const isMember = await checkUserInChannel(userId, chatId);
                if (!isMember) {
                    return res.status(400).json({ error: 'Please join all required channels first' });
                }
            }
        }
        const verifyTasks = await getTasks('verify', null);
        const completedTasks = await getCompletedTasks(userId);
        for (const task of verifyTasks) {
            if (!completedTasks.has(task.id)) {
                return res.status(400).json({ error: 'Please join all required channels first' });
            }
            if (task.url && task.url.includes('t.me/')) {
                const match = task.url.match(/t\.me\/([^\/\?]+)/);
                if (match) {
                    const isMember = await checkUserInChannel(userId, match[1]);
                    if (!isMember) {
                        return res.status(400).json({ error: 'Please join all required channels first' });
                    }
                }
            }
        }
        await updateUser(userId, {
            verified: true,
            verification_completed: true,
            referral_reward_given: true
        });
        if (user.referred_by && !user.referral_reward_given) {
            const referrer = await getUser(user.referred_by);
            if (referrer) {
                await incrementGram(referrer.id, APP_CONFIG.REFERRAL_REWARD_GRAM || 0.01);
                await incrementKopr(referrer.id, APP_CONFIG.REFERRAL_REWARD_KOPR || 500);
                await updateUser(referrer.id, {
                    verified_referrals: (referrer.verified_referrals || 0) + 1,
                    referral_gram_earnings: (referrer.referral_gram_earnings || 0) + (APP_CONFIG.REFERRAL_REWARD_GRAM || 0.01),
                    referral_kopr_earnings: (referrer.referral_kopr_earnings || 0) + (APP_CONFIG.REFERRAL_REWARD_KOPR || 500)
                });
            }
        }
        const freshUser = await getUser(userId);
        res.json({
            success: true,
            user: freshUser,
            message: 'Account verified'
        });
    } catch (error) {
        logFailure('/api/verify-account', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/claim-referral-earnings', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const gramEarnings = user.referral_gram_earnings || 0;
        const koprEarnings = user.referral_kopr_earnings || 0;
        if (gramEarnings < (APP_CONFIG.MIN_CLAIM_GRAM || 0.001) && koprEarnings < 1) {
            return res.status(400).json({ error: 'Minimum claim not reached' });
        }
        const { data: locked } = await supabase
            .from('users')
            .update({ referral_gram_earnings: 0, referral_kopr_earnings: 0 })
            .eq('id', userId)
            .eq('referral_gram_earnings', gramEarnings)
            .eq('referral_kopr_earnings', koprEarnings)
            .select()
            .single();
        if (!locked) {
            return res.status(429).json({ error: 'Please try again later' });
        }
        if (gramEarnings > 0) {
            await incrementGram(userId, gramEarnings);
        }
        if (koprEarnings > 0) {
            await incrementKopr(userId, koprEarnings);
        }
        const freshUser = await getUser(userId);
        res.json({
            success: true,
            user: freshUser,
            claimed: gramEarnings,
            claimedKopr: koprEarnings
        });
    } catch (error) {
        logFailure('/api/claim-referral-earnings', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/claim-promo-code', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { code } = req.body;
        const promoCheck = checkPromoCooldown(userId);
        if (!promoCheck.allowed) {
            return res.status(429).json({ error: `Please wait ${promoCheck.remaining} seconds before using another promo code` });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const promo = await getPromoCode(code);
        if (!promo || promo.status !== 'active') {
            return res.status(400).json({ error: 'Invalid promo code' });
        }
        if ((promo.total_uses || 0) >= promo.max_uses) {
            return res.status(400).json({ error: 'Promo code expired' });
        }
        if (promo.owner === userId) {
            return res.status(400).json({ error: 'Cannot use your own code' });
        }
        const { data: usedData } = await supabase
            .from('used_promo_codes')
            .select('*')
            .eq('user_id', userId)
            .eq('code', code)
            .maybeSingle();
        if (usedData) {
            return res.status(400).json({ error: 'Promo code already used' });
        }
        setPromoCooldown(userId);
        await supabase.from('used_promo_codes').insert([{
            user_id: userId,
            code: code,
            used_at: getCurrentTime()
        }]);
        await incrementPromoUses(code);
        const rewardText = promo.reward || 'Reward';
        const gramMatch = rewardText.match(/([0-9.]+)\s*GRAM/i);
        if (gramMatch) {
            await incrementGram(userId, parseFloat(gramMatch[1]));
        }
        const koprMatch = rewardText.match(/([0-9.]+)\s*KOPR/i);
        if (koprMatch) {
            await incrementKopr(userId, parseFloat(koprMatch[1]));
        }
        const freshUser = await getUser(userId);
        res.json({
            success: true,
            user: freshUser,
            reward: rewardText
        });
    } catch (error) {
        logFailure('/api/claim-promo-code', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/tasks/:category', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const category = req.params.category;
        const tasks = await getTasks(category, userId);
        res.json({ success: true, tasks });
    } catch (error) {
        logFailure('/api/tasks', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/my-tasks', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { data: tasks } = await supabase
            .from('tasks')
            .select('*')
            .eq('owner', userId)
            .eq('category', 'community')
            .order('created_at', { ascending: false });
        res.json({ success: true, tasks: tasks || [] });
    } catch (error) {
        logFailure('/api/my-tasks', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/delete-task', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId } = req.body;
        const { data: task } = await supabase.from('tasks').select('*').eq('id', taskId).single();
        if (!task) return res.status(404).json({ error: 'Task not found' });
        if (task.owner !== userId) {
            return res.status(403).json({ error: 'Not your task' });
        }
        await supabase.from('tasks').delete().eq('id', taskId);
        res.json({ success: true });
    } catch (error) {
        logFailure('/api/delete-task', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/check-payment', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { memo, amount, taskData } = req.body;
        if (!memo || !amount || !taskData) {
            return res.status(400).json({ error: 'Missing payment data' });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (await isMemoUsed(memo)) {
            return res.status(400).json({ error: 'Memo already used' });
        }
        const isVerify = taskData.category === 'verify' || taskData.type === 'verify' || taskData.verifyTask === true;
        let requiredAmount = 0;
        let total = 0;
        let reward = APP_CONFIG.SOCIAL_TASK_REWARD || 0.001;
        let rewardKopr = APP_CONFIG.TASK_REWARD_KOPR || 100;
        let category = 'community';
        if (isVerify) {
            requiredAmount = APP_CONFIG.VERIFY_TASK_PRICE || 10;
            total = 1000000000;
            reward = 0;
            rewardKopr = 0;
            category = 'verify';
            if (!taskData.name || taskData.name.length < 5 || taskData.name.length > 20) {
                return res.status(400).json({ error: 'Name must be 5-20 characters' });
            }
            if (!taskData.link || !taskData.link.startsWith('https://')) {
                return res.status(400).json({ error: 'Invalid link' });
            }
        } else {
            const parsedTotal = parseInt(taskData.total);
            if (isNaN(parsedTotal) || parsedTotal < 100 || parsedTotal > 5000) {
                return res.status(400).json({ error: 'Total must be between 100 and 5000' });
            }
            total = parsedTotal;
            requiredAmount = (parsedTotal / 100) * (APP_CONFIG.PRICE_PER_100 || 0.20);
            if (!taskData.name || taskData.name.length < 5 || taskData.name.length > 20) {
                return res.status(400).json({ error: 'Name must be 5-20 characters' });
            }
            if (!taskData.link || !taskData.link.startsWith('https://')) {
                return res.status(400).json({ error: 'Invalid link' });
            }
        }
        if (Math.abs(parseFloat(amount) - requiredAmount) > 0.0001) {
            return res.status(400).json({ error: 'Amount mismatch' });
        }
        let isMember = false;
        try {
            if (!BOT_TOKEN) {
                return res.status(500).json({ error: 'Payment verification not configured' });
            }
            const wallet = APP_CONFIG.PAYMENT_WALLET || APP_CONFIG.TON_WALLET_ADDRESS;
            const response = await fetch(`https://api.tonconsole.com/api/transactions?address=${wallet}&limit=50`);
            const data = await response.json();
            const transactions = data?.transactions || data?.data || [];
            for (const tx of transactions) {
                const txMemo = tx.memo || tx.comment || tx.message || '';
                const txAmount = parseFloat(tx.amount || tx.value || 0) / 1e9;
                if (txMemo === memo && Math.abs(txAmount - requiredAmount) < 0.001) {
                    isMember = true;
                    break;
                }
            }
        } catch (e) {
            return res.status(500).json({ error: 'Failed to verify payment' });
        }
        if (!isMember) {
            const testMode = process.env.PAYMENT_TEST_MODE === 'true';
            if (!testMode) {
                return res.status(400).json({ error: 'Payment not found. Please send the payment first.' });
            }
        }
        await recordMemo(memo, userId);
        const { data: newTask, error: taskError } = await supabase.from('tasks').insert([{
            id: memo,
            name: taskData.name,
            url: taskData.link,
            category: category,
            owner: userId,
            total: total,
            total_completed: 0,
            reward: reward,
            reward_kopr: rewardKopr,
            verification: taskData.verification || false,
            status: 'active',
            created_at: getCurrentTime()
        }]).select().single();
        if (taskError) throw taskError;
        res.json({
            success: true,
            task: newTask
        });
    } catch (error) {
        logFailure('/api/check-payment', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/withdraw-gram', authenticate, veryStrictLimiter, async (req, res) => {
    const userId = req._userId;
    if (withdrawLocks.has(userId)) {
        logFailure('/api/withdraw-gram', userId, req.ip, new Error('Withdrawal already in progress'));
        return res.status(429).json({ error: 'Withdrawal already in progress. Please wait.' });
    }
    withdrawLocks.set(userId, Date.now());
    try {
        const { gramAmount, walletAddress } = req.body;
        const user = await getUser(userId);
        if (!user) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('User not found'));
            return res.status(404).json({ error: 'User not found' });
        }
        const now = Date.now();
        const cooldownMs = 6 * 3600000;
        if (user.last_withdraw_time && (now - user.last_withdraw_time) < cooldownMs) {
            const remaining = Math.ceil((cooldownMs - (now - user.last_withdraw_time)) / 3600000);
            logFailure('/api/withdraw-gram', userId, req.ip, new Error(`Cooldown: ${remaining}h`));
            return res.status(400).json({ error: `Wait ${remaining}h before next withdrawal` });
        }
        if (!walletAddress || !walletAddress.startsWith('UQ') || walletAddress.length < 20) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('Invalid wallet address'));
            return res.status(400).json({ error: 'Invalid wallet address. Must start with UQ and be at least 20 characters.' });
        }
        const gram = parseFloat(gramAmount);
        if (isNaN(gram) || gram <= 0) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('Invalid amount'));
            return res.status(400).json({ error: 'Invalid amount' });
        }
        const fees = APP_CONFIG.WITHDRAWAL_FEES;
        const netGram = gram - fees;
        if (netGram <= 0) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('Amount less than fees'));
            return res.status(400).json({ error: `Amount must be greater than fees (${fees} GRAM)` });
        }
        if (gram < APP_CONFIG.MINIMUM_WITHDRAW) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('Below minimum'));
            return res.status(400).json({ error: `Minimum withdrawal: ${APP_CONFIG.MINIMUM_WITHDRAW} GRAM` });
        }
        if (gram > APP_CONFIG.MAXIMUM_WITHDRAW) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('Above maximum'));
            return res.status(400).json({ error: `Maximum withdrawal: ${APP_CONFIG.MAXIMUM_WITHDRAW} GRAM` });
        }
        if ((user.gram_balance || 0) < gram) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('Insufficient balance'));
            return res.status(400).json({ error: 'Insufficient GRAM balance' });
        }
        if (!user.verified) {
            logFailure('/api/withdraw-gram', userId, req.ip, new Error('Account not verified'));
            return res.status(400).json({ error: 'Account not verified' });
        }
        if ((user.verified_referrals || 0) < 3) {
            return res.status(400).json({
                error: `Error, please try again later`
            });
        }
        if ((user.total_referrals || 0) <= (user.verified_referrals || 0)) {
            return res.status(400).json({ error: 'Connot withdraw, fake referrals' });
        }
        const { data: lockResult, error: lockError } = await supabase
            .from('users')
            .update({
                gram_balance: (user.gram_balance || 0) - gram,
                last_withdraw_time: now
            })
            .eq('id', userId)
            .eq('gram_balance', user.gram_balance)
            .select()
            .single();
        if (lockError || !lockResult) {
            logFailure('/api/withdraw-gram', userId, req.ip, lockError || new Error('Lock conflict'));
            return res.status(429).json({ error: 'Please try again later.' });
        }
        const oxapay = new OxaPay({
            apiKey: process.env.OXAPAY_API_KEY,
            sandbox: process.env.NODE_ENV !== 'production'
        });
        try {
            const payout = await oxapay.createPayout({
                toAddress: walletAddress,
                amount: netGram,
                currency: 'GRAM',
                network: 'TON',
                description: `Withdraw ${netGram} GRAM for user ${userId}`
            });
            if (!payout || !payout.success) {
                await supabase
                    .from('users')
                    .update({
                        gram_balance: user.gram_balance,
                        last_withdraw_time: user.last_withdraw_time || 0
                    })
                    .eq('id', userId);
                logFailure('/api/withdraw-gram', userId, req.ip, new Error(payout?.message || 'Payout failed'));
                return res.status(500).json({ error: payout?.message || payout?.error || 'Payout failed' });
            }
            const trackId = payout?.data?.track_id || payout?.trackId || 'N/A';
            const status = 'processing';
            const txHash = payout?.data?.tx_hash || payout?.txHash || null;
            const withdrawal = await createWithdrawal({
                user_id: userId,
                amount: gram,
                fees: fees,
                gram_amount: netGram,
                wallet: walletAddress,
                status: status,
                timestamp: now,
                tx_id: trackId,
                tx_hash: txHash
            });
            res.json({
                success: true,
                user: lockResult,
                withdrawal: withdrawal,
                gramAmount: netGram,
                trackId: trackId,
                status: status,
                txHash: txHash
            });
        } catch (payoutError) {
            await supabase
                .from('users')
                .update({
                    gram_balance: user.gram_balance,
                    last_withdraw_time: user.last_withdraw_time || 0
                })
                .eq('id', userId);
            logFailure('/api/withdraw-gram', userId, req.ip, payoutError, { stage: 'payout' });
            return res.status(500).json({ error: 'Payouts not available now.'});
        }
    } catch (error) {
        logFailure('/api/withdraw-gram', userId, req.ip, error);
        res.status(500).json({ error: 'Payouts not available now.' });
    } finally {
        setTimeout(() => withdrawLocks.delete(userId), 3000);
    }
});
const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`KOPR server running on port ${PORT}`);
});
server.on('error', (error) => {
    console.error('Server error:', error);
});
process.on('SIGTERM', () => {
    server.close(() => {
        process.exit(0);
    });
});
