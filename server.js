import express from 'express';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(__dirname));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const BOT_TOKEN = process.env.BOT_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const requestCooldown = new Map();
const getUserCache = new Map();
const withdrawLocks = new Map();
const taskCompletionLocks = new Map();
const promoCodeLocks = new Map();
const deviceFingerprints = new Map();
const ipRegistrations = new Map();

function logFailure(endpoint, userId, ip, error, extra = {}) {
    console.error(`[${endpoint}] FAILED`, JSON.stringify({
        userId: userId || 'unknown',
        ip: ip || 'unknown',
        error: error?.message || error,
        ...extra
    }));
}

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    keyGenerator: (req) => req._userId?.toString() || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please slow down.' }
});

const strictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyGenerator: (req) => req._userId?.toString() || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait.' }
});

const veryStrictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    keyGenerator: (req) => req._userId?.toString() || req.ip,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait longer.' }
});

app.use('/api/', generalLimiter);

function checkCooldown(userId, endpoint, cooldownMs = 1500) {
    const now = Date.now();
    const key = `${userId}_${endpoint}`;
    const lastCall = requestCooldown.get(key) || 0;
    if (now - lastCall < cooldownMs) return false;
    requestCooldown.set(key, now);
    return true;
}

function checkTaskCompletionCooldown(userId) {
    const now = Date.now();
    const key = `task_completion_${userId}`;
    const lastCompletion = taskCompletionLocks.get(key) || 0;
    const cooldownMs = 10000;
    if (now - lastCompletion < cooldownMs) {
        const remaining = Math.ceil((cooldownMs - (now - lastCompletion)) / 1000);
        return { allowed: false, remaining };
    }
    return { allowed: true, remaining: 0 };
}

function setTaskCompletionCooldown(userId) {
    const key = `task_completion_${userId}`;
    taskCompletionLocks.set(key, Date.now());
}

function checkPromoCooldown(userId) {
    const now = Date.now();
    const key = `promo_${userId}`;
    const lastPromo = promoCodeLocks.get(key) || 0;
    const cooldownMs = 5000;
    if (now - lastPromo < cooldownMs) {
        const remaining = Math.ceil((cooldownMs - (now - lastPromo)) / 1000);
        return { allowed: false, remaining };
    }
    return { allowed: true, remaining: 0 };
}

function setPromoCooldown(userId) {
    const key = `promo_${userId}`;
    promoCodeLocks.set(key, Date.now());
}

function validateTelegramInitData(initData, botToken) {
    if (!initData || !botToken) {
        return { valid: false, error: 'Missing initData or bot token' };
    }
    try {
        const urlParams = new URLSearchParams(initData);
        const hash = urlParams.get('hash');
        if (!hash) {
            return { valid: false, error: 'Missing hash' };
        }
        urlParams.delete('hash');
        const dataCheckString = Array.from(urlParams.entries())
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([key, value]) => `${key}=${value}`)
            .join('\n');
        const secretKey = crypto
            .createHmac('sha256', 'WebAppData')
            .update(botToken)
            .digest();
        const calculatedHash = crypto
            .createHmac('sha256', secretKey)
            .update(dataCheckString)
            .digest('hex');
        if (calculatedHash !== hash) {
            return { valid: false, error: 'Invalid hash' };
        }
        const authDate = parseInt(urlParams.get('auth_date'));
        const now = Math.floor(Date.now() / 1000);
        const maxAge = 86400;
        if (now - authDate > maxAge) {
            return { valid: false, error: 'initData expired' };
        }
        const userJson = urlParams.get('user');
        let user = null;
        if (userJson) {
            try {
                user = JSON.parse(userJson);
            } catch (e) {
                return { valid: false, error: 'Invalid user data' };
            }
        }
        return {
            valid: true,
            user,
            authDate,
            queryId: urlParams.get('query_id')
        };
    } catch (error) {
        return { valid: false, error: error.message };
    }
}

function generateJWT(userId, telegramId) {
    return jwt.sign(
        {
            userId,
            telegramId,
            iat: Math.floor(Date.now() / 1000)
        },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
}

function verifyJWT(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function authenticate(req, res, next) {
    let token = req.cookies?.token;
    if (!token) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        }
    }
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    const decoded = verifyJWT(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req._userId = decoded.userId;
    req._telegramId = decoded.telegramId;
    next();
}

async function checkBotIsAdminInChannel(channelUsername) {
    if (!BOT_TOKEN) return false;
    try {
        const botInfo = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/getMe`).then(r => r.json());
        if (!botInfo.ok) return false;
        const botId = botInfo.result.id;
        const botMember = await fetch(
            `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channelUsername}&user_id=${botId}`
        ).then(r => r.json());
        if (!botMember.ok) return false;
        return ['administrator', 'creator'].includes(botMember.result?.status);
    } catch (error) {
        return false;
    }
}

async function checkUserInChannel(userId, channelUsername) {
    if (!BOT_TOKEN || !channelUsername) return true;
    try {
        const chatMember = await fetch(
            `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=@${channelUsername}&user_id=${userId}`
        ).then(r => r.json());
        return chatMember.ok && ['member', 'administrator', 'creator'].includes(chatMember.result?.status);
    } catch (error) {
        return false;
    }
}

async function checkDeviceAndIP(userId, deviceId, ip) {
    if (!deviceId) return { allowed: true };
    const deviceKey = `device_${deviceId}`;
    const ipKey = `ip_${ip}`;
    const existingDevice = deviceFingerprints.get(deviceKey);
    if (existingDevice && existingDevice !== userId) {
        return { allowed: false, reason: 'device_already_used', existingUser: existingDevice };
    }
    const existingIP = ipRegistrations.get(ipKey);
    if (existingIP && existingIP !== userId && existingIP !== 'multiple') {
        return { allowed: false, reason: 'ip_already_used', existingUser: existingIP };
    }
    deviceFingerprints.set(deviceKey, userId);
    if (ipRegistrations.has(ipKey) && ipRegistrations.get(ipKey) !== userId) {
        ipRegistrations.set(ipKey, 'multiple');
    } else {
        ipRegistrations.set(ipKey, userId);
    }
    return { allowed: true };
}

const APP_CONFIG = {
    APP_NAME: "PIRATES DROP 🏴‍☠️",
    BOT_USERNAME: "PtsDropBot",
    MINIMUM_WITHDRAW: 0.10,
    MAXIMUM_WITHDRAW: 100,
    WITHDRAWAL_FEES: 0.01,
    REFERRAL_PERCENTAGE: 10,
    REFERRAL_TASKS_PERCENTAGE: 15,
    REFERRAL_REWARD_GRAM: 0.01,
    TASK_VERIFICATION_DELAY: 10,
    DEFAULT_USER_AVATAR: "https://slho.shop/i/7933",
    TON_WALLET_ADDRESS: "UQAJC55HZXzaby1h9VX51Xr8KLHwmZt4AWqzScQ_BnE99KXH",
    PAYMENT_WALLET: "UQAJC55HZXzaby1h9VX51Xr8KLHwmZt4AWqzScQ_BnE99KXH",
    BOT_LINK: "https://t.me/PtsDropBot?start=",
    TASK_IMAGE: "https://slho.shop/i/7933",
    GRAM_ICON: "https://slho.shop/i/7932",
    MIN_CLAIM_GRAM: 0.001,
    PRICE_PER_100: 0.20,
    SOCIAL_TASK_REWARD: 0.001,
    VERIFY_BONUS: 0.03,
    PROMO_CODES_CHANNEL: "https://t.me/PiratesDropCodes",
    PROMO_CODES_CHANNEL_USERNAME: "PiratesDropCodes",
    TASKS_CHANNEL: "@PiratesDropTasks",
    PAYMENTS_CHANNEL: "https://t.me/PiratesDropProof",
    REWARD_AD_BLOCK_ID: "50647",
    INTERSTITIAL_AD_BLOCK_ID: "int-50648",
    OFFICIAL_CHANNEL_URL: "https://t.me/piratesdrop",
    PAYOUTS_CHANNEL_URL: "https://t.me/paymentdroppts",
    SPECIAL_TASKS: [
        {
            id: "ultra_wallet",
            name: "Join Ultra Wallet",
            description: "Join & get special reward",
            url: "https://t.me/UltrawalletTrade_Bot/app?startapp=5455903941",
            reward: 0.01,
            icon: "fa-rocket",
            special: true
        },
        {
            id: "money_hub",
            name: "Money Hub",
            description: "Subscribe & react",
            url: "https://t.me/MONEYHUB9_69",
            reward: 0.01,
            icon: "fa-rocket",
            special: true
        },
        {
            id: "master_x",
            name: "MASTER X",
            description: "Subscribe & react",
            url: "https://t.me/GramTownNews",
            reward: 0.01,
            icon: "fa-rocket",
            special: true
        }
    ]
};

function getCurrentTime() {
    return Date.now();
}

async function addReferralCommission(referrerId, amount, type) {
    if (!referrerId || amount <= 0) return;
    const referrer = await getUser(referrerId);
    if (!referrer || referrer.state === 'ban') return;
    let updates = {};
    if (type === 'gram') {
        updates.referral_gram_earnings = (referrer.referral_gram_earnings || 0) + amount;
    }
    if (Object.keys(updates).length > 0) {
        await updateUser(referrerId, updates);
    }
}

async function getUser(userId) {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();
        if (error && error.code !== 'PGRST116') throw error;
        return data;
    } catch (error) {
        return null;
    }
}

async function createUser(userData) {
    try {
        const { data, error } = await supabase
            .from('users')
            .insert([userData])
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function updateUser(userId, updates) {
    try {
        const { data, error } = await supabase
            .from('users')
            .update(updates)
            .eq('id', userId)
            .select()
            .single();
        if (error) throw error;
        getUserCache.delete(`getUser_${userId}`);
        return data;
    } catch (error) {
        throw error;
    }
}

async function isMemoUsed(memo) {
    try {
        const { data } = await supabase
            .from('confirmed_memos')
            .select('memo')
            .eq('memo', memo)
            .maybeSingle();
        return !!data;
    } catch (error) {
        return false;
    }
}

async function recordMemo(memo, userId) {
    try {
        await supabase
            .from('confirmed_memos')
            .insert([{ memo, user_id: userId, used_at: getCurrentTime() }]);
        return true;
    } catch (error) {
        return false;
    }
}

async function getTasks(category, userId) {
    try {
        let query = supabase.from('tasks').select('*');
        if (category) {
            query = query.eq('category', category);
        }
        const { data: tasks, error } = await query;
        if (error) throw error;
        const { data: completed } = await supabase
            .from('user_completed_tasks')
            .select('task_id')
            .eq('user_id', userId);
        const completedIds = new Set(completed?.map(t => t.task_id) || []);
        const availableTasks = tasks.filter(task =>
            !completedIds.has(task.id) && (task.total_completed || 0) < task.total
        );
        return availableTasks || [];
    } catch (error) {
        return [];
    }
}

async function getCompletedTasks(userId) {
    try {
        const { data, error } = await supabase
            .from('user_completed_tasks')
            .select('task_id')
            .eq('user_id', userId);
        if (error) throw error;
        return data ? data.map(t => t.task_id) : [];
    } catch (error) {
        return [];
    }
}

async function getWithdrawals(userId) {
    try {
        const { data, error } = await supabase
            .from('withdrawals')
            .select('*')
            .eq('user_id', userId)
            .order('timestamp', { ascending: false })
            .limit(10);
        if (error) throw error;
        return data || [];
    } catch (error) {
        return [];
    }
}

async function getReferrals(userId) {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, first_name, username, created_at, verified')
            .eq('referred_by', userId);
        if (error) throw error;
        return data || [];
    } catch (error) {
        return [];
    }
}

async function getPromoCode(code) {
    try {
        const { data, error } = await supabase
            .from('promo_codes')
            .select('*')
            .eq('code', code)
            .single();
        if (error && error.code !== 'PGRST116') throw error;
        return data;
    } catch (error) {
        return null;
    }
}

async function getActivePromoCodes(userId) {
    try {
        const { data: codes, error } = await supabase
            .from('promo_codes')
            .select('*')
            .eq('status', 'active')
            .gt('max_uses', 0);
        if (error) throw error;
        const { data: used } = await supabase
            .from('used_promo_codes')
            .select('code')
            .eq('user_id', userId);
        const usedCodes = new Set(used?.map(u => u.code) || []);
        return (codes || [])
            .filter(c => !usedCodes.has(c.code) && (c.total_uses || 0) < c.max_uses && c.owner !== userId)
            .map(c => ({ ...c, is_used: false }));
    } catch (error) {
        return [];
    }
}

async function usePromoCode(userId, code) {
    try {
        const { data, error } = await supabase
            .from('used_promo_codes')
            .insert([{ user_id: userId, code, used_at: getCurrentTime() }])
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function incrementPromoUses(code) {
    try {
        const { data: promo } = await supabase
            .from('promo_codes')
            .select('total_uses')
            .eq('code', code)
            .single();
        const newTotal = (promo?.total_uses || 0) + 1;
        const { data, error } = await supabase
            .from('promo_codes')
            .update({ total_uses: newTotal })
            .eq('code', code)
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function createWithdrawal(withdrawalData) {
    try {
        const { data, error } = await supabase
            .from('withdrawals')
            .insert([withdrawalData])
            .select()
            .single();
        if (error) throw error;
        return data;
    } catch (error) {
        throw error;
    }
}

async function sendTelegramNotification(userId, title, message, inlineButton = null) {
    if (!BOT_TOKEN || !userId) return;
    try {
        const payload = {
            chat_id: userId,
            text: message,
            parse_mode: 'HTML',
            disable_web_page_preview: true
        };
        if (inlineButton) {
            payload.reply_markup = {
                inline_keyboard: [[{ text: inlineButton.text, url: inlineButton.url }]]
            };
        }
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
    } catch (error) {}
}

class OxaPay {
    constructor(config) {
        this.apiKey = config.apiKey;
        this.sandbox = config.sandbox || false;
        this.baseUrl = this.sandbox
            ? 'https://sandbox.oxapay.com/v1'
            : 'https://api.oxapay.com/v1';
    }

    async request(endpoint, data) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            'payout_api_key': this.apiKey
        };
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(data)
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
        for (const withdrawal of withdrawals) {
            try {
                const statusResult = await oxapay.getPayoutStatus(withdrawal.tx_id);
                if (statusResult && statusResult.data) {
                    const oxaPayStatus = statusResult.data.status;
                    if (oxaPayStatus === 'confirmed' || oxaPayStatus === 'completed') {
                        await supabase
                            .from('withdrawals')
                            .update({
                                status: 'completed',
                                tx_hash: statusResult.data.tx_hash || withdrawal.tx_hash
                            })
                            .eq('id', withdrawal.id);
                        const userMessage = `<b>✅ Your Withdrawal Confirmed!</b>\n\n💸 <code>${withdrawal.gram_amount.toFixed(5)}</code> <b>GRAM has been sent</b>\n\n`;
                        await sendTelegramNotification(withdrawal.user_id, '✅ Withdrawal Completed!', userMessage);
                    }
                }
            } catch (error) {}
        }
    } catch (error) {}
}

setInterval(async () => {
    await checkPendingWithdrawals();
}, 60000);

setTimeout(() => {
    checkPendingWithdrawals();
}, 10000);

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', time: getCurrentTime() });
});

app.get('/api/config', (req, res) => {
    res.json(APP_CONFIG);
});

app.get('/api/current-time', (req, res) => {
    res.json({ serverTime: getCurrentTime() });
});

app.post('/api/check-bot-admin', authenticate, async (req, res) => {
    try {
        const { channel } = req.body;
        if (!channel) {
            return res.status(400).json({ error: 'Channel is required' });
        }
        const isAdmin = await checkBotIsAdminInChannel(channel);
        res.json({ isAdmin });
    } catch (error) {
        logFailure('/api/check-bot-admin', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const secretToken = req.headers['x-telegram-bot-api-secret-token'];
    if (!WEBHOOK_SECRET || secretToken !== WEBHOOK_SECRET) {
        logFailure('/webhook', null, req.ip, new Error('Unauthorized webhook'));
        return res.sendStatus(403);
    }
    try {
        const update = req.body;
        if (update.message && update.message.chat && update.message.chat.type === 'private') {
            const chatId = update.message.chat.id;
            const username = update.message.chat.username || '';
            const firstName = update.message.chat.first_name || 'User';
            const photoUrl = update.message.chat.photo_url || APP_CONFIG.DEFAULT_USER_AVATAR;
            const text = update.message.text;
            let referrerId = null;
            if (text && text.startsWith('/start')) {
                const parts = text.split(' ');
                if (parts.length > 1 && !isNaN(parts[1])) {
                    referrerId = parseInt(parts[1]);
                }
            }
            const appLink = referrerId
                ? `https://t.me/PtsDropBot/app?startapp=${referrerId}`
                : `https://t.me/PtsDropBot/app`;
            const existingUser = await getUser(chatId);
            if (!existingUser) {
                const userData = {
                    id: chatId,
                    username: username || '',
                    first_name: firstName || 'User',
                    photo_url: photoUrl || APP_CONFIG.DEFAULT_USER_AVATAR,
                    created_at: getCurrentTime(),
                    gram_balance: 0,
                    referral_gram_earnings: 0,
                    level: 1,
                    total_tasks_completed: 0,
                    referral_reward_given: false,
                    state: 'active',
                    verified: false,
                    verification_completed: false,
                    total_referrals: 0,
                    last_withdraw_time: 0,
                    referred_by_verified: false,
                    wallet: null,
                    task_count: 0,
                    device_id: null,
                    ip_address: null
                };
                
                if (referrerId && referrerId !== chatId) {
                    userData.referred_by = referrerId;
                }
                
                if (referrerId && referrerId !== chatId) {
                    const referrer = await getUser(referrerId);
                    if (referrer) {
                        await updateUser(referrerId, {
                            total_referrals: (referrer.total_referrals || 0) + 1
                        });
                    }
                } 
                    
                try {
                    await createUser(userData);
                } catch (createError) {
                    logFailure('/webhook', chatId, req.ip, createError);
                }
            }
            await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    chat_id: chatId,
                    photo: 'https://slho.shop/i/7933',
                    caption: `<b>🏴‍☠️ Welcome to PIRATES DROP\n\n💎 JOIN & EARN FREE GRAM!</b>`,
                    parse_mode: 'HTML',
                    reply_markup: {
                        inline_keyboard: [
                            [{ text: '🏴‍☠️ Start App', url: appLink }],
                        ]
                    }
                })
            });
        }
        res.sendStatus(200);
    } catch (error) {
        logFailure('/webhook', null, req.ip, error);
        res.sendStatus(500);
    }
});

app.post('/api/check-membership', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { channel } = req.body;
        if (!channel) {
            return res.status(400).json({ error: 'Channel is required' });
        }
        if (!BOT_TOKEN) {
            return res.json({ isMember: true, error: 'bot_not_configured' });
        }
        const isAdmin = await checkBotIsAdminInChannel(channel);
        if (!isAdmin) {
            return res.json({ isMember: true, error: 'bot_not_admin' });
        }
        const isMember = await checkUserInChannel(userId, channel);
        res.json({ isMember });
    } catch (error) {
        logFailure('/api/check-membership', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth', strictLimiter, async (req, res) => {
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || null;
    try {
        const { initData, userId, username, firstName, photoUrl, deviceId } = req.body;
        if (!initData) {
            logFailure('/api/auth', userId, req.ip, new Error('Missing initData'));
            return res.status(400).json({ error: 'Missing initData' });
        }
        const validation = validateTelegramInitData(initData, BOT_TOKEN);
        if (!validation.valid) {
            logFailure('/api/auth', userId, req.ip, new Error('Invalid initData: ' + validation.error));
            return res.status(403).json({ error: 'Invalid Telegram data: ' + validation.error });
        }
        const telegramUser = validation.user;
        if (!telegramUser || !telegramUser.id) {
            logFailure('/api/auth', userId, req.ip, new Error('No user in initData'));
            return res.status(403).json({ error: 'No user data in initData' });
        }
        if (userId && telegramUser.id !== userId) {
            logFailure('/api/auth', userId, req.ip, new Error('User ID mismatch'));
            return res.status(403).json({ error: 'User ID mismatch' });
        }
        let user = await getUser(telegramUser.id);
        if (!user) {
            const userData = {
                id: telegramUser.id,
                username: telegramUser.username || '',
                first_name: telegramUser.first_name || 'User',
                photo_url: photoUrl || telegramUser.photo_url || APP_CONFIG.DEFAULT_USER_AVATAR,
                created_at: getCurrentTime(),
                gram_balance: 0,
                referral_gram_earnings: 0,
                level: 1,
                total_tasks_completed: 0,
                referral_reward_given: false,
                state: 'active',
                verified: false,
                verification_completed: false,
                total_referrals: 0,
                last_withdraw_time: 0,
                referred_by_verified: false,
                wallet: null,
                task_count: 0,
                device_id: deviceId || null,
                ip_address: ip || null
            };
            try {
                user = await createUser(userData);
                if (!user.referred_by) {
                    const urlParams = new URLSearchParams(initData);
                    const startParam = urlParams.get('start_param');
                    
                    if (startParam && !isNaN(startParam) && parseInt(startParam) !== telegramUser.id) {
                        user = await updateUser(telegramUser.id, {
                            referred_by: parseInt(startParam)
                        });
                    }
                }
                
            } catch (createError) {
                logFailure('/api/auth', telegramUser.id, req.ip, createError);
                user = await getUser(telegramUser.id);
                if (!user) {
                    return res.status(500).json({ error: 'Failed to create user' });
                }
            }
        } else {
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
        res.json({ success: true, token });
    } catch (error) {
        logFailure('/api/refresh', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/get-user', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const cacheKey = `getUser_${userId}`;
        const cached = getUserCache.get(cacheKey);
        const now = Date.now();
        if (cached && (now - cached.timestamp) < 3000) {
            return res.json(cached.data);
        }
        if (!checkCooldown(userId, req.path)) {
            return res.status(429).json({ error: 'Too many requests. Please wait.' });
        }
        let user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (user.state === 'ban') {
            return res.status(403).json({ error: 'Account banned', banned: true });
        }
        const [completedTasks, withdrawals, referrals] = await Promise.all([
            getCompletedTasks(userId),
            getWithdrawals(userId),
            getReferrals(userId)
        ]);
        const responseData = {
            user: user,
            completedTasks,
            withdrawals,
            referrals
        };
        getUserCache.set(cacheKey, { data: responseData, timestamp: now });
        res.json(responseData);
    } catch (error) {
        logFailure('/api/get-user', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/update-user', authenticate, async (req, res) => {
    res.json({ success: true });
});

app.post('/api/complete-task', authenticate, strictLimiter, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId, taskType } = req.body;
        const cooldownCheck = checkTaskCompletionCooldown(userId);
        if (!cooldownCheck.allowed) {
            return res.status(429).json({ error: `Please wait ${cooldownCheck.remaining} seconds before completing another task` });
        }
        const user = await getUser(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        let reward = 0;
        if (taskType === 'special') {
            const task = APP_CONFIG.SPECIAL_TASKS.find(t => t.id === taskId);
            if (!task) {
                return res.status(404).json({ error: 'Task not found' });
            }
            const channelMatch = task.url.match(/t\.me\/([^\/\?]+)/);
            if (channelMatch) {
                const chatId = channelMatch[1];
                const isAdmin = await checkBotIsAdminInChannel(chatId);
                if (isAdmin) {
                    const isMember = await checkUserInChannel(userId, chatId);
                    if (!isMember) {
                        return res.status(400).json({ error: 'Join the channel first' });
                    }
                }
            }
            reward = task.reward;
            if (!user.completed_special_tasks) {
                await updateUser(userId, { completed_special_tasks: [taskId] });
            } else if (!user.completed_special_tasks.includes(taskId)) {
                await updateUser(userId, { completed_special_tasks: [...user.completed_special_tasks, taskId] });
            }
        } else {
            const { data: task, error: taskError } = await supabase
                .from('tasks')
                .select('*')
                .eq('id', taskId)
                .single();
            if (taskError || !task) {
                return res.status(404).json({ error: 'Task not found' });
            }
            if (task.verification && task.url) {
                const chatId = task.url.match(/t\.me\/([^\/\?]+)/)?.[1];
                if (chatId) {
                    const isMember = await checkUserInChannel(userId, chatId);
                    if (!isMember) {
                        return res.status(400).json({ error: 'Join the channel first' });
                    }
                }
            }
            const { data: completed } = await supabase
                .from('user_completed_tasks')
                .select('task_id')
                .eq('user_id', userId)
                .eq('task_id', taskId)
                .single();
            if (completed) {
                return res.status(400).json({ error: 'Task already completed!' });
            }
            reward = task.reward || APP_CONFIG.SOCIAL_TASK_REWARD;
            await supabase
                .from('user_completed_tasks')
                .insert([{ user_id: userId, task_id: taskId, completed_at: getCurrentTime() }]);
            const newTotalCompleted = (task.total_completed || 0) + 1;
            await supabase
                .from('tasks')
                .update({ total_completed: newTotalCompleted })
                .eq('id', taskId);
        }
        setTaskCompletionCooldown(userId);
        const updatedUser = await updateUser(userId, {
            gram_balance: (user.gram_balance || 0) + reward,
            total_tasks_completed: (user.total_tasks_completed || 0) + 1
        });
        if (user.referred_by && taskType !== 'special') {
            const referralEarning = reward * (APP_CONFIG.REFERRAL_TASKS_PERCENTAGE / 100);
            await addReferralCommission(user.referred_by, referralEarning, 'gram');
        }
        res.json({
            success: true,
            user: updatedUser,
            reward: reward
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
        let allChannelsJoined = true;
        for (const task of APP_CONFIG.SPECIAL_TASKS) {
            const channelMatch = task.url.match(/t\.me\/([^\/\?]+)/);
            if (channelMatch) {
                const chatId = channelMatch[1];
                const isAdmin = await checkBotIsAdminInChannel(chatId);
                if (isAdmin) {
                    const isMember = await checkUserInChannel(userId, chatId);
                    if (!isMember) {
                        allChannelsJoined = false;
                        break;
                    }
                }
            }
        }
        if (!allChannelsJoined) {
            return res.status(400).json({ error: 'Please join all required channels first' });
        }
        const reward = APP_CONFIG.VERIFY_BONUS;
        const updatedUser = await updateUser(userId, {
            verified: true,
            verification_completed: true,
        });
        
        if (user.referred_by && !user.referral_reward_given) {
            const referrer = await getUser(user.referred_by);
            if (referrer) {
                const newTotal = (referrer.total_referrals || 0) + 1;
                await updateUser(user.referred_by, {
                    verified_referrals: (referrer.verified_referrals || 0) + 1,
                    referral_gram_earnings: (referrer.referral_gram_earnings || 0) + APP_CONFIG.REFERRAL_REWARD_GRAM
                });
                await updateUser(userId, { referral_reward_given: true });
            }
        }
        res.json({
            success: true,
            user: updatedUser
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
        const amount = user.referral_gram_earnings || 0;
        if (amount < APP_CONFIG.MIN_CLAIM_GRAM) {
            return res.status(400).json({ error: `Minimum claim: ${APP_CONFIG.MIN_CLAIM_GRAM} GRAM` });
        }
        const updatedUser = await updateUser(userId, {
            gram_balance: (user.gram_balance || 0) + amount,
            referral_gram_earnings: 0
        });
        res.json({
            success: true,
            user: updatedUser,
            claimed: amount
        });
    } catch (error) {
        logFailure('/api/claim-referral-earnings', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/tasks/:category', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { category } = req.params;
        if (!checkCooldown(userId, req.path)) {
            return res.status(429).json({ error: 'Too many requests. Please wait.' });
        }
        const tasks = await getTasks(category, userId);
        res.json({ tasks });
    } catch (error) {
        logFailure('/api/tasks', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/my-tasks', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { data: tasks, error } = await supabase
            .from('tasks')
            .select('*')
            .eq('owner', userId)
            .eq('category', 'community')
            .order('created_at', { ascending: false });
        if (error) throw error;
        res.json({ tasks: tasks || [] });
    } catch (error) {
        logFailure('/api/my-tasks', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/delete-task', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { taskId } = req.body;
        const { data: task, error: checkError } = await supabase
            .from('tasks')
            .select('owner')
            .eq('id', taskId)
            .single();
        if (checkError || !task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        if (task.owner !== userId) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        await supabase.from('tasks').delete().eq('id', taskId);
        await supabase.from('user_completed_tasks').delete().eq('task_id', taskId);
        res.json({ success: true });
    } catch (error) {
        logFailure('/api/delete-task', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/promo-codes', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const codes = await getActivePromoCodes(userId);
        res.json({ codes });
    } catch (error) {
        logFailure('/api/promo-codes', req._userId, req.ip, error);
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
            .single();
        if (usedData) {
            return res.status(400).json({ error: 'Code already used' });
        }
        if (promo.required_channel) {
            const isMember = await checkUserInChannel(userId, promo.required_channel);
            if (!isMember) {
                return res.status(400).json({ error: 'Join the required channel first', requiredChannel: promo.required_channel });
            }
        }
        setPromoCooldown(userId);
        await usePromoCode(userId, code);
        await incrementPromoUses(code);
        const updatedUser = await updateUser(userId, {
            gram_balance: (user.gram_balance || 0) + promo.reward_amount,
            last_promo_time: getCurrentTime()
        });
        res.json({
            success: true,
            user: updatedUser,
            reward: `+${promo.reward_amount} GRAM`,
            rewardAmount: promo.reward_amount
        });
    } catch (error) {
        logFailure('/api/claim-promo-code', req._userId, req.ip, error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/check-payment', authenticate, async (req, res) => {
    try {
        const userId = req._userId;
        const { memo, amount, taskData } = req.body;
        const user = await getUser(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const address = APP_CONFIG.PAYMENT_WALLET || APP_CONFIG.TON_WALLET_ADDRESS;
        if (!address) {
            return res.status(500).json({ error: 'Payment wallet not configured' });
        }
        if (await isMemoUsed(memo)) {
            return res.json({ success: false, error: 'Transaction already used' });
        }
        const response = await fetch(`https://toncenter.com/api/v2/getTransactions?address=${address}&limit=3`);
        const data = await response.json();
        if (!data.ok) {
            return res.status(500).json({ error: 'Payment API error' });
        }
        let foundTx = null;
        if (data.result && data.result.length > 0) {
            foundTx = data.result.find(tx => {
                const msg = tx.in_msg?.message;
                return msg && msg.includes(memo);
            });
        }
        if (foundTx) {
            const onChainMemo = foundTx.in_msg?.message || '';
            if (onChainMemo !== memo) {
                return res.json({ success: false, error: 'Failed to create task.' });
            }
            const txAmount = parseFloat(foundTx.in_msg?.value) / 1000000000 || 0;
            const rewardNum = APP_CONFIG.SOCIAL_TASK_REWARD;
            const totalNum = parseInt(taskData.total);
            if (totalNum < 100 || totalNum > 5000) {
                return res.json({ success: false, error: 'Failed to create task.' });
            }
            const requiredAmount = (totalNum / 100) * (APP_CONFIG.PRICE_PER_100 || 0.20);
            if (txAmount >= requiredAmount * 0.98) {
                let verification = taskData.verification || false;
                if (verification && taskData.link) {
                    const channelMatch = taskData.link.match(/t\.me\/([^\/\?]+)/);
                    if (channelMatch) {
                        const isAdmin = await checkBotIsAdminInChannel(channelMatch[1]);
                        if (!isAdmin) {
                            return res.json({ success: false, error: 'Bot is not admin in the channel. Please add bot as admin.' });
                        }
                    }
                }
                const { data: existingTask } = await supabase
                    .from('tasks')
                    .select('id')
                    .eq('id', memo)
                    .maybeSingle();
                if (existingTask) {
                    return res.json({ success: false, error: 'Failed to create task.' });
                }
                const taskToAdd = {
                    id: memo,
                    name: taskData.name,
                    url: taskData.link,
                    category: 'community',
                    reward: APP_CONFIG.SOCIAL_TASK_REWARD,
                    total: totalNum,
                    verification: verification,
                    owner: userId,
                    status: 'active',
                    created_at: getCurrentTime(),
                    total_completed: 0,
                    notified: false
                };
                const { data: taskResult, error: taskError } = await supabase
                    .from('tasks')
                    .insert([taskToAdd])
                    .select()
                    .single();
                if (taskError) {
                    logFailure('/api/check-payment', userId, req.ip, taskError, { memo });
                    return res.status(500).json({ error: 'Failed to add task' });
                }
                await updateUser(userId, { task_count: (user.task_count || 0) + 1 });
                await recordMemo(memo, userId);
                return res.json({
                    success: true,
                    task: taskResult,
                    message: 'Payment verified and task added'
                });
            } else {
                return res.json({ success: false, error: 'Insufficient payment amount' });
            }
        } else {
            return res.json({ success: false, error: 'Payment not found' });
        }
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
            return res.status(400).json({ error: 'Please verify your account first' });
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
            return res.status(500).json({ error: 'Payment provider error: ' + payoutError.message });
        }
    } catch (error) {
        logFailure('/api/withdraw-gram', userId, req.ip, error);
        res.status(500).json({ error: 'Failed to send withdrawal request: ' + error.message });
    } finally {
        setTimeout(() => withdrawLocks.delete(userId), 3000);
    }
});

const PORT = process.env.PORT || 8080;

const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`PIRATES DROP server running on port ${PORT}`);
});

server.on('error', (error) => {
    console.error('Server error:', error);
});

process.on('SIGTERM', () => {
    server.close(() => {
        process.exit(0);
    });
});
