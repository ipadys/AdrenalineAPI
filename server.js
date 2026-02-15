const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

// ============================================
// ENCRYPTION CONFIG
// Этот же ключ вставь в Lua клиент
// ============================================
const SHARED_SECRET = "a7f3k9m2p5q8s1v4w6x0y3z8b2d5e7h1"; // ровно 32 символа

function encryptResponse(data) {
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(SHARED_SECRET, 'utf8');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const jsonStr = JSON.stringify(data);
  let encrypted = cipher.update(jsonStr, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  // base64url — заменяем проблемные символы + / =
  const toBase64url = (str) => str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  
  const ivB64 = toBase64url(iv.toString('base64'));
  const dataB64 = toBase64url(encrypted);
  
  const hmac = crypto.createHmac('sha256', key)
    .update(ivB64 + dataB64)
    .digest('base64');
    
  return { iv: ivB64, data: dataB64, hmac: toBase64url(hmac) };
}

// Middleware — все res.json() автоматически шифруются
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = function(data) {
    return originalJson(encryptResponse(data));
  };
  next();
});

// ============================================
// RATE LIMITING
// ============================================
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many requests' }
});
app.use('/api/', limiter);

// ============================================
// CONFIG
// ============================================
const FIREBASE_URL = "https://adrebaline-7fd8d-default-rtdb.firebaseio.com/keys.json";

const generateFingerprint = (userId, clientId, jobId) => {
  const data = `${userId}-${clientId}-${jobId}`;
  return crypto.createHash('sha256').update(data).digest('hex');
};

// ============================================
// ROUTES
// ============================================

app.post('/api/verify-key', async (req, res) => {
  try {
    const { key, userId, clientId, jobId } = req.body;

    if (!key || !userId) {
      return res.status(400).json({ success: false, message: "Missing key or userId" });
    }

    if (key === "Free") {
      return res.json({ success: true, message: "Free access granted", data: { type: "Free" } });
    }

    const fbResponse = await fetch(FIREBASE_URL);
    const allKeys = await fbResponse.json();

    if (!allKeys) return res.status(404).json({ success: false, message: "No keys in database" });

    let found = null;
    for (const [ownerId, data] of Object.entries(allKeys)) {
      if (data.key === key) { found = { ownerId, data }; break; }
    }

    if (!found) return res.status(404).json({ success: false, message: "Invalid key" });

    const now = Math.floor(Date.now() / 1000);
    if (now > found.data.expires) return res.status(403).json({ success: false, message: "Key expired" });

    const allowedUsers = found.data.allowedUsers || [found.ownerId];
    if (!allowedUsers.includes(String(userId))) {
      return res.status(403).json({ success: false, message: "User not allowed" });
    }

    found.data.fingerprints = found.data.fingerprints || {};
    const fingerprint = generateFingerprint(userId, clientId || '', jobId || '');
    if (found.data.fingerprints[userId] && found.data.fingerprints[userId] !== fingerprint) {
      return res.status(403).json({ success: false, message: "Device mismatch. Key locked." });
    } else {
      found.data.fingerprints[userId] = fingerprint;
    }

    await fetch(`https://adrebaline-7fd8d-default-rtdb.firebaseio.com/keys/${found.ownerId}.json`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lastUsed: now, lastUserId: String(userId), fingerprints: found.data.fingerprints })
    });

    return res.json({
      success: true,
      message: `Key valid until ${new Date(found.data.expires * 1000).toISOString()}`,
      data: {
        key: found.data.key,
        type: found.data.type,
        owner: found.ownerId,
        allowedUsers: allowedUsers,
        isOwner: String(userId) === found.ownerId
      }
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post('/api/add-alt', async (req, res) => {
  try {
    const { key, ownerUserId, altUserId } = req.body;
    if (!key || !ownerUserId || !altUserId)
      return res.status(400).json({ success: false, message: "Missing parameters" });

    const fbResponse = await fetch(FIREBASE_URL);
    const allKeys = await fbResponse.json();

    let found = null;
    for (const [ownerId, data] of Object.entries(allKeys)) {
      if (data.key === key) { found = { ownerId, data }; break; }
    }

    if (!found) return res.status(404).json({ success: false, message: "Key not found" });
    if (String(ownerUserId) !== found.ownerId)
      return res.status(403).json({ success: false, message: "Only owner can add alts" });

    const maxAlts = found.data.maxAlts || 5;
    found.data.allowedUsers = found.data.allowedUsers || [found.ownerId];

    if (found.data.allowedUsers.length >= maxAlts)
      return res.status(403).json({ success: false, message: `Maximum alts limit reached (${maxAlts})` });

    if (found.data.allowedUsers.includes(String(altUserId)))
      return res.status(400).json({ success: false, message: "User already added" });

    found.data.allowedUsers.push(String(altUserId));

    await fetch(`https://adrebaline-7fd8d-default-rtdb.firebaseio.com/keys/${found.ownerId}.json`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ allowedUsers: found.data.allowedUsers })
    });

    return res.json({ success: true, message: "Alt added successfully", data: { allowedUsers: found.data.allowedUsers } });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post('/api/remove-alt', async (req, res) => {
  try {
    const { key, ownerUserId, altUserId } = req.body;
    const fbResponse = await fetch(FIREBASE_URL);
    const allKeys = await fbResponse.json();

    let found = null;
    for (const [ownerId, data] of Object.entries(allKeys)) {
      if (data.key === key) { found = { ownerId, data }; break; }
    }

    if (!found) return res.status(404).json({ success: false, message: "Key not found" });
    if (String(ownerUserId) !== found.ownerId)
      return res.status(403).json({ success: false, message: "Only owner can remove alts" });

    const altStr = String(altUserId);
    if (altStr === found.ownerId) return res.status(400).json({ success: false, message: "Cannot remove owner" });

    if (!found.data.allowedUsers.includes(altStr))
      return res.status(400).json({ success: false, message: "User not in allowed list" });

    found.data.allowedUsers = found.data.allowedUsers.filter(u => u !== altStr);
    if (found.data.fingerprints && found.data.fingerprints[altStr]) delete found.data.fingerprints[altStr];

    await fetch(`https://adrebaline-7fd8d-default-rtdb.firebaseio.com/keys/${found.ownerId}.json`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ allowedUsers: found.data.allowedUsers, fingerprints: found.data.fingerprints || {} })
    });

    return res.json({ success: true, message: "Alt removed successfully", data: { allowedUsers: found.data.allowedUsers } });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: Date.now() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
