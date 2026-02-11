// server.js
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch'); // npm install node-fetch@2

const app = express();
app.use(express.json());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many requests' }
});
app.use('/api/', limiter);

// Firebase Realtime Database URL
const FIREBASE_URL = "https://adrebaline-7fd8d-default-rtdb.firebaseio.com/keys.json";

// Генерация fingerprint
const crypto = require('crypto');
const generateFingerprint = (userId, clientId, jobId) => {
  const data = `${userId}-${clientId}-${jobId}`;
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Проверка ключа
app.post('/api/verify-key', async (req, res) => {
  try {
    const { key, userId, clientId, jobId } = req.body;

    if (!key || !userId) {
      return res.status(400).json({ success: false, message: "Missing key or userId" });
    }

    // Получаем все ключи из Firebase
    const fbResponse = await fetch(FIREBASE_URL);
    const allKeys = await fbResponse.json();

    if (!allKeys) return res.status(404).json({ success: false, message: "No keys in database" });

    // Ищем ключ
    let found = null;
    for (const [ownerId, data] of Object.entries(allKeys)) {
      if (data.key === key) {
        found = { ownerId, data };
        break;
      }
    }

    if (!found) return res.status(404).json({ success: false, message: "Invalid key" });

    // Проверка срока действия
    const now = Math.floor(Date.now() / 1000);
    if (now > found.data.expires) return res.status(403).json({ success: false, message: "Key expired" });

    // Проверка allowedUsers
    const allowedUsers = found.data.allowedUsers || [found.ownerId];
    if (!allowedUsers.includes(String(userId))) {
      return res.status(403).json({ success: false, message: "User not allowed" });
    }

    await fetch(`https://adrebaline-7fd8d-default-rtdb.firebaseio.com/keys/${found.ownerId}.json`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        lastUsed: now,
        lastUserId: String(userId),
      })
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

// Добавление твинка
app.post('/api/add-alt', async (req, res) => {
  try {
    const { key, ownerUserId, altUserId } = req.body;
    if (!key || !ownerUserId || !altUserId)
      return res.status(400).json({ success: false, message: "Missing parameters" });

    const fbResponse = await fetch(FIREBASE_URL);
    const allKeys = await fbResponse.json();

    let found = null;
    for (const [ownerId, data] of Object.entries(allKeys)) {
      if (data.key === key) {
        found = { ownerId, data };
        break;
      }
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

// Удаление твинка
app.post('/api/remove-alt', async (req, res) => {
  try {
    const { key, ownerUserId, altUserId } = req.body;
    const fbResponse = await fetch(FIREBASE_URL);
    const allKeys = await fbResponse.json();

    let found = null;
    for (const [ownerId, data] of Object.entries(allKeys)) {
      if (data.key === key) {
        found = { ownerId, data };
        break;
      }
    }

    if (!found) return res.status(404).json({ success: false, message: "Key not found" });
    if (String(ownerUserId) !== found.ownerId)
      return res.status(403).json({ success: false, message: "Only owner can remove alts" });

    const altStr = String(altUserId);
    if (altStr === found.ownerId) return res.status(400).json({ success: false, message: "Cannot remove owner" });

    if (!found.data.allowedUsers.includes(altStr))
      return res.status(400).json({ success: false, message: "User not in allowed list" });

    found.data.allowedUsers = found.data.allowedUsers.filter(u => u !== altStr);
    await fetch(`https://adrebaline-7fd8d-default-rtdb.firebaseio.com/keys/${found.ownerId}.json`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        allowedUsers: found.data.allowedUsers,
      })
    });

    return res.json({ success: true, message: "Alt removed successfully", data: { allowedUsers: found.data.allowedUsers } });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Health check
app.get('/health', (_, res) => res.json({ status: 'ok', timestamp: Date.now() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

