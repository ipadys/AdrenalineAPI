// server.js
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

// Инициализация Firebase
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.database();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many requests' }
});

app.use('/api/', limiter);

// Валидация формата ключа
const validateKeyFormat = (key) => {
  return /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(key);
};

// Генерация fingerprint из нескольких параметров
const generateFingerprint = (userId, clientId, jobId) => {
  const data = `${userId}-${clientId}-${jobId}`;
  return crypto.createHash('sha256').update(data).digest('hex');
};

// Основной endpoint для проверки ключа
app.post('/api/verify-key', async (req, res) => {
  try {
    const { key, userId, clientId, jobId } = req.body;

    // Валидация входных данных
    if (!key || !userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing key or userId' 
      });
    }

    if (!validateKeyFormat(key)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid key format' 
      });
    }

    // Генерируем fingerprint
    const fingerprint = generateFingerprint(userId, clientId || '', jobId || '');

    // Получаем данные ключа
    const keysRef = db.ref('keys');
    const snapshot = await keysRef.once('value');
    const allKeys = snapshot.val();

    if (!allKeys) {
      return res.status(404).json({ 
        success: false, 
        message: 'No keys in database' 
      });
    }

    // Ищем ключ
    let keyData = null;
    let keyOwner = null;

    for (const [owner, data] of Object.entries(allKeys)) {
      if (data.key === key) {
        keyData = data;
        keyOwner = owner;
        break;
      }
    }

    if (!keyData) {
      return res.status(404).json({ 
        success: false, 
        message: 'Invalid key' 
      });
    }

    // Проверка срока действия
    const now = Math.floor(Date.now() / 1000);
    if (now > keyData.expires) {
      return res.status(403).json({ 
        success: false, 
        message: 'Key expired' 
      });
    }

    // Инициализация массива разрешенных пользователей
    if (!keyData.allowedUsers) {
      keyData.allowedUsers = [keyOwner];
    }

    // Инициализация fingerprints для каждого пользователя
    if (!keyData.fingerprints) {
      keyData.fingerprints = {};
    }

    // Проверка, разрешен ли этот userId
    const userIdStr = userId.toString();
    if (!keyData.allowedUsers.includes(userIdStr)) {
      return res.status(403).json({ 
        success: false, 
        message: 'User not authorized for this key' 
      });
    }

    // Проверка fingerprint для этого пользователя
    if (keyData.fingerprints[userIdStr]) {
      // Fingerprint уже существует - проверяем совпадение
      if (keyData.fingerprints[userIdStr] !== fingerprint) {
        return res.status(403).json({ 
          success: false, 
          message: 'Device mismatch. Key is locked to another device.' 
        });
      }
    } else {
      // Первый вход с этого userId - сохраняем fingerprint
      keyData.fingerprints[userIdStr] = fingerprint;
    }

    // Проверка лимита одновременных сессий (опционально)
    const maxConcurrentSessions = keyData.maxSessions || keyData.allowedUsers.length;
    const activeSessions = keyData.activeSessions || {};
    
    // Очищаем старые сессии (старше 5 минут)
    const sessionTimeout = 5 * 60 * 1000;
    Object.keys(activeSessions).forEach(sessionUser => {
      if (now * 1000 - activeSessions[sessionUser] > sessionTimeout) {
        delete activeSessions[sessionUser];
      }
    });

    activeSessions[userIdStr] = Date.now();

    if (Object.keys(activeSessions).length > maxConcurrentSessions) {
      return res.status(403).json({ 
        success: false, 
        message: 'Maximum concurrent sessions exceeded' 
      });
    }

    // Обновляем данные в Firebase
    await keysRef.child(keyOwner).update({
      lastUsed: now,
      lastUserId: userIdStr,
      fingerprints: keyData.fingerprints,
      activeSessions: activeSessions
    });

    // Успешная валидация
    return res.json({ 
      success: true, 
      message: `Key valid until ${new Date(keyData.expires * 1000).toISOString()}`,
      data: {
        type: keyData.type,
        expires: keyData.expires,
        owner: keyOwner,
        allowedUsers: keyData.allowedUsers.length,
        isOwner: userIdStr === keyOwner
      }
    });

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// Endpoint для добавления твинка (только для владельца)
app.post('/api/add-alt', async (req, res) => {
  try {
    const { key, ownerUserId, altUserId } = req.body;

    if (!key || !ownerUserId || !altUserId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing parameters' 
      });
    }

    const keysRef = db.ref('keys');
    const snapshot = await keysRef.once('value');
    const allKeys = snapshot.val();

    let keyData = null;
    let keyOwner = null;

    for (const [owner, data] of Object.entries(allKeys)) {
      if (data.key === key) {
        keyData = data;
        keyOwner = owner;
        break;
      }
    }

    if (!keyData) {
      return res.status(404).json({ 
        success: false, 
        message: 'Key not found' 
      });
    }

    // Проверка, что запрос от владельца
    if (keyOwner !== ownerUserId.toString()) {
      return res.status(403).json({ 
        success: false, 
        message: 'Only key owner can add alts' 
      });
    }

    // Проверка лимита альтов
    const maxAlts = keyData.maxAlts || 5;
    if (!keyData.allowedUsers) {
      keyData.allowedUsers = [keyOwner];
    }

    if (keyData.allowedUsers.length >= maxAlts) {
      return res.status(403).json({ 
        success: false, 
        message: `Maximum alts limit reached (${maxAlts})` 
      });
    }

    const altUserIdStr = altUserId.toString();

    if (keyData.allowedUsers.includes(altUserIdStr)) {
      return res.status(400).json({ 
        success: false, 
        message: 'User already added' 
      });
    }

    keyData.allowedUsers.push(altUserIdStr);

    await keysRef.child(keyOwner).update({
      allowedUsers: keyData.allowedUsers
    });

    return res.json({ 
      success: true, 
      message: 'Alt account added successfully',
      data: {
        allowedUsers: keyData.allowedUsers
      }
    });

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// Endpoint для удаления твинка
app.post('/api/remove-alt', async (req, res) => {
  try {
    const { key, ownerUserId, altUserId } = req.body;

    const keysRef = db.ref('keys');
    const snapshot = await keysRef.once('value');
    const allKeys = snapshot.val();

    let keyData = null;
    let keyOwner = null;

    for (const [owner, data] of Object.entries(allKeys)) {
      if (data.key === key) {
        keyData = data;
        keyOwner = owner;
        break;
      }
    }

    if (!keyData) {
      return res.status(404).json({ success: false, message: 'Key not found' });
    }

    if (keyOwner !== ownerUserId.toString()) {
      return res.status(403).json({ success: false, message: 'Only owner can remove alts' });
    }

    const altUserIdStr = altUserId.toString();
    
    if (!keyData.allowedUsers || !keyData.allowedUsers.includes(altUserIdStr)) {
      return res.status(400).json({ success: false, message: 'User not in allowed list' });
    }

    // Нельзя удалить самого владельца
    if (altUserIdStr === keyOwner) {
      return res.status(400).json({ success: false, message: 'Cannot remove owner' });
    }

    keyData.allowedUsers = keyData.allowedUsers.filter(u => u !== altUserIdStr);

    // Удаляем fingerprint этого пользователя
    if (keyData.fingerprints && keyData.fingerprints[altUserIdStr]) {
      delete keyData.fingerprints[altUserIdStr];
    }

    await keysRef.child(keyOwner).update({
      allowedUsers: keyData.allowedUsers,
      fingerprints: keyData.fingerprints || {}
    });

    return res.json({ 
      success: true, 
      message: 'Alt removed successfully',
      data: { allowedUsers: keyData.allowedUsers }
    });

  } catch (error) {
    console.error('Error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);

});
