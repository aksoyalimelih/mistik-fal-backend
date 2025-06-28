const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config({ path: './config.env' });
const fs = require('fs');
const axios = require('axios');
const xss = require('xss-clean');
const hpp = require('hpp');
const winston = require('winston');
const Joi = require('joi');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cookieParser = require('cookie-parser');
const mongoSanitize = require('express-mongo-sanitize');
const morgan = require('morgan');

const app = express();
app.set('trust proxy', 1); // Render ve benzeri platformlar için gerekli
const PORT = process.env.PORT || 3020;

const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB bağlantısı ve User modeli en başa taşındı
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/mistikfal';
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  birthDate: { type: Date },
  role: { type: String, enum: ['user', 'admin', 'fortune_teller'], default: 'user' },
  credits: { type: Number, default: 10 },
  createdAt: { type: Date, default: Date.now },
  trialRights: {
    tarot: { type: Boolean, default: true },
    coffee: { type: Boolean, default: true },
    zodiac: { type: Boolean, default: true },
    face: { type: Boolean, default: true }
  }
});
const User = mongoose.model('User', userSchema);

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB bağlantısı başarılı'))
  .catch(err => console.error('MongoDB bağlantı hatası:', err));

// JWT doğrulama middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: 'Invalid or expired token' });
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: 'No token provided' });
  }
}

// Middleware
app.use(helmet());
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'http://localhost:5176',
    'http://localhost:5177',
    'https://couva.de',
    'https://www.couva.de' // www'li domain de eklendi
  ],
  credentials: true
}));
app.use(express.json({ limit: '50mb' })); // Resim için daha büyük limit
app.use(cookieParser());
app.use(passport.initialize());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Middleware to check API key
const checkApiKey = (req, res, next) => {
  if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'your_gemini_api_key_here') {
    return res.status(500).json({ 
      error: 'Gemini API key not configured. Please set GEMINI_API_KEY in config.env' 
    });
  }
  next();
};

// Helper function to determine if image is provided
const hasImage = (imageData) => {
  return imageData && imageData.trim() !== '';
};

// Helper function to create image part for Gemini
const createImagePart = (imageData) => {
  // Remove data:image/...;base64, prefix if present
  const base64Data = imageData.replace(/^data:image\/[a-z]+;base64,/, '');
  return {
    inlineData: {
      data: base64Data,
      mimeType: 'image/jpeg' // Default, could be made dynamic
    }
  };
};

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Fortune Backend is running' });
});

// User registration (MongoDB)
app.post('/api/register', async (req, res) => {
  try {
    const schema = Joi.object({
      username: Joi.string().min(2).max(32).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).max(64).required(),
      birthDate: Joi.date().required()
    });
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    const { username, email, password, birthDate } = req.body;
    // Email benzersizliği kontrolü
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    // Şifreyi hashle
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword,
      birthDate,
      credits: 10,
      trialRights: { tarot: true, coffee: true, zodiac: true, face: true }
    });
    await user.save();
    res.status(201).json({
      message: 'User registered successfully',
      user: { id: user._id, username, email, role: user.role, credits: user.credits, trialRights: user.trialRights }
    });
  } catch (error) {
    logger.error('Registration error', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User login (MongoDB + JWT)
app.post('/api/login', async (req, res) => {
  console.log('GELEN BODY:', req.body); // DEBUG LOG
  try {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().min(6).max(64).required()
    });
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    // JWT token oluştur
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        credits: user.credits,
        trialRights: user.trialRights
      }
    });
  } catch (error) {
    logger.error('Login error', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user credits (MongoDB)
app.get('/api/user/:email/credits', async (req, res) => {
  try {
    const { email } = req.params;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ 
      credits: user.credits,
      trialRights: user.trialRights
    });
  } catch (error) {
    console.error('Get credits error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Winston logger kurulumu
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Fortune telling endpoint with image support
app.post('/api/fortune', checkApiKey, async (req, res) => {
  try {
    const { type, userEmail, question, birthDate, zodiacSign, imageData } = req.body;
    if (!userEmail) {
      return res.status(400).json({ error: 'User email is required' });
    }
    // Email'i normalize et (küçük harfe çevir, boşlukları kırp)
    const normalizedEmail = userEmail.trim().toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(404).json({ error: 'User not found', email: normalizedEmail });
    }
    // Fal türüne göre promptu oluştur
    let prompt = '';
    switch (type) {
      case 'face':
        prompt = `Sen bir yüz analizi uzmanısın. İnsanların yüz hatlarını, ifadelerini ve simalarını analiz ederek onların karakter özelliklerini, ruh hallerini ve potansiyel geleceğini yorumluyorsun. Her yüzün eşsiz olduğunu bilerek, yüzün detaylarındaki ipuçlarından derinlemesine yorumlar yap. Sadece yüz analizi yap, başka fal türlerinden bahsetme.`;
        break;
      case 'coffee':
        prompt = `Sen bir kahve falcısısın. Fincandaki şekilleri analiz ederek insanların geçmişi, bugünü ve geleceği hakkında detaylı ve gizemli yorumlar yapıyorsun. Sadece kahve falı yorumu yap, başka fal türlerinden bahsetme.`;
        break;
      case 'tarot':
        prompt = `Sen bir tarot falcısısın. Tarot kartlarının sembolizmini ve anlamını kullanarak, danışanların hayat yolculuklarında karşılaşabilecekleri fırsatlar ve zorluklar hakkında içgörüler sağlıyorsun. Sadece tarot yorumu yap, başka fal türlerinden bahsetme.`;
        break;
      case 'zodiac':
        prompt = `Sen bir yıldızname ve burç uzmanısın. Kişilerin doğum tarihlerine, saatlerine ve astrolojik haritalarına bakarak yıldızların enerjisini ve etkisini analiz ediyorsun. Sadece burç ve yıldızname yorumu yap, başka fal türlerinden bahsetme.`;
        break;
      case 'dream':
        prompt = `Sen bir rüya tabiri uzmanısın. Kullanıcının rüyasını analiz et, sembollerin anlamını açıkla, geçmiş ve geleceğe dair gizemli ve gerçekçi öngörülerde bulun. Sadece rüya tabiri yap, başka fal türlerinden bahsetme.`;
        break;
      default:
        prompt = `Sen deneyimli bir falcısın. Kullanıcıya gönderilen fal türüne göre gerçekçi, gizemli ve mistik yorumlar yap. Sadece istenen fal türüne odaklan, başka türlerden bahsetme.`;
    }
    if (question) prompt += `\nSoru: ${question}`;
    if (birthDate) prompt += `\nDoğum tarihi: ${birthDate}`;
    if (zodiacSign) prompt += `\nBurç: ${zodiacSign}`;
    const hasImageData = hasImage(imageData);
    const modelName = "gemini-1.5-flash";
    const model = genAI.getGenerativeModel({ model: modelName });
    console.log('MODELE GİDEN PROMPT:', prompt);
    if (hasImageData) {
      console.log('GÖNDERİLEN RESİM VAR (base64 uzunluğu):', imageData.length);
    }
    fs.appendFileSync('model-logs.txt', JSON.stringify({ date: new Date(), type, userEmail, prompt, hasImageData, imageLength: imageData ? imageData.length : 0 }) + '\n');
    // Önce deneme hakkı kontrolü
    if (user.trialRights && user.trialRights[type]) {
      user.trialRights[type] = false; // Hakkı tüket
      await user.save();
      let result;
      if (hasImageData) {
        const imagePart = createImagePart(imageData);
        result = await model.generateContent([prompt, imagePart]);
      } else {
        result = await model.generateContent(prompt);
      }
      const response = await result.response;
      const text = response.text();
      console.log('MODEL ÇIKTISI:', text);
      fs.appendFileSync('model-logs.txt', JSON.stringify({ date: new Date(), type, userEmail, prompt, response: text }) + '\n');
      res.json({
        fortune: text,
        type,
        creditsRemaining: user.credits,
        creditsUsed: 0,
        trialUsed: true,
        trialRights: user.trialRights,
        hasImage: hasImageData,
        timestamp: new Date().toISOString()
      });
      return;
    }
    // Deneme hakkı yoksa kredi kontrolü
    if (user.credits <= 0) {
      return res.status(402).json({ error: 'Insufficient credits' });
    }
    
    // Fal türüne göre kredi maliyeti belirle
    const creditCosts = {
      tarot: 5,
      coffee: 10,
      palm: 10,
      astrology: 15,
      numerology: 5,
      dream: 5,
      love: 5,
      'face-reading': 15,
      crystal: 5,
      graphology: 10,
      'bean-fortune': 8,
      'water-fortune': 8,
      'candle-fortune': 8,
      'playing-cards': 6,
      zodiac: 5,
      face: 15
    };
    
    const creditCost = creditCosts[type] || 1;
    
    // Yeterli kredi kontrolü
    if (user.credits < creditCost) {
      return res.status(402).json({ 
        error: 'Insufficient credits', 
        required: creditCost, 
        available: user.credits 
      });
    }
    
    // Krediyi düş
    user.credits -= creditCost;
    await user.save();
    let result;
    if (hasImageData) {
      const imagePart = createImagePart(imageData);
      result = await model.generateContent([prompt, imagePart]);
    } else {
      result = await model.generateContent(prompt);
    }
    const response = await result.response;
    const text = response.text();
    console.log('MODEL ÇIKTISI:', text);
    fs.appendFileSync('model-logs.txt', JSON.stringify({ date: new Date(), type, userEmail, prompt, response: text }) + '\n');
    res.json({
      fortune: text,
      type,
      creditsRemaining: user.credits,
      creditsUsed: creditCost,
      trialUsed: false,
      trialRights: user.trialRights,
      hasImage: hasImageData,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Fortune API error:', error);
    const { userEmail } = req.body;
    // Kredi iadesi veya başka bir işlem gerekirse buraya ekleyebilirsin
    if (error.message.includes('gemini-pro-vision') || error.message.includes('not found')) {
      res.status(500).json({ 
        error: 'Resimli fal desteği mevcut değil. Lütfen sadece metinli fal kullanın.',
        details: 'API anahtarınız Gemini Vision modelini desteklemiyor olabilir.',
        fallback: true
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to generate fortune reading. Please try again.',
        details: error.message 
      });
    }
  }
});

// Add credits endpoint (MongoDB)
app.post('/api/user/:email/add-credits', async (req, res) => {
  try {
    const { email } = req.params;
    const { amount } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.credits += amount || 10;
    await user.save();
    res.json({ 
      message: 'Credits added successfully',
      credits: user.credits
    });
  } catch (error) {
    console.error('Add credits error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Aztro API endpoint yerine Gemini ile burç yorumu
app.post('/api/horoscope', async (req, res) => {
  const { sign, day } = req.body;
  // Türkçe burç isimlerini İngilizceye çevir
  const signMap = {
    koc: 'aries', boga: 'taurus', ikizler: 'gemini', yengec: 'cancer', aslan: 'leo', basak: 'virgo',
    terazi: 'libra', akrep: 'scorpio', yay: 'sagittarius', oglak: 'capricorn', kova: 'aquarius', balik: 'pisces'
  };
  const engSign = signMap[sign.toLowerCase()] || sign;
  try {
    const prompt = `Bugün için ${engSign.charAt(0).toUpperCase() + engSign.slice(1)} burcuna özel kısa, özgün ve pozitif bir günlük burç yorumu hazırla.`;
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    res.json({ horoscope: text });
  } catch (error) {
    res.status(500).json({ error: 'Gemini API hatası', details: error.message });
  }
});

// Korumalı profil endpointi (JWT ile)
app.get('/api/profile', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (error) {
    logger.error('Profile fetch error', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin endpoint: Tüm kullanıcıları ve istatistikleri döndür
app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const users = await User.find({}).select('-password');
    const totalUsers = users.length;
    const totalCredits = users.reduce((sum, user) => sum + user.credits, 0);
    
    res.json({
      users,
      stats: {
        totalUsers,
        totalCredits,
        averageCredits: totalUsers > 0 ? Math.round(totalCredits / totalUsers) : 0
      }
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Falcı endpoint: Kendi müşterilerini görüntüle
app.get('/api/fortune-teller/customers', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.role !== 'fortune_teller') {
      return res.status(403).json({ error: 'Fortune teller access required' });
    }
    
    // Falcının müşterilerini getir (şimdilik tüm kullanıcılar)
    const customers = await User.find({ role: 'user' }).select('-password');
    
    res.json({
      customers,
      stats: {
        totalCustomers: customers.length,
        activeCustomers: customers.filter(c => c.credits > 0).length
      }
    });
  } catch (error) {
    console.error('Fortune teller customers error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug endpoint: Tüm kullanıcıları döndür
app.get('/api/debug/users', async (req, res) => {
  const users = await User.find({});
  res.json(users);
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Passport Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3020/api/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ email: profile.emails[0].value });
    if (!user) {
      user = new User({
        username: profile.displayName,
        email: profile.emails[0].value,
        password: 'google_oauth',
        role: 'user',
        credits: 10,
        trialRights: { tarot: true, coffee: true, zodiac: true, face: true }
      });
      await user.save();
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// Google Auth Routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback', passport.authenticate('google', { session: false, failureRedirect: '/auth?error=google' }), (req, res) => {
  // JWT token oluştur ve frontend'e yönlendir
  const token = jwt.sign({ id: req.user._id, email: req.user.email }, JWT_SECRET, { expiresIn: '7d' });
  // Frontend'e token ile yönlendir (örnek: /auth/social?token=...)
  res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/auth/social?token=${token}`);
});

// 404 handler (en sonda olmalı!)
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.use(xss());
app.use(hpp());

if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}
app.use(mongoSanitize());

// API routes
app.use('/api', require('./routes/api'));

// Sadece production'da frontend'i serve et
if (process.env.NODE_ENV === 'production') {
  const path = require('path');
  app.use(express.static(path.join(__dirname, '../public_html')));
  app.get('*', (req, res) => {
    // Eğer istek /api ile başlıyorsa, next() ile Express route'larına git
    if (req.path.startsWith('/api')) return res.status(404).json({ error: 'API endpoint not found' });
    res.sendFile(path.join(__dirname, '../public_html', 'index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`🚀 Fortune Backend running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔑 Gemini API Key configured: ${process.env.GEMINI_API_KEY ? 'Yes' : 'No'}`);
  console.log(`🖼️  Image support: Enabled (Gemini Vision)`);
}); 