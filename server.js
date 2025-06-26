const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config({ path: './config.env' });
const fs = require('fs');

const app = express();
app.set('trust proxy', 1); // Render ve benzeri platformlar için gerekli
const PORT = process.env.PORT || 3020;

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

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// In-memory user storage (production'da database kullanın)
const users = new Map();
const userCredits = new Map();

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

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user already exists
    if (users.has(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Create user (in production, password should be hashed)
    const user = {
      id: Date.now().toString(),
      username,
      email,
      password, // In production, hash this
      credits: 10, // Free credits
      createdAt: new Date(),
      trialRights: {
        tarot: true,
        coffee: true,
        zodiac: true,
        face: true
      }
    };
    
    users.set(email, user);
    userCredits.set(email, 10);
    
    res.status(201).json({ 
      message: 'User registered successfully',
      user: { id: user.id, username, email, credits: user.credits, trialRights: user.trialRights }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = users.get(email);
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    res.json({ 
      message: 'Login successful',
      user: { 
        id: user.id, 
        username: user.username, 
        email: user.email, 
        credits: userCredits.get(email) || 0,
        trialRights: user.trialRights
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user credits
app.get('/api/user/:email/credits', (req, res) => {
  try {
    const { email } = req.params;
    const credits = userCredits.get(email) || 0;
    const user = users.get(email);
    res.json({ 
      credits,
      trialRights: user ? user.trialRights : null
    });
  } catch (error) {
    console.error('Get credits error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Fortune telling endpoint with image support
app.post('/api/fortune', checkApiKey, async (req, res) => {
  try {
    const { type, userEmail, question, birthDate, zodiacSign, imageData } = req.body;
    
    if (!userEmail) {
      return res.status(400).json({ error: 'User email is required' });
    }
    
    const user = users.get(userEmail);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Fal türüne göre promptu PHP örneğindeki gibi oluştur
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
    // Kullanıcıdan gelen soruyu veya ek veriyi prompta ekle
    if (question) prompt += `\nSoru: ${question}`;
    if (birthDate) prompt += `\nDoğum tarihi: ${birthDate}`;
    if (zodiacSign) prompt += `\nBurç: ${zodiacSign}`;

    // Resim var mı kontrol et
    const hasImageData = hasImage(imageData);
    
    // Model seçimi - resim varsa vision modeli kullan
    const modelName = "gemini-1.5-flash";
    const model = genAI.getGenerativeModel({ model: modelName });

    // Log: Modele giden prompt ve görsel bilgisi
    console.log('MODELE GİDEN PROMPT:', prompt);
    if (hasImageData) {
      console.log('GÖNDERİLEN RESİM VAR (base64 uzunluğu):', imageData.length);
    }
    fs.appendFileSync('model-logs.txt', JSON.stringify({ date: new Date(), type, userEmail, prompt, hasImageData, imageLength: imageData ? imageData.length : 0 }) + '\n');

    // Önce deneme hakkı kontrolü
    if (user.trialRights && user.trialRights[type]) {
      user.trialRights[type] = false; // Hakkı tüket
      
      let result;
      if (hasImageData) {
        // Resimli fal için
        const imagePart = createImagePart(imageData);
        result = await model.generateContent([prompt, imagePart]);
      } else {
        // Metinli fal için
        result = await model.generateContent(prompt);
      }
      
      const response = await result.response;
      const text = response.text();
      // Log: Modelden dönen yanıt
      console.log('MODEL ÇIKTISI:', text);
      fs.appendFileSync('model-logs.txt', JSON.stringify({ date: new Date(), type, userEmail, prompt, response: text }) + '\n');
      
      res.json({
        fortune: text,
        type,
        creditsRemaining: userCredits.get(userEmail),
        trialUsed: true,
        trialRights: user.trialRights,
        hasImage: hasImageData,
        timestamp: new Date().toISOString()
      });
      return;
    }

    // Deneme hakkı yoksa kredi kontrolü
    const currentCredits = userCredits.get(userEmail) || 0;
    if (currentCredits <= 0) {
      return res.status(402).json({ error: 'Insufficient credits' });
    }
    
    userCredits.set(userEmail, currentCredits - 1);
    
    let result;
    if (hasImageData) {
      // Resimli fal için
      const imagePart = createImagePart(imageData);
      result = await model.generateContent([prompt, imagePart]);
    } else {
      // Metinli fal için
      result = await model.generateContent(prompt);
    }
    
    const response = await result.response;
    const text = response.text();
    // Log: Modelden dönen yanıt
    console.log('MODEL ÇIKTISI:', text);
    fs.appendFileSync('model-logs.txt', JSON.stringify({ date: new Date(), type, userEmail, prompt, response: text }) + '\n');
    
    res.json({
      fortune: text,
      type,
      creditsRemaining: userCredits.get(userEmail),
      trialUsed: false,
      trialRights: user.trialRights,
      hasImage: hasImageData,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Fortune API error:', error);
    const { userEmail } = req.body;
    if (userEmail) {
      const currentCredits = userCredits.get(userEmail) || 0;
      userCredits.set(userEmail, currentCredits + 1);
    }
    
    // Gemini Vision model hatası kontrolü
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

// Add credits endpoint (for testing)
app.post('/api/user/:email/add-credits', (req, res) => {
  try {
    const { email } = req.params;
    const { amount } = req.body;
    
    const currentCredits = userCredits.get(email) || 0;
    userCredits.set(email, currentCredits + (amount || 10));
    
    res.json({ 
      message: 'Credits added successfully',
      credits: userCredits.get(email)
    });
  } catch (error) {
    console.error('Add credits error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 Fortune Backend running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔑 Gemini API Key configured: ${process.env.GEMINI_API_KEY ? 'Yes' : 'No'}`);
  console.log(`🖼️  Image support: Enabled (Gemini Vision)`);
}); 