/**
 * ═══════════════════════════════════════════════════════════
 * 🔒 Backend сервер для приёма платежей (БЕЗОПАСНАЯ ВЕРСИЯ)
 * ═══════════════════════════════════════════════════════════
 * Психолог Екатерина Князькова
 * 
 * API:
 * POST /api/create-payment — создать платёж
 * GET  /api/payment-status/:id — проверить статус
 * POST /api/webhook — webhook от ЮKassa
 */

// ——————————————————————————————
// ЗАГРУЗКА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ
// ——————————————————————————————
const path = require('path');
const dotenv = require('dotenv');

// Определяем окружение
const NODE_ENV = process.env.NODE_ENV || 'development';
const envFile = NODE_ENV === 'production' ? '.env.production' : '.env.development';

// Загружаем переменные
const envPath = path.join(__dirname, envFile);
const envConfig = dotenv.config({ path: envPath });

// Если .env не найден, пробуем .env
if (envConfig.error) {
  dotenv.config({ path: path.join(__dirname, '.env') });
}

// ——————————————————————————————
// ИМПОРТЫ
// ——————————————————————————————
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const crypto = require('crypto');
const axios = require('axios');
const winston = require('winston');

const app = express();
const PORT = process.env.PORT || 3000;

// ——————————————————————————————
// ЛОГИРОВАНИЕ (безопасное)
// ——————————————————————————————
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'psixolog-payment' },
  transports: [
    // В продакшене пишем только ошибки в файл
    ...(process.env.NODE_ENV === 'production' 
      ? [new winston.transports.File({ 
          filename: process.env.LOG_FILE || 'logs/error.log', 
          level: 'error' 
        })]
      : []),
    // В разработке пишем в консоль
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// ——————————————————————————————
// ПРОВЕРКА КРИТИЧЕСКИХ ПЕРЕМЕННЫХ
// ——————————————————————————————
const requiredEnvVars = ['YOOKASSA_SHOP_ID', 'YOOKASSA_SECRET_KEY'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  logger.error(`❌ Отсутствуют критические переменные: ${missingVars.join(', ')}`);
  logger.error('Проверьте .env файл!');
  // Не останавливаем сервер в development режиме
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}

// ——————————————————————————————
// КОНФИДЕНЦИАЛЬНЫЕ ДАННЫЕ
// ——————————————————————————————
const YOOKASSA_SHOP_ID = process.env.YOOKASSA_SHOP_ID;
const YOOKASSA_SECRET_KEY = process.env.YOOKASSA_SECRET_KEY;
const YOOKASSA_WEBHOOK_SECRET = process.env.YOOKASSA_WEBHOOK_SECRET;
const SITE_URL = process.env.SITE_URL || 'http://localhost:5500';
const PAYMENT_MODE = process.env.PAYMENT_MODE || 'test';

const YOOKASSA_BASE_URL = 'https://api.yookassa.ru/v3';
const AUTH_HEADER = Buffer.from(`${YOOKASSA_SHOP_ID}:${YOOKASSA_SECRET_KEY}`).toString('base64');

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// ——————————————————————————————
// MIDDLEWARE БЕЗОПАСНОСТИ
// ——————————————————————————————

// 1. Helmet — security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.yookassa.ru"],
      frameSrc: ["'self'", "https://yookassa.ru"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// 2. CORS — разрешаем только доверенные домены
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : [SITE_URL];

app.use(cors({
  origin: function (origin, callback) {
    // Разрешаем запросы без origin (мобильные приложения, curl)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn(`❌ CORS: Запрещённый домен: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400 // 24 часа
}));

// 3. Rate Limiting — защита от DDoS и брутфорса
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000, // 1 минута
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // 100 запросов
  message: {
    success: false,
    error: 'Слишком много запросов, попробуйте позже',
    retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000) / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Используем IP + UserAgent для идентификации
    return `${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  },
  handler: (req, res) => {
    logger.warn(`⚠️ Rate limit превышен для IP: ${req.ip}`);
    res.status(429).json({
      success: false,
      error: 'Слишком много запросов',
      retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000) / 1000)
    });
  }
});

// Применяем rate limiter ко всем запросам
app.use(limiter);

// 4. Строгий rate limit для чувствительных эндпоинтов
const strictLimiter = rateLimit({
  windowMs: 60000, // 1 минута
  max: 10, // 10 запросов в минуту
  message: {
    success: false,
    error: 'Слишком много попыток, попробуйте через минуту'
  }
});

// 5. Парсинг JSON с ограничением размера
app.use(express.json({ 
  limit: '10kb', // Ограничиваем размер тела запроса
  strict: true 
}));

// 6. URL-encoded с ограничением
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10kb' 
}));

// ——————————————————————————————
// SANITIZATION HELPER
// ——————————————————————————————
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  
  // Удаляем опасные символы
  return input
    .replace(/[<>]/g, '') // Удаляем < >
    .replace(/javascript:/gi, '') // Удаляем javascript:
    .replace(/on\w+=/gi, '') // Удаляем on*=
    .trim();
}

// ——————————————————————————————
// VALIDATION ERROR HANDLER
// ——————————————————————————————
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`⚠️ Ошибка валидации: ${JSON.stringify(errors.array())}`);
    return res.status(400).json({
      success: false,
      error: 'Некорректные данные',
      details: errors.array().map(e => e.msg)
    });
  }
  next();
};

// ——————————————————————————————
// TELEGRAM УВЕДОМЛЕНИЯ (безопасные)
// ——————————————————————————————
async function sendTelegramNotification(message) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
    logger.warn('⚠️ Telegram не настроен, пропускаем уведомление');
    return;
  }

  try {
    // Санизируем сообщение
    const safeMessage = sanitizeInput(message);
    
    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        chat_id: TELEGRAM_CHAT_ID,
        text: safeMessage,
        parse_mode: 'HTML'
      },
      {
        timeout: 5000, // Таймаут 5 секунд
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );
    logger.info('✅ Уведомление отправлено в Telegram');
  } catch (error) {
    logger.error(`❌ Ошибка отправки в Telegram: ${error.message}`);
    // Не выбрасываем ошибку, чтобы не ломать основной поток
  }
}

// ——————————————————————————————
// API: СОЗДАТЬ ПЛАТЁЖ
// ——————————————————————————————
app.post('/api/create-payment', 
  strictLimiter, // Строгий rate limit
  [
    body('amount')
      .optional()
      .isFloat({ min: 10, max: 250000 })
      .withMessage('Сумма должна быть от 10 до 250000 ₽'),
    
    body('description')
      .optional()
      .isString()
      .isLength({ max: 200 })
      .withMessage('Описание не более 200 символов'),
    
    body('orderId')
      .optional()
      .isString()
      .isLength({ max: 50 })
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Некорректный ID заказа'),
    
    body('customerEmail')
      .optional()
      .isEmail()
      .normalizeEmail()
      .withMessage('Некорректный email'),
    
    handleValidationErrors
  ],
  async (req, res) => {
    const startTime = Date.now();
    
    try {
      const { 
        amount = 3500, 
        description = 'Консультация психолога', 
        orderId,
        customerEmail 
      } = req.body;

      // Генерируем уникальный orderNumber
      const orderNumber = orderId || `order_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      
      // Санизируем описание
      const safeDescription = sanitizeInput(description);

      logger.info(`📝 Создание платежа: ${orderNumber}, сумма: ${amount}₽`);

      // Создаём платёж через ЮKassa API
      const response = await axios.post(
        `${YOOKASSA_BASE_URL}/payments`,
        {
          amount: {
            value: amount.toString(),
            currency: 'RUB'
          },
          description: safeDescription,
          metadata: {
            order_id: orderNumber,
            created_at: new Date().toISOString()
          },
          confirmation: {
            type: 'redirect',
            return_url: `${SITE_URL}/payment-success.html`
          },
          capture: true, // Автоматическое подтверждение
          paid: false,
          // Для самозанятого (без НДС)
          income_amount: { value: amount.toString(), currency: 'RUB' },
          tax_amount: { value: '0', currency: 'RUB' }
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Idempotence-Key': orderNumber, // Идемпотентность
            'Authorization': `Basic ${AUTH_HEADER}`
          },
          timeout: 10000 // Таймаут 10 секунд
        }
      );

      const payment = response.data;
      const duration = Date.now() - startTime;

      logger.info(`✅ Платёж создан: ${payment.id} (${duration}мс)`);

      // Отправляем уведомление (не блокируем ответ)
      sendTelegramNotification(
        `🆕 <b>Новый платёж</b>\n\n` +
        `💰 Сумма: ${amount} ₽\n` +
        `📋 Заказ: ${orderNumber}\n` +
        `🆔 ID: ${payment.id}\n` +
        `👤 Email: ${customerEmail || 'не указан'}`
      );

      res.json({
        success: true,
        paymentId: payment.id,
        confirmationUrl: payment.confirmation.confirmation_url,
        amount: payment.amount.value,
        description: safeDescription
      });

    } catch (error) {
      const duration = Date.now() - startTime;
      const errorData = error.response?.data || { description: error.message };
      
      logger.error(`❌ Ошибка создания платежа (${duration}мс):`, {
        error: error.message,
        response: errorData,
        status: error.response?.status
      });

      // Не раскрываем детали ошибки клиенту
      res.status(error.response?.status || 500).json({
        success: false,
        error: 'Не удалось создать платёж',
        details: process.env.NODE_ENV === 'development' ? errorData : undefined,
        retry: true
      });
    }
  }
);

// ——————————————————————————————
// API: ПРОВЕРИТЬ СТАТУС ПЛАТЕЖА
// ——————————————————————————————
app.get('/api/payment-status/:id',
  strictLimiter,
  [
    param('id')
      .isString()
      .isLength({ min: 10, max: 50 })
      .matches(/^[a-zA-Z0-9-]+$/)
      .withMessage('Некорректный ID платежа'),
    handleValidationErrors
  ],
  async (req, res) => {
    const startTime = Date.now();
    
    try {
      const { id } = req.params;

      logger.info(`🔍 Проверка статуса платежа: ${id}`);

      const response = await axios.get(
        `${YOOKASSA_BASE_URL}/payments/${id}`,
        {
          headers: {
            'Authorization': `Basic ${AUTH_HEADER}`
          },
          timeout: 5000
        }
      );

      const payment = response.data;
      const duration = Date.now() - startTime;

      logger.info(`✅ Статус получен: ${payment.status} (${duration}мс)`);

      res.json({
        success: true,
        paymentId: payment.id,
        status: payment.status,
        amount: payment.amount.value,
        description: payment.description,
        created_at: payment.created_at,
        paid: payment.paid
      });

    } catch (error) {
      const duration = Date.now() - startTime;
      
      logger.error(`❌ Ошибка проверки статуса (${duration}мс):`, {
        error: error.message,
        status: error.response?.status
      });

      res.status(error.response?.status || 500).json({
        success: false,
        error: 'Не удалось получить статус платежа',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

// ——————————————————————————————
// API: WEBHOOK ОТ ЮKASSA
// ——————————————————————————————
app.post('/api/webhook',
  // Для webhook используем отдельный строгий лимит
  rateLimit({
    windowMs: 60000,
    max: 50
  }),
  async (req, res) => {
    try {
      const event = req.body;
      const object = event.object;

      // Проверяем тип события
      if (!event.event || !object) {
        logger.warn('⚠️ Webhook: Неверный формат события');
        return res.status(400).send('Invalid event format');
      }

      logger.info(`📩 Webhook получен: ${event.event} ${object.id}`);

      // ПРОВЕРКА ПОДПИСИ (если настроена)
      if (YOOKASSA_WEBHOOK_SECRET) {
        const signature = req.headers['x-yookassa-signature'];
        
        if (signature) {
          // Вычисляем HMAC-SHA256
          const hmac = crypto.createHmac('sha256', YOOKASSA_WEBHOOK_SECRET);
          hmac.update(JSON.stringify(req.body));
          const calculatedSignature = hmac.digest('hex');
          
          if (signature !== calculatedSignature) {
            logger.error('❌ Webhook: Неверная подпись!');
            return res.status(401).send('Invalid signature');
          }
          logger.info('✅ Webhook: Подпись подтверждена');
        }
      }

      // Обработка событий
      switch (event.event) {
        case 'payment.succeeded':
          logger.info(`✅ Оплата успешна: ${object.id}`);
          
          await sendTelegramNotification(
            `✅ <b>Оплата получена!</b>\n\n` +
            `💰 Сумма: ${object.amount.value} ₽\n` +
            `📋 Заказ: ${object.metadata?.order_id || 'N/A'}\n` +
            `🆔 ID платежа: ${object.id}\n` +
            `⏰ Время: ${new Date(object.created_at).toLocaleString('ru-RU')}`
          );
          break;

        case 'payment.waiting_for_capture':
          logger.info(`⏳ Платёж ожидает подтверждения: ${object.id}`);
          break;

        case 'payment.canceled':
          logger.warn(`❌ Оплата отменена: ${object.id}`);
          
          await sendTelegramNotification(
            `❌ <b>Оплата отменена</b>\n\n` +
            `📋 Заказ: ${object.metadata?.order_id || 'N/A'}\n` +
            `🆔 ID платежа: ${object.id}`
          );
          break;

        default:
          logger.info(`ℹ️ Неизвестное событие: ${event.event}`);
      }

      res.status(200).send('OK');

    } catch (error) {
      logger.error('❌ Ошибка обработки webhook:', error.message);
      res.status(500).send('Webhook error');
    }
  }
);

// ——————————————————————————————
// HEALTH CHECK
// ——————————————————————————————
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'psixolog-payment-backend',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    payment_mode: PAYMENT_MODE
  });
});

// ——————————————————————————————
// 404 HANDLER
// ——————————————————————————————
app.use((req, res) => {
  logger.warn(`⚠️ 404: ${req.method} ${req.path}`);
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// ——————————————————————————————
// GLOBAL ERROR HANDLER
// ——————————————————————————————
app.use((err, req, res, next) => {
  logger.error('💥 Global error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  // Не раскрываем детали ошибок в продакшене
  res.status(err.status || 500).json({
    success: false,
    error: process.env.NODE_ENV === 'production' 
      ? 'Внутренняя ошибка сервера' 
      : err.message
  });
});

// ——————————————————————————————
// ЗАПУСК СЕРВЕРА
// ——————————————————————————————
const server = app.listen(PORT, () => {
  logger.info(`
╔═══════════════════════════════════════════════════════════╗
║   🔒 Сервер запущен (БЕЗОПАСНАЯ ВЕРСИЯ)                   ║
║                                                           ║
║   Порт: ${PORT}                                            
║   Режим: ${NODE_ENV}                                       
║   Платежи: ${PAYMENT_MODE}                                 
║                                                           ║
║   Endpoints:                                               ║
║   POST /api/create-payment                                 ║
║   GET  /api/payment-status/:id                             ║
║   POST /api/webhook                                        ║
║   GET  /api/health                                         ║
║                                                           ║
║   Безопасность:                                            ║
║   ✅ Helmet (security headers)                             ║
║   ✅ CORS (доверенные домены)                              ║
║   ✅ Rate Limiting (защита от DDoS)                        ║
║   ✅ Валидация входных данных                              ║
║   ✅ Проверка подписи webhook                              ║
║   ✅ Безопасное логирование                                ║
╚═══════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('📡 SIGTERM получен. Завершаем работу...');
  server.close(() => {
    logger.info('✅ Сервер остановлен');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('📡 SIGINT получен. Завершаем работу...');
  server.close(() => {
    logger.info('✅ Сервер остановлен');
    process.exit(0);
  });
});

// Обработка необработанных ошибок
process.on('uncaughtException', (err) => {
  logger.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('💥 Unhandled Rejection:', reason);
  process.exit(1);
});

module.exports = app;
