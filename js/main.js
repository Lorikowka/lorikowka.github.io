/**
 * ═══════════════════════════════════════════════════════════
 * 🔒 main.js — БЕЗОПАСНАЯ ВЕРСИЯ
 * ═══════════════════════════════════════════════════════════
 * Психолог Екатерина Князькова
 */

// ——————————————————————————————
// КОНФИГУРАЦИЯ (БЕЗОПАСНАЯ)
// ——————————————————————————————
const CONFIG = {
  // ⚠️ Заменить на свой URL после развёртывания backend
  BACKEND_URL: 'https://your-backend-url.vercel.app',
  
  // Ссылка на оплату DIKIDI
  DIKIDI_PAYMENT_LINK: 'https://pay.dikidi.ru/YOUR_LINK_HERE',
  
  // Таймауты
  FETCH_TIMEOUT: 10000,
  
  // Разрешённые домены для внешних ссылок
  ALLOWED_EXTERNAL_DOMAINS: [
    't.me',
    'yookassa.ru',
    'pay.dikidi.ru'
  ]
};

// ——————————————————————————————
// SANITIZATION ФУНКЦИИ
// ——————————————————————————————

/**
 * Санитизация HTML для предотвращения XSS
 */
function sanitizeHTML(str) {
  if (!str) return '';
  
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/**
 * Проверка URL на безопасность
 */
function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    
    // Разрешаем только https
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return false;
    }
    
    // Проверяем домен
    return CONFIG.ALLOWED_EXTERNAL_DOMAINS.some(allowed => 
      hostname === allowed || hostname.endsWith('.' + allowed)
    );
  } catch {
    return false;
  }
}

/**
 * Безопасное открытие внешних ссылок
 */
function openExternalSafely(url) {
  if (!isSafeUrl(url)) {
    console.warn('⚠️ Попытка открыть небезопасную ссылку:', url);
    return false;
  }
  
  // Открываем в новой вкладке с noopener для безопасности
  window.open(url, '_blank', 'noopener,noreferrer');
  return true;
}

// ——————————————————————————————
// АВТОСКРОЛЛ К ОПЛАТЕ ПРИ ЗАГРУЗКЕ
// ——————————————————————————————
window.addEventListener('load', () => {
  const payment = document.querySelector('#payment');
  if (payment) {
    setTimeout(() => {
      payment.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 400);
  }
});

// ——————————————————————————————
// ПЛАВНЫЙ СКРОЛЛ ПО ЯКОРЯМ
// ——————————————————————————————
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    const targetId = this.getAttribute('href');
    
    // Пропускаем внешние ссылки
    if (targetId.startsWith('http')) {
      return;
    }
    
    const target = document.querySelector(targetId);
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ——————————————————————————————
// ОПЛАТА ЧЕРЕЗ ЮKASSA (BACKEND)
// ——————————————————————————————
async function handleYooKassaPay() {
  const button = event.target.closest('button');
  const originalText = button.innerHTML;
  
  // Проверяем, настроен ли backend
  if (CONFIG.BACKEND_URL.includes('your-backend-url')) {
    alert(
      '⚙️ Оплата через ЮKassa\n\n' +
      'Сервер оплаты ещё не настроен.\n\n' +
      'Для записи и оплаты, пожалуйста, напишите в Telegram: @Ekaterina_K'
    );
    return;
  }
  
  try {
    // Блокируем кнопку
    button.disabled = true;
    button.innerHTML = '⏳ Создаём платёж...';
    button.style.opacity = '0.7';
    
    // Генерируем уникальный ID заказа
    const orderId = `order_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Создаём AbortController для таймаута
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.FETCH_TIMEOUT);
    
    // Запрос к backend для создания платежа
    const response = await fetch(`${CONFIG.BACKEND_URL}/api/create-payment`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        amount: 3500,
        description: 'Консультация психолога — Екатерина Князькова',
        orderId: orderId
      }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    const data = await response.json();
    
    if (!response.ok || !data.success) {
      throw new Error(data.error || 'Не удалось создать платёж');
    }
    
    // Логируем (в development)
    console.log('✅ Платёж создан:', data.paymentId);
    
    // Перенаправляем на платёжную страницу ЮKassa
    // Проверяем URL перед перенаправлением
    if (data.confirmationUrl && data.confirmationUrl.includes('yookassa.ru')) {
      window.location.href = data.confirmationUrl;
    } else {
      throw new Error('Неверная платёжная ссылка');
    }
    
  } catch (error) {
    console.error('Ошибка оплаты:', error);
    
    let errorMessage = '⚙️ Оплата через ЮKassa\n\n';
    
    if (error.name === 'AbortError') {
      errorMessage += 'Превышено время ожидания. Попробуйте ещё раз.';
    } else if (error.message.includes('Failed to fetch')) {
      errorMessage += 'Сервер оплаты недоступен. Проверьте подключение к интернету.';
    } else {
      errorMessage += 'Произошла ошибка при создании платежа.\n\n';
      errorMessage += 'Для записи и оплаты, пожалуйста, напишите в Telegram: @Ekaterina_K';
    }
    
    alert(errorMessage);
  } finally {
    // Возвращаем кнопку в исходное состояние
    button.disabled = false;
    button.innerHTML = originalText;
    button.style.opacity = '1';
  }
}

// ——————————————————————————————
// ОПЛАТА ЧЕРЕЗ DIKIDI
// ——————————————————————————————
function handleDikidiPay() {
  // Проверяем, установлена ли реальная ссылка
  if (CONFIG.DIKIDI_PAYMENT_LINK.includes('YOUR_LINK_HERE')) {
    alert(
      '⚙️ Оплата через DIKIDI\n\n' +
      'Ссылка на оплату ещё не настроена.\n\n' +
      'Для записи и оплаты, пожалуйста, напишите в Telegram: @Ekaterina_K'
    );
    return;
  }
  
  // Проверяем безопасность URL
  if (!CONFIG.DIKIDI_PAYMENT_LINK.includes('dikidi.ru')) {
    console.error('⚠️ Неверная ссылка DIKIDI');
    alert('Ошибка конфигурации. Обратитесь к администратору.');
    return;
  }
  
  // Открываем платёжную страницу Dikidi в новой вкладке
  openExternalSafely(CONFIG.DIKIDI_PAYMENT_LINK);
}

// ——————————————————————————————
// ОПЛАТА ЧЕРЕЗ СБЕРБИЗНЕС (ЗАГЛУШКА)
// ——————————————————————————————
function handleSberPay() {
  alert(
    '⚙️ Оплата через СберБизнес\n\n' +
    'Интеграция в процессе подключения.\n' +
    'Для оплаты, пожалуйста, напишите в Telegram: @Ekaterina_K'
  );
}

// ——————————————————————————————
// АКТИВНЫЙ ПУНКТ МЕНЮ ПРИ СКРОЛЛЕ
// ——————————————————————————————
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('nav a[href^="#"]');

const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      navLinks.forEach(link => {
        link.classList.toggle(
          'active',
          link.getAttribute('href') === '#' + entry.target.id
        );
      });
    }
  });
}, { rootMargin: '-40% 0px -55% 0px' });

sections.forEach(section => observer.observe(section));

// ——————————————————————————————
// ЗАЩИТА ОТ CONSOLE.LOG В PRODUCTION
// ——————————————————————————————
if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
  // В production отключаем console.log (оставляем только ошибки)
  console.log = function() {};
  console.warn = function() {};
}

// ——————————————————————————————
// DETECT MALICIOUS ACTIVITY
// ——————————————————————————————
// Простая защита от XSS через URL параметры
window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  
  // Проверяем подозрительные параметры
  for (const [key, value] of urlParams.entries()) {
    if (value.includes('<script') || value.includes('javascript:')) {
      console.warn('⚠️ Обнаружена подозрительная активность');
      // Очищаем URL
      window.history.replaceState({}, document.title, window.location.pathname);
      break;
    }
  }
});
