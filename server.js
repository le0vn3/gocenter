const fs = require('fs');
const path = require('path');

/* ============================================================
   Charge les secrets Render (Secret Files ou env vars)
   ============================================================ */
(function loadSecretFile(){
  const ENV_PATH = '/etc/secrets/gocenter.env';
  try {
    if (!fs.existsSync(ENV_PATH)) return;
    const content = fs.readFileSync(ENV_PATH, 'utf8');
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const idx = trimmed.indexOf('=');
      if (idx === -1) return;
      process.env[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
    });
    console.log('✓ Secrets chargés depuis', ENV_PATH);
  } catch (err) {
    console.warn('⚠️  Erreur secrets :', err.message);
  }
})();

const express = require('express');
const app = express();

const PORT = process.env.PORT || 3000;
const HTML_PATH = path.join(__dirname, 'public', 'index.html');

/* ============================================================
   ANTI-DDOS — protection serveur intégrée
   ============================================================ */

// Configuration de la protection
const DDOS_CONFIG = {
  WINDOW_MS: 60000,              // Fenêtre de 1 minute
  MAX_REQUESTS: 50,             // Max 120 requêtes/min par IP
  MAX_CONCURRENT: 4,            // Max 30 connexions simultanées par IP
  BLOCK_DURATION_MS: 900000,     // Blocage 15 min si dépassement
  SUSPICIOUS_UA_PATTERNS: [
    /curl/i, /wget/i, /python-requests/i, /scrapy/i,
    /bot.*spam/i, /masscan/i, /nmap/i, /nikto/i,
    /sqlmap/i, /hydra/i
  ],
  BLOCKED_PATHS: [
    /^\/\.env/, /^\/\.git/, /^\/wp-admin/, /^\/wp-login/,
    /^\/phpmyadmin/, /^\/admin\.php/, /^\/xmlrpc\.php/,
    /^\/\.aws/, /^\/\.ssh/, /^\/backup/, /^\/config/
  ]
};

// Stockage en mémoire
const ipTracker = new Map();    // { ip: { count, firstReq, blockedUntil, concurrent } }
const blockedIPs = new Map();   // { ip: blockedUntil }

// Nettoyage périodique
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of ipTracker) {
    if (now - data.firstReq > DDOS_CONFIG.WINDOW_MS) ipTracker.delete(ip);
  }
  for (const [ip, until] of blockedIPs) {
    if (now > until) blockedIPs.delete(ip);
  }
}, 60000);

// Récupère l'IP réelle du client
function getClientIP(req){
  return (
    req.headers['cf-connecting-ip'] ||  // Cloudflare
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.ip ||
    req.connection?.remoteAddress ||
    'unknown'
  );
}

// Middleware anti-DDoS
function antiDDoS(req, res, next){
  const ip = getClientIP(req);
  const now = Date.now();
  const ua = req.headers['user-agent'] || '';
  const path_ = req.path;

  // 1. IP bloquée ?
  if(blockedIPs.has(ip)){
    const until = blockedIPs.get(ip);
    if(now < until){
      const retry = Math.ceil((until - now) / 1000);
      res.set('Retry-After', String(retry));
      return res.status(429).send(`
        <!DOCTYPE html><html><head><title>429</title></head>
        <body style="background:#000;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:24px">
          <div>
            <h1 style="color:#a78bfa;font-size:28px;margin-bottom:16px">⚠️ Accès temporairement bloqué</h1>
            <p style="color:#a1a1aa">Trop de requêtes. Réessayez dans <strong style="color:#fff">${retry}s</strong>.</p>
          </div>
        </body></html>
      `);
    } else {
      blockedIPs.delete(ip);
    }
  }

  // 2. Chemin suspect (scanner)
  if(DDOS_CONFIG.BLOCKED_PATHS.some(p => p.test(path_))){
    console.warn(`[anti-ddos] Scanner détecté : ${ip} → ${path_}`);
    blockedIPs.set(ip, now + DDOS_CONFIG.BLOCK_DURATION_MS);
    return res.status(403).send('Forbidden');
  }

  // 3. User-Agent suspect
  if(DDOS_CONFIG.SUSPICIOUS_UA_PATTERNS.some(p => p.test(ua))){
    console.warn(`[anti-ddos] UA suspect : ${ip} → ${ua.substring(0, 60)}`);
    blockedIPs.set(ip, now + DDOS_CONFIG.BLOCK_DURATION_MS);
    return res.status(403).send('Forbidden');
  }

  // 4. Rate limiting
  let track = ipTracker.get(ip);
  if(!track || (now - track.firstReq) > DDOS_CONFIG.WINDOW_MS){
    track = { count: 0, firstReq: now, concurrent: 0 };
    ipTracker.set(ip, track);
  }

  track.count++;
  track.concurrent++;

  if(track.count > DDOS_CONFIG.MAX_REQUESTS){
    console.warn(`[anti-ddos] Rate limit dépassé : ${ip} (${track.count} req/min)`);
    blockedIPs.set(ip, now + DDOS_CONFIG.BLOCK_DURATION_MS);
    return res.status(429).send('Too Many Requests');
  }

  if(track.concurrent > DDOS_CONFIG.MAX_CONCURRENT){
    console.warn(`[anti-ddos] Connexions simultanées : ${ip}`);
    return res.status(429).send('Too many concurrent connections');
  }

  // 5. Délai progressif si proche de la limite
  const ratio = track.count / DDOS_CONFIG.MAX_REQUESTS;
  if(ratio > 0.7){
    const delay = Math.floor((ratio - 0.7) * 1000);
    setTimeout(() => {
      track.concurrent--;
      next();
    }, delay);
    return;
  }

  // 6. Décrément après réponse
  res.on('finish', () => { track.concurrent--; });
  res.on('close', () => { track.concurrent--; });

  next();
}

app.use(antiDDoS);

/* ============================================================
   Headers de sécurité
   ============================================================ */
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'SAMEORIGIN');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.set('X-XSS-Protection', '1; mode=block');
  next();
});

/* ============================================================
   Injection des env vars
   ============================================================ */
function injectEnv(html){
  const vars = {
    TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY || '',
    DISCORD_URL:        process.env.DISCORD_URL        || 'https://discord.com'
  };
  return html.replace(/__([A-Z][A-Z0-9_]+)__/g, (match, key) => {
    if(vars[key] !== undefined) return vars[key];
    console.warn(`[env] Variable manquante : ${key}`);
    return match;
  });
}

app.use(express.json({ limit: '4kb' }));

/* ============================================================
   Routes
   ============================================================ */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    ts: Date.now(),
    ips: ipTracker.size,
    blocked: blockedIPs.size
  });
});

app.post('/api/verify', async (req, res) => {
  const { token } = req.body;
  if(!token) return res.status(400).json({ ok: false, error: 'no_token' });

  const secret = process.env.TURNSTILE_SECRET_KEY;
  if(!secret){
    console.error('[verify] TURNSTILE_SECRET_KEY manquante');
    return res.status(500).json({ ok: false, error: 'server_misconfigured' });
  }

  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret,
        response: token,
        remoteip: getClientIP(req)
      })
    });
    const data = await r.json();
    console.log('[verify]', data.success ? '✓ valid' : '✗ invalid');
    return res.json({ ok: data.success, data });
  } catch (e) {
    console.error('[verify]', e.message);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.get('*', (req, res) => {
  try {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.send(injectEnv(html));
  } catch (err) {
    console.error('[error]', err);
    res.status(500).send('Erreur serveur');
  }
});

/* ============================================================
   Démarrage
   ============================================================ */
app.listen(PORT, () => {
  console.log(`🚀 GO CENTER démarré sur le port ${PORT}`);
  console.log(`   TURNSTILE_SITE_KEY   : ${process.env.TURNSTILE_SITE_KEY   ? '✓' : '✗ MANQUANT'}`);
  console.log(`   TURNSTILE_SECRET_KEY : ${process.env.TURNSTILE_SECRET_KEY ? '✓' : '✗ MANQUANT'}`);
  console.log(`   DISCORD_URL          : ${process.env.DISCORD_URL          ? '✓' : '✗ MANQUANT'}`);
  console.log(`   Anti-DDoS            : ✓ actif (${DDOS_CONFIG.MAX_REQUESTS} req/min max)`);
});
