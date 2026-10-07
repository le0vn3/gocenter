const fs = require('fs');
const path = require('path');

/* ============================================================
   Charge les secrets depuis /etc/secrets/gocenter.env (Render Secret Files)
   OU utilise les env vars classiques si le fichier n'existe pas.
   ============================================================ */
(function loadSecretFile(){
  const ENV_PATH = '/etc/secrets/gocenter.env';
  try {
    if (!fs.existsSync(ENV_PATH)) {
      console.log('ℹ️  Pas de fichier secret Render — utilisation des env vars classiques');
      return;
    }
    const content = fs.readFileSync(ENV_PATH, 'utf8');
    content.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const idx = trimmed.indexOf('=');
      if (idx === -1) return;
      const key = trimmed.slice(0, idx).trim();
      const value = trimmed.slice(idx + 1).trim();
      if (key) process.env[key] = value;
    });
    console.log('✓ Secrets chargés depuis', ENV_PATH);
  } catch (err) {
    console.warn('⚠️  Erreur chargement secrets :', err.message);
  }
})();

const express = require('express');
const app = express();

const PORT = process.env.PORT || 3000;
const HTML_PATH = path.join(__dirname, 'public', 'index.html');

/* ============================================================
   Injection des variables d'environnement dans le HTML
   ============================================================ */
function injectEnv(html) {
  const vars = {
    TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY || '',
    DISCORD_URL:        process.env.DISCORD_URL        || 'https://discord.com'
  };

  return html.replace(/__([A-Z][A-Z0-9_]+)__/g, (match, key) => {
    if (vars[key] !== undefined) return vars[key];
    console.warn(`[env] Variable manquante dans le template : ${key}`);
    return match;
  });
}

app.use(express.json());

/* ============================================================
   Health check (utile pour Render)
   ============================================================ */
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

/* ============================================================
   Validation serveur du token Turnstile
   ============================================================ */
app.post('/api/verify', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ ok: false, error: 'no_token' });

  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
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
        remoteip: req.ip
      })
    });
    const data = await r.json();
    console.log('[verify]', data.success ? '✓ valid' : '✗ invalid', data['error-codes'] || '');
    return res.json({ ok: data.success, data });
  } catch (e) {
    console.error('[verify] erreur fetch :', e.message);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/* ============================================================
   Sert le HTML avec env vars injectées
   ============================================================ */
app.get('*', (req, res) => {
  try {
    const html = fs.readFileSync(HTML_PATH, 'utf8');
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'SAMEORIGIN');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.send(injectEnv(html));
  } catch (err) {
    console.error('[error]', err);
    res.status(500).send('Erreur serveur');
  }
});

app.listen(PORT, () => {
  console.log(`🚀 GO CENTER démarré sur le port ${PORT}`);
  console.log(`   TURNSTILE_SITE_KEY   : ${process.env.TURNSTILE_SITE_KEY   ? '✓ défini' : '✗ MANQUANT'}`);
  console.log(`   TURNSTILE_SECRET_KEY : ${process.env.TURNSTILE_SECRET_KEY ? '✓ défini' : '✗ MANQUANT'}`);
  console.log(`   DISCORD_URL          : ${process.env.DISCORD_URL          ? '✓ défini' : '✗ MANQUANT'}`);
});
