const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

const PORT = process.env.PORT || 3000;
const HTML_PATH = path.join(__dirname, 'public', 'index.html');

/**
 * Injecte les variables d'environnement dans le HTML.
 * Les placeholders dans index.html ressemblent à : __TURNSTILE_SITE_KEY__
 */
function injectEnv(html) {
  const vars = {
    TURNSTILE_SITE_KEY: process.env.TURNSTILE_SITE_KEY || '',
    DISCORD_URL:        process.env.DISCORD_URL        || 'https://discord.com',
  };

  return html.replace(/__([A-Z][A-Z0-9_]+)__/g, (match, key) => {
    if (vars[key] !== undefined) return vars[key];
    console.warn(`[env] Variable manquante dans le template : ${key}`);
    return match;
  });
}

// Health check pour Render
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Sert le HTML avec env vars injectées
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
  console.log(`   TURNSTILE_SITE_KEY : ${process.env.TURNSTILE_SITE_KEY ? '✓ défini' : '✗ MANQUANT'}`);
  console.log(`   DISCORD_URL        : ${process.env.DISCORD_URL ? '✓ défini' : '✗ MANQUANT'}`);
});
