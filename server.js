require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileP = promisify(execFile);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIG
// ============================================================
const COMFY_URL = (process.env.COMFY_URL || '').replace(/\/$/, '');
const FFMPEG = process.env.FFMPEG_PATH || 'ffmpeg';
const FFPROBE = process.env.FFPROBE_PATH || 'ffprobe';
const WARMUP_TIMEOUT_MS = 7 * 60 * 1000;

// LongCat workflow: 1st segment ≈ 5.81s, then +5.0s/segment; the graph exposes
// 1/2/3-segment outputs on these node ids.
const SEG_SECONDS = [5.81, 10.81, 15.81];
const SEG_OUTPUT_NODE = ['320', '386', '453'];

const DEFAULT_PROMPT =
  "The person speaks calmly and naturally to the camera. Static locked-off camera, " +
  "fixed framing, no camera movement, no zoom, no pan; the subject stays centered in the " +
  "exact same position and framing as the input photo. Plain static background, consistent " +
  "lighting and identity. Only the mouth and subtle natural facial expressions move — " +
  "no head turning, no body movement. Sharp focus, high detail, photorealistic.";

// ============================================================
// AUTH — same Google OAuth + allowlist pattern as Avalution
// ============================================================
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const ALLOWED_EMAILS = new Set(
  (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
);
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const SESSION_SECRET = (process.env.SESSION_SECRET || '').trim() || crypto.randomBytes(48).toString('base64url');
const AUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && ALLOWED_EMAILS.size > 0);

console.log(AUTH_ENABLED
  ? `[auth] Google OAuth enabled, allowlist: ${[...ALLOWED_EMAILS].join(', ')}`
  : '[auth] DISABLED (dev mode — set GOOGLE_CLIENT_ID/SECRET/ALLOWED_EMAILS)');
console.log(`[comfy] target: ${COMFY_URL || '(unset!)'}`);

if (PUBLIC_URL.startsWith('https://')) app.set('trust proxy', 1);

app.use(session({
  secret: SESSION_SECRET,
  name: 'studio_session',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: PUBLIC_URL.startsWith('https://'),
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 14 * 24 * 60 * 60 * 1000,
  },
}));

const PUBLIC_PREFIXES = ['/auth/', '/login.html'];
const PUBLIC_EXACT = new Set(['/api/me', '/favicon.ico']);
const isPublicPath = p => PUBLIC_EXACT.has(p) || PUBLIC_PREFIXES.some(pre => p.startsWith(pre));

app.use((req, res, next) => {
  if (!AUTH_ENABLED) return next();
  if (isPublicPath(req.path)) return next();
  const email = req.session?.user_email;
  const authorized = email && ALLOWED_EMAILS.has(email);
  if (req.path.startsWith('/api/')) {
    if (!authorized) return res.status(401).json({ error: 'auth required' });
    return next();
  }
  if (!authorized) return res.redirect('/login.html');
  return next();
});

const redirectUri = () => `${PUBLIC_URL}/auth/google/callback`;

app.get('/auth/google/login', (req, res) => {
  if (!AUTH_ENABLED) return res.status(503).send('auth not configured');
  const state = crypto.randomBytes(24).toString('base64url');
  req.session.oauth_state = state;
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID, redirect_uri: redirectUri(), response_type: 'code',
    scope: 'openid email profile', state, access_type: 'online', prompt: 'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  if (!AUTH_ENABLED) return res.status(503).send('auth not configured');
  const { code, state, error } = req.query;
  if (error) return res.redirect(`/login.html?error=${encodeURIComponent(error)}`);
  const expected = req.session.oauth_state;
  delete req.session.oauth_state;
  if (!code || !state || state !== expected) return res.redirect('/login.html?error=invalid_state');
  try {
    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri(), grant_type: 'authorization_code',
      }),
    });
    if (!tokenResp.ok) throw new Error(`token exchange ${tokenResp.status}`);
    const { access_token } = await tokenResp.json();
    if (!access_token) throw new Error('no access_token');
    const userResp = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    if (!userResp.ok) throw new Error(`userinfo ${userResp.status}`);
    const user = await userResp.json();
    const email = (user.email || '').toLowerCase();
    if (!email || !user.email_verified) return res.redirect('/login.html?error=unverified');
    if (!ALLOWED_EMAILS.has(email)) {
      return res.redirect(`/login.html?${new URLSearchParams({ error: 'unauthorized', email })}`);
    }
    req.session.user_email = email;
    req.session.user_name = user.name || '';
    req.session.user_picture = user.picture || '';
    return res.redirect('/');
  } catch (e) {
    console.error('[auth] OAuth failed:', e.message);
    return res.redirect('/login.html?error=token_exchange');
  }
});

app.post('/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/me', (req, res) => {
  if (!AUTH_ENABLED) return res.json({ authenticated: true, email: 'anonymous', auth_enabled: false });
  const email = req.session?.user_email;
  if (!email || !ALLOWED_EMAILS.has(email)) return res.status(401).json({ authenticated: false, auth_enabled: true });
  res.json({ authenticated: true, auth_enabled: true, email, name: req.session.user_name || '', picture: req.session.user_picture || '' });
});

app.get('/api/config', (req, res) => res.json({ defaultPrompt: DEFAULT_PROMPT, maxSeconds: SEG_SECONDS[2] }));

// ============================================================
// GENERATION PIPELINE → ComfyUI on the A100 (fully async; cold-start aware)
// ============================================================
const TEMPLATE_PATH = path.join(__dirname, 'workflow_api_template.json');
const loadTemplate = () => JSON.parse(fs.readFileSync(TEMPLATE_PATH, 'utf8'));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 60 * 1024 * 1024 } });
const jobs = new Map(); // jobId -> { status, phase, promptId, segNode, meta, out, error, created }

const sanitize = s => (s || 'file').replace(/[^a-zA-Z0-9._-]/g, '_').slice(-60);

async function ffprobeDuration(file) {
  const { stdout } = await execFileP(FFPROBE, ['-v', 'error', '-show_entries', 'format=duration',
    '-of', 'default=noprint_wrappers=1:nokey=1', file]);
  const d = parseFloat(stdout.trim());
  return Number.isFinite(d) && d > 0 ? d : 6;
}

async function padAudioToSilence(inFile, outFile, targetSec) {
  await execFileP(FFMPEG, ['-y', '-i', inFile, '-af', 'apad', '-t', String(targetSec),
    '-ar', '24000', '-ac', '1', outFile]);
}

async function comfyUpload(buf, filename) {
  const fd = new FormData();
  fd.append('image', new Blob([buf]), filename);
  fd.append('type', 'input');
  fd.append('overwrite', 'true');
  const r = await fetch(`${COMFY_URL}/upload/image`, { method: 'POST', body: fd });
  if (!r.ok) throw new Error(`upload ${filename}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  const j = await r.json();
  return j.subfolder ? `${j.subfolder}/${j.name}` : j.name;
}

async function waitComfyReady() {
  const deadline = Date.now() + WARMUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${COMFY_URL}/system_stats`, { signal: AbortSignal.timeout(15000) });
      if (r.ok) return;
    } catch { /* cold start in progress */ }
    await new Promise(r => setTimeout(r, 6000));
  }
  throw new Error("le GPU n'a pas démarré à temps (timeout warm-up)");
}

function pickOutput(entry, preferredNode) {
  const outs = entry.outputs || {};
  const scan = node => {
    const o = outs[node]; if (!o) return null;
    for (const k of ['gifs', 'videos', 'images']) {
      if (Array.isArray(o[k]) && o[k][0]?.filename) return o[k][0];
    }
    return null;
  };
  return scan(preferredNode)
    || SEG_OUTPUT_NODE.map(scan).find(Boolean)
    || Object.keys(outs).map(scan).find(Boolean) || null;
}

function extractError(entry) {
  const m = (entry.status?.messages || []).find(x => x[0] === 'execution_error');
  return m ? `${m[1].node_type}: ${m[1].exception_message}`.slice(0, 300) : "erreur d'exécution";
}

async function runJob(jobId, img, aud, prompt) {
  const job = jobs.get(jobId);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'studio-'));
  try {
    job.phase = 'audio';
    const audIn = path.join(tmp, 'in.' + (sanitize(aud.originalname).split('.').pop() || 'wav'));
    fs.writeFileSync(audIn, aud.buffer);
    let dur = 6;
    try { dur = await ffprobeDuration(audIn); } catch { console.warn('ffprobe failed, assuming 6s'); }
    const nseg = dur <= SEG_SECONDS[0] ? 1 : dur <= SEG_SECONDS[1] ? 2 : 3;
    job.segNode = SEG_OUTPUT_NODE[nseg - 1];
    job.meta = { audioDuration: Math.round(dur * 10) / 10, segments: nseg, outputSeconds: SEG_SECONDS[nseg - 1] };
    const audPad = path.join(tmp, 'pad.wav');
    await padAudioToSilence(audIn, audPad, SEG_SECONDS[nseg - 1] + 0.4);

    job.phase = 'starting';            // triggers + waits for A100 cold start
    await waitComfyReady();

    job.phase = 'upload';
    const stamp = crypto.randomBytes(5).toString('hex');
    const imgRef = await comfyUpload(img.buffer, `st_${stamp}_${sanitize(img.originalname)}`);
    const audRef = await comfyUpload(fs.readFileSync(audPad), `st_${stamp}.wav`);

    job.phase = 'submit';
    const p = loadTemplate();
    p['284'].inputs.image = imgRef;
    p['125'].inputs.audio = audRef;
    delete p['125'].inputs.audioUI;
    p['241'].inputs.positive_prompt = prompt;
    const r = await fetch(`${COMFY_URL}/prompt`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: p, client_id: jobId }),
    });
    const txt = await r.text();
    if (!r.ok) throw new Error('ComfyUI a refusé le prompt: ' + txt.slice(0, 400));
    const j = JSON.parse(txt);
    if (!j.prompt_id) throw new Error('pas de prompt_id: ' + JSON.stringify(j.node_errors || {}).slice(0, 400));
    job.promptId = j.prompt_id;
    job.phase = 'generating';
  } catch (e) {
    console.error('[runJob]', e);
    job.status = 'error';
    job.error = e.message;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

app.post('/api/generate', upload.fields([{ name: 'image', maxCount: 1 }, { name: 'audio', maxCount: 1 }]), (req, res) => {
  if (!COMFY_URL) return res.status(500).json({ error: 'COMFY_URL non configuré' });
  const img = req.files?.image?.[0];
  const aud = req.files?.audio?.[0];
  if (!img || !aud) return res.status(400).json({ error: 'Image ET audio requis.' });
  const prompt = (req.body.prompt || '').trim() || DEFAULT_PROMPT;
  const jobId = crypto.randomUUID();
  jobs.set(jobId, { status: 'running', phase: 'audio', created: Date.now() });
  runJob(jobId, img, aud, prompt);   // fire-and-forget; status endpoint tracks it
  res.json({ jobId });
});

app.get('/api/status/:jobId', async (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'job inconnu' });
  if (job.status === 'done') return res.json({ status: 'done', meta: job.meta });
  if (job.status === 'error') return res.json({ status: 'error', error: job.error });
  if (!job.promptId) return res.json({ status: 'running', phase: job.phase || 'preparing', meta: job.meta });
  try {
    const r = await fetch(`${COMFY_URL}/history/${job.promptId}`, { signal: AbortSignal.timeout(20000) });
    if (r.ok) {
      const entry = (await r.json())[job.promptId];
      if (entry) {
        const st = entry.status || {};
        if (st.status_str === 'error') { job.status = 'error'; job.error = extractError(entry); return res.json({ status: 'error', error: job.error }); }
        if (st.completed || st.status_str === 'success') {
          const out = pickOutput(entry, job.segNode);
          if (!out) { job.status = 'error'; job.error = 'aucune vidéo en sortie'; return res.json({ status: 'error', error: job.error }); }
          job.status = 'done'; job.out = out;
          return res.json({ status: 'done', meta: job.meta });
        }
      }
    }
  } catch { /* transient */ }
  return res.json({ status: 'running', phase: 'generating', meta: job.meta });
});

app.get('/api/result/:jobId', async (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job || job.status !== 'done' || !job.out) return res.status(404).send('pas prêt');
  const q = new URLSearchParams({ filename: job.out.filename, subfolder: job.out.subfolder || '', type: job.out.type || 'output' });
  const r = await fetch(`${COMFY_URL}/view?${q}`);
  if (!r.ok) return res.status(502).send('récupération échouée');
  res.setHeader('Content-Type', 'video/mp4');
  res.setHeader('Content-Disposition', 'inline; filename="avatar-studio.mp4"');
  res.send(Buffer.from(await r.arrayBuffer()));
});

setInterval(() => {
  const cutoff = Date.now() - 2 * 3600 * 1000;
  for (const [id, j] of jobs) if (j.created < cutoff) jobs.delete(id);
}, 10 * 60 * 1000);

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => console.log(`[studio] listening on :${PORT}`));
