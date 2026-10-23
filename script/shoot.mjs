// Cattura screenshot della dashboard con Chrome headless via CDP (WebSocket nativo di Node).
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';

const OUT = process.argv[2];
const BASE = 'http://localhost:8131';
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const PORT = 9333;
const W = 1280, H = 800, SCALE = 2;
const sleep = ms => new Promise(r => setTimeout(r, ms));
mkdirSync(OUT, { recursive: true });

const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, '--no-first-run',
  '--no-default-browser-check', `--user-data-dir=${OUT}/../chrome-profile`, `--window-size=${W},${H}`, 'about:blank'],
  { stdio: 'ignore' });

let targets;
for (let i = 0; i < 50; i++) {
  try { targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); break; } catch { await sleep(200); }
}
const page = targets.find(t => t.type === 'page');
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r));
let id = 0; const pending = new Map();
ws.addEventListener('message', ev => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
});
const send = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const evaluate = async expr => {
  const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 400));
  return r.result?.result?.value;
};

await send('Page.enable'); await send('Runtime.enable');
await send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: SCALE, mobile: false });

// Helper iniettati nella pagina
const HELPERS = `
window.__byText = (sel, txt) => [...document.querySelectorAll(sel)].find(e => e.textContent.trim().startsWith(txt));
window.__light = () => { const t = document.getElementById('theme-toggle'); if (t && document.documentElement.getAttribute('data-theme') !== 'light') t.click(); };
`;

async function shot(name, path, { prep = '', clip = null, wait = 2500, height = H } = {}) {
  await send('Emulation.setDeviceMetricsOverride', { width: W, height, deviceScaleFactor: SCALE, mobile: false });
  await send('Page.navigate', { url: BASE + path });
  await sleep(wait);
  await evaluate(HELPERS + '__light();');
  await sleep(400);
  if (prep) { await evaluate(`(async () => { ${prep} })()`); await sleep(2500); }
  let params = { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: W, height, scale: 1 } };
  if (clip) {
    const rect = await evaluate(`(() => { ${clip} })()`);
    if (rect) params.clip = { ...rect, scale: 1 };
  }
  const r = await send('Page.captureScreenshot', params);
  writeFileSync(`${OUT}/${name}.png`, Buffer.from(r.result.data, 'base64'));
  console.log('ok', name, params.clip ? JSON.stringify(params.clip) : 'viewport');
}

const box = (expr, pad = 12, maxH = 1400) => `
  const e = ${expr}; if (!e) return null;
  const b = e.getBoundingClientRect();
  return { x: Math.max(0, b.left - ${pad}), y: Math.max(0, b.top + window.scrollY - ${pad}),
           width: Math.min(b.width + 2 * ${pad}, ${W}), height: Math.min(b.height + 2 * ${pad}, ${maxH}) };`;

const which = process.argv.slice(3);
const want = n => which.length === 0 || which.includes(n);

if (want('home')) await shot('dashboard_home', '/', { height: 700 });
if (want('checkov')) await shot('dashboard_checkov', '/results?target=sadcloud', {
  height: 1150,
  prep: `const h = document.querySelector('.finding-row'); if (h) h.click();`,
});
if (want('spectral')) await shot('dashboard_spectral', '/contract-results?target=vampi', { height: 900 });
if (want('semgrep')) await shot('dashboard_semgrep', '/api-results?target=dvapi', { height: 900 });
if (want('core')) await shot('dashboard_core', '/unified-results?target=vampi', { height: 1050 });
if (want('bola')) await shot('dashboard_bola', '/unified-results?target=vampi', {
  height: 2600,
  clip: `const e = document.querySelector('.findings-section-title'); if (!e) return null; const b = e.getBoundingClientRect(); return { x: 0, y: b.top + window.scrollY - 16, width: ${W}, height: 760 };`,
});

ws.close(); chrome.kill();
