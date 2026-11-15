// Records the SecureLakehouse demo video in ONE continuous browser session:
//   storyboard part 1 (structure, encryption, flow, Spark bug, real demo output)
//   -> the LIVE Streamlit dashboard, driven like a user (captions + visible cursor)
//   -> storyboard part 2 (tests, closing).
// Usage: node record.js <storyboard.html path> <app url> <output dir>
// Requires the Node "playwright" package (run via make_video.sh).

const { chromium } = require('playwright');
const path = require('path');

const [, , storyboard, appUrl, outDir] = process.argv;
const W = 1280, H = 720;
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function playStoryboard(page, part) {
  await page.goto(`file://${path.resolve(storyboard)}?part=${part}`);
  const h = await page.waitForFunction(() => window.__done, null, { timeout: 600000, polling: 250 });
  if ((await h.jsonValue()) !== true) throw new Error(`storyboard part ${part} failed`);
}

// ---- overlay for the live dashboard (caption bar, chapter tag, cursor) ----
const OVERLAY = () => {
  if (document.getElementById('vcap')) return;
  const css = document.createElement('style');
  css.textContent = `
    #vcap{position:fixed;left:0;bottom:0;width:100vw;min-height:66px;box-sizing:border-box;display:block;
      padding:20px 90px 12px;text-align:center;white-space:normal;overflow-wrap:break-word;
      font:18px/1.35 "DejaVu Sans",sans-serif;color:#e6e9ef;z-index:2147483600;
      background:linear-gradient(transparent,rgba(0,0,0,.82) 30%);pointer-events:none}
    #vchap{position:fixed;top:10px;right:16px;z-index:99999;font:12px "DejaVu Sans",sans-serif;color:#e6e9ef;
      background:#1f3354;border:1px solid #6ea8fe;border-radius:999px;padding:5px 12px;pointer-events:none;z-index:2147483600}
    #vcur{position:fixed;width:18px;height:18px;margin:-9px 0 0 -9px;border-radius:50%;z-index:2147483647;
      background:rgba(110,168,254,.55);border:2px solid #fff;pointer-events:none;transition:transform .12s;left:-50px;top:-50px}
    #vcur.down{transform:scale(.7)}`;
  document.head.appendChild(css);
  for (const id of ['vcap', 'vchap', 'vcur']) { const d = document.createElement('div'); d.id = id; document.body.appendChild(d); }
  document.getElementById('vchap').textContent = '7. Dashboard · live Streamlit app';
  addEventListener('mousemove', e => { const c = document.getElementById('vcur'); c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
  addEventListener('mousedown', () => document.getElementById('vcur').classList.add('down'), true);
  addEventListener('mouseup', () => document.getElementById('vcur').classList.remove('down'), true);
};

let mouse = { x: W / 2, y: H / 2 };
async function caption(page, text) { await page.evaluate(t => { document.getElementById('vcap').textContent = t; }, text); }

async function moveTo(page, locator) {
  await locator.scrollIntoViewIfNeeded();
  const b = await locator.boundingBox();
  const x = b.x + b.width / 2, y = b.y + b.height / 2;
  await page.mouse.move(x, y, { steps: 25 });
  mouse = { x, y };
  await sleep(250);
}
async function click(page, locator) {
  await moveTo(page, locator);
  await page.mouse.down(); await sleep(90); await page.mouse.up();
}

// Wait until Streamlit has finished re-running the script.
async function idle(page, timeout = 180000) {
  await sleep(600);
  await page.waitForFunction(() => {
    const w = document.querySelector('[data-testid="stStatusWidget"]');
    return !w || !/running/i.test(w.textContent || '');
  }, null, { timeout, polling: 200 });
  await sleep(400);
}

async function smoothScrollTo(page, locator) {
  await locator.evaluate(el => el.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  await sleep(1300);
}

async function pickRole(page, role) {
  const box = page.getByTestId('stSelectbox').filter({ hasText: 'Role' });
  await click(page, box);
  await sleep(500);
  await click(page, page.getByRole('option', { name: role, exact: true }));
  await idle(page);
}

async function runQuery(page, expectOutcome) {
  await click(page, page.getByRole('button', { name: 'Run query' }));
  await page.getByRole('heading', { name: new RegExp(`^Outcome: ${expectOutcome}`) }).waitFor({ timeout: 120000 });
  await idle(page);
}

async function dashboard(page) {
  await page.goto(appUrl);
  await page.getByRole('heading', { name: 'SecureLakehouse' }).first().waitFor({ timeout: 180000 });
  await idle(page);
  await page.evaluate(OVERLAY);
  await page.mouse.move(mouse.x, mouse.y);
  await caption(page, 'The live dashboard is only a presentation layer over the same gateway, audit log and detector as the CLI.');
  await sleep(4200);

  await caption(page, 'Reset the workspace: the sample CSV is encrypted column by column into Parquet by Spark.');
  await click(page, page.getByRole('button', { name: /Reset workspace/ }));
  await page.getByText(/Ingested \d+ encrypted rows/).waitFor({ timeout: 180000 });
  await idle(page);
  await sleep(1500);

  await caption(page, 'Analyst in Engineering asks for names and salaries…');
  await runQuery(page, 'SERVED');
  await moveTo(page, page.getByRole('heading', { name: /^Outcome:/ }));
  await caption(page, '…and gets real values, automatically limited to their own department (4 of 12 rows).');
  await sleep(4800);

  await caption(page, 'Same query as an auditor: every sensitive value is redacted, and no key is ever used.');
  await smoothScrollTo(page, page.getByRole('heading', { name: 'Query the lake' }));
  await pickRole(page, 'auditor');
  await runQuery(page, 'MASKED');
  await moveTo(page, page.getByRole('heading', { name: /^Outcome:/ }));
  await sleep(4500);

  await caption(page, 'As support, salary is DENY, so the whole query is refused (fail closed) and still audited.');
  await smoothScrollTo(page, page.getByRole('heading', { name: 'Query the lake' }));
  await pickRole(page, 'support');
  await runQuery(page, 'DENIED');
  await moveTo(page, page.getByRole('heading', { name: /^Outcome:/ }));
  await sleep(4500);

  const breachBtn = page.getByRole('button', { name: 'Run breach simulation' });
  await smoothScrollTo(page, page.getByRole('heading', { name: 'Breach simulation' }));
  await caption(page, 'Breach simulation: replay a normal workday, then a compromised analyst account at 23:40…');
  await click(page, breachBtn);
  await idle(page, 300000);
  await smoothScrollTo(page, page.getByRole('heading', { name: 'Breach simulation' }));
  await caption(page, '…15 real queries through the gateway: SSN probes, ciphertext requests and a bulk export are denied.');
  await sleep(5500);

  await smoothScrollTo(page, page.getByRole('heading', { name: 'Insider-threat alerts' }));
  await caption(page, 'The detector reads only the audit trail and explains every alert. Red = HIGH, amber = MEDIUM, blue = LOW.');
  await sleep(4000);
  await page.mouse.wheel(0, 260); await sleep(3200);

  await smoothScrollTo(page, page.getByRole('heading', { name: 'Audit log' }));
  await caption(page, 'Every query appended one hash-chained audit event. Verify the chain…');
  await click(page, page.getByRole('button', { name: 'Verify integrity' }));
  await page.getByText(/^INTACT/).waitFor({ timeout: 60000 });
  await sleep(3200);

  await caption(page, 'Now play the attacker: rewrite a past "denied" entry as "served"…');
  await click(page, page.getByRole('button', { name: 'Simulate tampering' }));
  await page.getByText(/Attacker rewrote seq=/).waitFor({ timeout: 60000 });
  await idle(page);
  await sleep(2800);
  await click(page, page.getByRole('button', { name: 'Verify integrity' }));
  await page.getByText(/^TAMPERED/).waitFor({ timeout: 60000 });
  await moveTo(page, page.getByText(/^TAMPERED/));
  await caption(page, '…and verify() names the exact entry that was modified.');
  await sleep(5000);
}

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: W, height: H }, colorScheme: 'dark',
    recordVideo: { dir: outDir, size: { width: W, height: H } },
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  const t0 = Date.now();
  const mark = label => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${label}`);
  try {
    const only = process.env.ONLY;  // debugging aid: ONLY=dashboard records just that segment
    if (!only) { mark('storyboard part 1'); await playStoryboard(page, 1); }
    if (!only || only === 'dashboard') { mark('dashboard'); await dashboard(page); }
    if (!only) { mark('storyboard part 2'); await playStoryboard(page, 2); }
    mark('done');
  } finally {
    const video = page.video();
    await context.close();
    await browser.close();
    console.log('VIDEO=' + (await video.path()));
    const exc = errors.filter(e => !/ResizeObserver/.test(e));
    console.log('page errors: ' + JSON.stringify(exc));
  }
})().catch(e => { console.error(e); process.exit(1); });
