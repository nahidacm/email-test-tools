// Email Test Tools UI. Plain JS, no build step besides Tailwind/FlyonUI CSS.
(function () {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const store = {
    get(k, d) { try { const v = localStorage.getItem('ett-' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem('ett-' + k, JSON.stringify(v)); } catch { /* private mode */ } },
  };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ------------------------------------------------------------ status styles
  // Class names are written out in full so Tailwind can find them.
  const STATUS = {
    ok:   { icon: 'icon-[tabler--circle-check-filled]', color: 'text-success', alert: 'alert-success', badge: 'badge-success', label: 'Passed' },
    warn: { icon: 'icon-[tabler--alert-triangle-filled]', color: 'text-warning', alert: 'alert-warning', badge: 'badge-warning', label: 'Warning' },
    fail: { icon: 'icon-[tabler--circle-x-filled]', color: 'text-error', alert: 'alert-error', badge: 'badge-error', label: 'Problem' },
    info: { icon: 'icon-[tabler--info-circle-filled]', color: 'text-info', alert: 'alert-info', badge: 'badge-info', label: 'Info' },
    skip: { icon: 'icon-[tabler--player-skip-forward-filled]', color: 'text-base-content/50', alert: 'alert-info', badge: 'badge-neutral', label: 'Skipped' },
  };

  // ------------------------------------------------------------ routing
  const pages = $$('[data-page]');
  function route() {
    const id = (location.hash || '#home').slice(1);
    const page = pages.find((p) => p.dataset.page === id) ? id : 'home';
    pages.forEach((p) => (p.hidden = p.dataset.page !== page));
    $$('#nav a').forEach((a) => a.classList.toggle('menu-active', a.getAttribute('href') === '#' + page));
    closeMenu();
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', route);

  // Sidebar: a drawer on small screens, collapsible on desktop.
  const sidebar = $('#sidebar'), backdrop = $('#backdrop'), menuBtn = $('#menu-toggle');
  const desktop = window.matchMedia('(min-width: 1024px)');
  function closeMenu() { sidebar.classList.add('-translate-x-full'); backdrop.hidden = true; }
  function paintSidebar() {
    const hidden = store.get('sidebar-hidden', false);
    sidebar.classList.toggle('lg:hidden', hidden);
    menuBtn.innerHTML = !desktop.matches ? '<span class="icon-[tabler--menu-2] size-5"></span>'
      : hidden ? '<span class="icon-[tabler--layout-sidebar-left-expand] size-5"></span>'
      : '<span class="icon-[tabler--layout-sidebar-left-collapse] size-5"></span>';
    menuBtn.title = desktop.matches ? (hidden ? 'Show menu' : 'Hide menu') : 'Open menu';
  }
  menuBtn.addEventListener('click', () => {
    if (desktop.matches) { store.set('sidebar-hidden', !store.get('sidebar-hidden', false)); paintSidebar(); return; }
    sidebar.classList.remove('-translate-x-full'); backdrop.hidden = false;
  });
  backdrop.addEventListener('click', closeMenu);
  desktop.addEventListener('change', paintSidebar);

  // Theme
  const themeBtn = $('#theme-toggle');
  function paintThemeIcon() {
    const dark = document.documentElement.dataset.theme === 'dark';
    themeBtn.innerHTML = dark ? '<span class="icon-[tabler--sun] size-5"></span>' : '<span class="icon-[tabler--moon] size-5"></span>';
  }
  themeBtn.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('ett-theme', next); } catch {}
    paintThemeIcon();
  });

  // Technical mode: show details expanded by default
  const tech = $('#tech-mode');
  tech.checked = store.get('tech', false);
  tech.addEventListener('change', () => {
    store.set('tech', tech.checked);
    $$('[data-details]').forEach((d) => (d.open = tech.checked));
  });

  // Password visibility
  $$('[data-toggle-password]').forEach((btn) => btn.addEventListener('click', () => {
    const inp = $(btn.dataset.togglePassword);
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    btn.innerHTML = show ? '<span class="icon-[tabler--eye-off] text-base-content/60 size-5"></span>' : '<span class="icon-[tabler--eye] text-base-content/60 size-5"></span>';
  }));

  // ------------------------------------------------------------ SMTP presets
  const PRESETS = {
    gmail:    { host: 'smtp.gmail.com', port: 587, security: 'starttls', tip: 'Use your full Gmail address as the username and an <b>App password</b> (not your normal password). Requires 2-Step Verification.' },
    m365:     { host: 'smtp.office365.com', port: 587, security: 'starttls', tip: 'Your admin may need to enable <b>Authenticated SMTP</b> for this mailbox. Accounts with MFA need an app password.' },
    yahoo:    { host: 'smtp.mail.yahoo.com', port: 465, security: 'ssl', tip: 'Yahoo requires an <b>app password</b> (Account Security → Generate app password).' },
    zoho:     { host: 'smtp.zoho.com', port: 465, security: 'ssl', tip: 'EU/IN accounts use smtp.zoho.eu / smtp.zoho.in. Use an app-specific password if 2FA is on.' },
    icloud:   { host: 'smtp.mail.me.com', port: 587, security: 'starttls', tip: 'Use an <b>app-specific password</b> from appleid.apple.com.' },
    ses:      { host: 'email-smtp.us-east-1.amazonaws.com', port: 587, security: 'starttls', tip: 'Change the region in the server name if needed. Use <b>SES SMTP credentials</b>, not AWS access keys.' },
    sendgrid: { host: 'smtp.sendgrid.net', port: 587, security: 'starttls', user: 'apikey', tip: 'Username is literally <b>apikey</b>; the password is your API key (starts with SG.).' },
    mailgun:  { host: 'smtp.mailgun.org', port: 587, security: 'starttls', tip: 'Use the SMTP credentials from your Mailgun domain settings. EU accounts: smtp.eu.mailgun.org.' },
    local:    { host: '127.0.0.1', port: 1025, security: 'none', tip: 'MailHog and Mailpit listen on port 1025 without encryption or login by default.' },
  };
  const presetSel = $('#smtp-preset'), presetTip = $('#smtp-preset-tip');
  const defaultTip = presetTip.innerHTML;
  presetSel.addEventListener('change', () => {
    const p = PRESETS[presetSel.value];
    const f = $('form[data-tool="smtp"]');
    if (!p) { presetTip.innerHTML = defaultTip; return; }
    f.host.value = p.host;
    f.port.value = p.port;
    $$('input[name="security"]', f).forEach((r) => (r.checked = r.value === p.security));
    if (p.user) f.username.value = p.user;
    presetTip.innerHTML = '<span class="icon-[tabler--bulb] size-4 align-text-bottom text-warning"></span> ' + p.tip;
  });

  // Port 465 ⇄ SSL hint when the user types a port while on Auto
  $('#smtp-port').addEventListener('change', (e) => {
    const port = +e.target.value;
    const f = e.target.form;
    const sec = $('input[name="security"]:checked', f).value;
    if (sec === 'ssl' && (port === 587 || port === 25)) $$('input[name="security"]', f).forEach((r) => (r.checked = r.value === 'starttls'));
    if (sec === 'starttls' && port === 465) $$('input[name="security"]', f).forEach((r) => (r.checked = r.value === 'ssl'));
  });

  // Port quick-picks
  $$('[data-ports]').forEach((b) => b.addEventListener('click', () => { $('#ports-list').value = b.dataset.ports; }));
  $('#port25-test').addEventListener('click', () => {
    $('#ports-host').value = 'gmail-smtp-in.l.google.com';
    $('#ports-list').value = '25';
    $('form[data-tool="ports"]').requestSubmit();
  });

  // ------------------------------------------------------------ collect form data
  const toInt = (v) => parseInt(v, 10) || 0;
  const COLLECT = {
    smtp: (f) => ({
      host: f.host.value, port: toInt(f.port.value),
      security: $('input[name="security"]:checked', f).value,
      username: f.username.value, password: f.password.value,
      from: f.from.value, fromName: f.fromName.value,
      to: [f.to.value],
      subject: f.subject.value, body: f.body.value,
      mode: $('input[name="mode"]:checked', f).value,
      heloName: f.heloName.value, timeoutSec: toInt(f.timeoutSec.value),
      skipVerify: f.skipVerify.checked,
    }),
    domain: (f) => ({ domain: f.domain.value, selectors: f.selectors.value.split(/[\s,]+/).filter(Boolean), server: f.server.value, checks: $$('input[name="checks"]:checked', f).map((c) => c.value) }),
    ports: (f) => ({ host: f.host.value, ports: f.ports.value.split(/[\s,;]+/).map(toInt).filter((n) => n > 0 && n < 65536) }),
    dns: (f) => ({ name: f.name.value, types: $$('input[name="types"]:checked', f).map((c) => c.value), server: f.server.value }),
    tls: (f) => ({ host: f.host.value, port: toInt(f.port.value), mode: f.mode.value }),
  };

  // Remember non-secret form values per tool.
  const SECRET = new Set(['password']);
  function saveForm(tool, f) {
    const data = {};
    for (const el of f.elements) {
      if (!el.name || SECRET.has(el.name)) continue;
      if (el.type === 'radio') { if (el.checked) data[el.name] = el.value; }
      else if (el.type === 'checkbox') { (data[el.name] ||= []); if (el.checked) data[el.name].push(el.value); }
      else data[el.name] = el.value;
    }
    store.set('form-' + tool, data);
  }
  function restoreForm(tool, f) {
    const data = store.get('form-' + tool, null);
    if (!data) return;
    for (const el of f.elements) {
      if (!el.name || !(el.name in data)) continue;
      const v = data[el.name];
      if (el.type === 'radio') el.checked = el.value === v;
      else if (el.type === 'checkbox') el.checked = Array.isArray(v) && v.includes(el.value);
      else el.value = v;
    }
  }

  // ------------------------------------------------------------ run a tool
  // Each tool page shows either its form or its result, full width.
  const last = {}; // tool -> { req (no password), rep }
  const running = {}; // tool -> AbortController

  function showView(tool, view) {
    const f = $(`form[data-tool="${tool}"]`), out = $(`[data-result="${tool}"]`);
    f.hidden = view !== 'form';
    out.hidden = view !== 'result';
    window.scrollTo(0, 0);
  }

  $$('form[data-tool]').forEach((f) => {
    const tool = f.dataset.tool;
    const out = $(`[data-result="${tool}"]`);
    restoreForm(tool, f);

    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      saveForm(tool, f);
      const req = COLLECT[tool](f);
      const shown = { ...req };
      delete shown.password;
      last[tool] = { req: shown, rep: null };

      running[tool]?.abort();
      const ctl = new AbortController();
      running[tool] = ctl;
      out.innerHTML = toolbar(tool, null) + loadingCard(tool);
      bindToolbar(tool, out);
      showView(tool, 'result');
      try {
        const res = await fetch('api/' + tool, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req),
          signal: ctl.signal,
        });
        if (!res.ok) throw new Error((await res.text()) || res.statusText);
        const rep = await res.json();
        last[tool].rep = rep;
        out.innerHTML = toolbar(tool, rep) + renderReport(rep);
        bindToolbar(tool, out);
        bindResult(out, rep, tool);
      } catch (err) {
        if (err.name === 'AbortError') return;
        out.innerHTML = toolbar(tool, null) + `<div class="alert alert-error flex flex-row items-start gap-3"><span class="icon-[tabler--plug-x] size-6 shrink-0"></span>
          <div><h3 class="font-semibold">Couldn't reach the Email Test Tools app.</h3>
          <p class="text-sm">Is it still running? Restart it and reload this page.</p>
          <p class="mt-1 font-mono text-xs opacity-70">${esc(err.message)}</p></div></div>`;
        bindToolbar(tool, out);
      } finally {
        if (running[tool] === ctl) delete running[tool];
      }
    });
  });

  const TOOL_NAMES = { smtp: 'SMTP test', domain: 'Domain health check', ports: 'Port check', dns: 'DNS lookup', tls: 'Certificate check' };

  // One line describing what was tested, e.g. "smtp.gmail.com:587 · STARTTLS".
  function describe(tool, r) {
    if (!r) return '';
    switch (tool) {
      case 'smtp': return `${r.host}:${r.port} · ${{ auto: 'Auto security', starttls: 'STARTTLS', ssl: 'SSL/TLS', none: 'No encryption' }[r.security] || r.security}${r.username ? ' · login ' + r.username : ''}${r.mode === 'verify' ? ' · check only' : ''}`;
      case 'domain': return r.domain;
      case 'ports': return `${r.host} · ports ${r.ports.join(', ')}`;
      case 'dns': return `${r.name}${r.server ? ' via ' + r.server : ''}`;
      case 'tls': return `${r.host}:${r.port}`;
    }
    return '';
  }

  function toolbar(tool, rep) {
    const problems = rep ? rep.steps.filter((x) => x.status === 'fail' || x.status === 'warn').length : 0;
    const what = describe(tool, last[tool]?.req);
    return `<div class="bg-base-100 rounded-box border-base-content/10 sticky top-16 z-10 flex flex-wrap items-center gap-2 border p-2 shadow-sm">
      <button type="button" class="btn btn-soft" data-back><span class="icon-[tabler--arrow-left] size-5"></span>Back to settings</button>
      ${rep ? `<button type="button" class="btn btn-text" data-rerun title="Run the same test again"><span class="icon-[tabler--refresh] size-5"></span>Run again</button>` : ''}
      <span class="min-w-0 flex-1 truncate px-2 text-sm text-base-content/70" title="${esc(what)}">${esc(what)}</span>
      ${rep ? `<button type="button" class="btn btn-soft" data-copy-all title="Copy the results as text"><span class="icon-[tabler--copy] size-5"></span>${problems ? `Copy ${problems} issue${problems === 1 ? '' : 's'}` : 'Copy result'}</button>
      <button type="button" class="btn btn-primary" data-prompt-all title="Copy a ready-made prompt to paste into ChatGPT, Claude or another AI agent"><span class="icon-[tabler--sparkles] size-5"></span>Copy AI prompt</button>` : ''}
    </div>`;
  }

  function bindToolbar(tool, out) {
    $('[data-back]', out)?.addEventListener('click', () => { running[tool]?.abort(); showView(tool, 'form'); });
    $('[data-rerun]', out)?.addEventListener('click', () => $(`form[data-tool="${tool}"]`).requestSubmit());
    const rep = last[tool]?.rep;
    if (!rep) return;
    const issues = rep.steps.filter((x) => x.status === 'fail' || x.status === 'warn');
    $('[data-copy-all]', out)?.addEventListener('click', (e) => copyText(resultText(tool, rep), e.currentTarget));
    $('[data-prompt-all]', out)?.addEventListener('click', (e) => copyText(aiPrompt(tool, rep, issues), e.currentTarget));
  }

  function loadingCard(tool) {
    const msg = { smtp: 'Talking to the mail server…', domain: 'Checking DNS, mail servers, blacklists and website… (up to a minute)', ports: 'Knocking on ports…', dns: 'Asking DNS…', tls: 'Inspecting the certificate…' }[tool];
    return `<div class="card"><div class="card-body flex-row items-center gap-4">
      <span class="loading loading-spinner loading-lg text-primary"></span>
      <div><p class="font-medium">${msg}</p><p class="text-sm text-base-content/60">This can take up to a minute if a server is slow to answer. Use “Back to settings” to cancel.</p></div>
    </div></div>`;
  }

  // ------------------------------------------------------------ copy & AI prompt
  async function copyText(text, btn) {
    let ok = true;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch { ok = false; }
      ta.remove();
    }
    if (!btn) return;
    const html = btn.dataset.html || btn.innerHTML;
    btn.dataset.html = html;
    const small = btn.classList.contains('btn-xs');
    btn.innerHTML = ok ? `<span class="icon-[tabler--check] ${small ? 'size-4' : 'size-5'}"></span>Copied` : 'Copy failed';
    clearTimeout(btn._t);
    btn._t = setTimeout(() => { btn.innerHTML = html; }, 1600);
  }

  const LEVEL = { fail: 'Error', warn: 'Warning', ok: 'Passed', info: 'Info', skip: 'Skipped' };

  function stepText(st, withDetails = true) {
    const out = [`[${LEVEL[st.status] || st.status}] ${st.title}${st.target ? ` (${st.target})` : ''}`];
    if (st.summary) out.push(st.summary);
    if (st.counts) {
      const c = st.counts;
      out.push(`Checks: ${c.fail + c.warn + c.ok + c.unchecked} total: ${c.fail} error, ${c.warn} warning, ${c.ok} passed, ${c.unchecked} not checked`);
    }
    if (st.hint) out.push('What to do: ' + st.hint);
    if (withDetails && st.details?.length) out.push('Details:\n' + st.details.map((d) => '  - ' + d).join('\n'));
    if (st.moreInfo) out.push('More info: ' + st.moreInfo);
    return out.join('\n');
  }

  function resultText(tool, rep) {
    const issues = rep.steps.filter((x) => x.status === 'fail' || x.status === 'warn');
    const head = `${TOOL_NAMES[tool]}: ${describe(tool, last[tool]?.req)}\n${rep.headline}${rep.advice ? '\n' + rep.advice : ''}\n(${new Date(rep.startedAt).toLocaleString()})`;
    const list = issues.length ? issues : rep.steps;
    return head + '\n\n' + list.map((x) => stepText(x)).join('\n\n');
  }

  function contextLines(tool, r) {
    if (!r) return [];
    switch (tool) {
      case 'smtp': return [
        `SMTP server: ${r.host}, port ${r.port}`,
        `Security setting: ${r.security}${r.skipVerify ? ' (certificate verification turned off)' : ''}`,
        `Login username: ${r.username || '(none)'} (password intentionally not included)`,
        `From: ${r.from}${r.fromName ? ` (${r.fromName})` : ''}`,
        `To: ${(r.to || []).join(', ')}`,
        `Mode: ${r.mode === 'verify' ? 'check only, no message sent' : 'send a test message'}`,
      ];
      case 'domain': return [`Domain: ${r.domain}`, `Areas checked: ${(r.checks?.length ? r.checks : ['auth', 'mail', 'dns', 'blacklist', 'web']).join(', ')}`, r.selectors?.length ? `DKIM selectors given: ${r.selectors.join(', ')}` : ''].filter(Boolean);
      case 'ports': return [`Host: ${r.host}`, `Ports tested: ${r.ports.join(', ')}`];
      case 'dns': return [`Name: ${r.name}`, `Record types: ${(r.types || []).join(', ') || 'default'}`, `DNS server: ${r.server || 'system default'}`];
      case 'tls': return [`Server: ${r.host}, port ${r.port}`, `Connection type: ${r.mode}`];
    }
    return [];
  }

  const ROLE = {
    smtp: 'an expert email systems administrator who knows SMTP, mail clients and email providers (Gmail, Microsoft 365, Amazon SES, etc.)',
    domain: 'an expert in email deliverability, DNS and mail server administration (SPF, DKIM, DMARC, MX, reverse DNS, blacklists)',
    ports: 'an expert network administrator who knows firewalls, ISPs and email ports',
    dns: 'an expert DNS administrator',
    tls: 'an expert in TLS certificates and mail/web server configuration',
  };

  // A self-contained prompt for ChatGPT, Claude or a coding/ops agent.
  function aiPrompt(tool, rep, issues) {
    const r = last[tool]?.req;
    const passed = rep.steps.filter((x) => x.status === 'ok');
    const parts = [];
    parts.push(`You are ${ROLE[tool] || 'an expert in email delivery and networking'}. Help me fix the problems below, found by the "${TOOL_NAMES[tool]}" in Email Test Tools on ${new Date(rep.startedAt).toLocaleString()}.`);
    parts.push('## What was tested\n' + contextLines(tool, r).map((l) => '- ' + l).join('\n'));
    parts.push(`## Overall result\n${rep.headline}${rep.advice ? '\n' + rep.advice : ''}`);
    if (issues.length) {
      parts.push(`## Problems to fix (${issues.length})\n` + issues.map((x, i) => `### ${i + 1}. ${stepText(x)}`).join('\n\n'));
    } else {
      parts.push('## Problems\nNo errors or warnings were reported. Please review the results below for anything worth improving.');
    }
    if (passed.length) parts.push('## Checks that passed (for context)\n' + passed.map((x) => `- ${x.title}${x.target ? ` (${x.target})` : ''}: ${x.summary}`).join('\n'));
    if (tool !== 'domain' && rep.log?.length) {
      const log = rep.log.slice(-80).map((l) => `${(l.ms / 1000).toFixed(3)}s ${l.dir} ${l.text}`).join('\n');
      parts.push('## Technical log (passwords hidden; > sent, < received, * info, ! error)\n```\n' + log + '\n```');
    }
    parts.push(`## What I need from you
1. Explain the root cause of each problem in plain language.
2. Give exact, step-by-step fixes: full DNS records (type, host/name, value, TTL), server or app configuration, or provider settings, as applicable.
3. Order the fixes by impact, and say which I can do myself and which need my email, DNS or hosting provider.
4. Tell me how to verify each fix (I can re-run this test).
5. If you can act on my systems (DNS, server, code), tell me what you will change before changing it.
If anything is unclear or depends on information not shown here, ask me before assuming.`);
    return parts.join('\n\n');
  }

  // ------------------------------------------------------------ rendering
  function renderReport(rep) {
    const s = STATUS[rep.status] || STATUS.info;
    const secs = (rep.durationMs / 1000).toFixed(1);
    return `
      <div class="flex flex-col gap-4">
        <div class="alert alert-soft ${s.alert} flex flex-row items-start gap-4">
          <span class="${s.icon} size-7 shrink-0"></span>
          <div class="min-w-0 flex-1">
            <h2 class="text-lg font-semibold">${esc(rep.headline)}</h2>
            ${rep.advice ? `<p class="mt-1">${esc(rep.advice)}</p>` : ''}
            <p class="mt-2 text-xs opacity-70">Finished in ${secs}s · ${new Date(rep.startedAt).toLocaleString()}</p>
          </div>
        </div>
        ${renderExtra(rep)}
        ${renderSteps(rep)}
        ${renderLog(rep)}
      </div>`;
  }

  // Areas of the domain report, in display order.
  const CATS = {
    auth: { name: 'Email authentication', icon: 'icon-[tabler--shield-check]' },
    mail: { name: 'Mail server', icon: 'icon-[tabler--mail]' },
    dns: { name: 'DNS', icon: 'icon-[tabler--world]' },
    blacklist: { name: 'Blacklist', icon: 'icon-[tabler--ban]' },
    web: { name: 'Web server', icon: 'icon-[tabler--world-www]' },
  };
  // A step counts as one check, unless it carries its own tally
  // (e.g. the blacklist step counts every list it queried).
  const tally = (x) => x.counts
    ? { fail: x.counts.fail, warn: x.counts.warn, ok: x.counts.ok, unchecked: x.counts.unchecked }
    : { fail: +(x.status === 'fail'), warn: +(x.status === 'warn'), ok: +(x.status === 'ok'), unchecked: 0 };
  const count = (steps) => steps.map(tally).reduce((a, t) => ({
    fail: a.fail + t.fail, warn: a.warn + t.warn, ok: a.ok + t.ok, unchecked: a.unchecked + t.unchecked,
  }), { fail: 0, warn: 0, ok: 0, unchecked: 0 });

  function renderSteps(rep) {
    const list = (steps) => `<div class="card"><div class="card-body p-0">
      <ol class="divide-base-content/10 divide-y">${steps.map(renderStep).join('')}</ol></div></div>`;
    if (!rep.steps.some((x) => x.category)) return list(rep.steps);

    const cats = Object.keys(CATS).filter((c) => rep.steps.some((x) => x.category === c));
    const card = (title, icon, c, active) => {
      const bar = c.fail ? 'bg-error' : c.warn ? 'bg-warning' : 'bg-success';
      const line = (n, label, cls, ic) => `<li class="flex items-center gap-2 ${n ? cls : 'text-base-content/50'}"><span class="${ic} size-4"></span>${n} ${label}</li>`;
      return `<div class="card overflow-hidden ${active ? 'ring-base-content/20 ring-2' : ''}">
        <div class="card-body gap-3 p-4">
          <h3 class="flex items-center gap-2 font-semibold text-base-content"><span class="${icon} size-5"></span>${title}</h3>
          <ul class="flex flex-col gap-1 text-sm">
            ${line(c.fail, 'Errors', 'text-error', 'icon-[tabler--circle-x-filled]')}
            ${line(c.warn, 'Warnings', 'text-warning', 'icon-[tabler--alert-triangle-filled]')}
            ${line(c.ok, 'Passed', 'text-success', 'icon-[tabler--circle-check-filled]')}
            ${c.unchecked ? `<li class="flex items-center gap-2 text-base-content/60" title="Couldn't be queried from your network or DNS server"><span class="icon-[tabler--help-circle] size-4"></span>${c.unchecked} Not checked</li>` : ''}
          </ul>
        </div>
        <div class="${bar} h-1.5"></div>
      </div>`;
    };
    const total = count(rep.steps);
    const cards = `<div class="grid grid-cols-2 gap-3 sm:grid-cols-3 2xl:grid-cols-6">
      ${card('Problems', 'icon-[tabler--alert-octagon]', total, true)}
      ${cats.map((c) => card(CATS[c].name, CATS[c].icon, count(rep.steps.filter((x) => x.category === c)))).join('')}
    </div>`;

    const problems = rep.steps.filter((x) => x.status === 'fail' || x.status === 'warn')
      .sort((a, b) => (a.status === b.status ? 0 : a.status === 'fail' ? -1 : 1));
    const table = problems.length ? `<div class="card">
      <div class="card-body pb-2"><h3 class="card-title">${problems.length} problem${problems.length === 1 ? '' : 's'} to look at</h3>
        <p class="text-sm text-base-content/60">Click a row to jump to the full explanation.</p></div>
      <div class="overflow-x-auto"><table class="table">
        <thead><tr><th class="w-8"></th><th>Area</th><th>Host</th><th>Result</th><th></th></tr></thead>
        <tbody>${problems.map((x) => {
          const s = STATUS[x.status];
          return `<tr class="hover:bg-base-200/60 cursor-pointer" data-jump="step-${esc(x.id)}">
            <td><span class="${s.icon} ${s.color} size-5"></span></td>
            <td class="whitespace-nowrap">${esc(CATS[x.category]?.name || '')}</td>
            <td class="max-w-48 truncate font-mono text-xs" title="${esc(x.target || '')}">${esc(x.target || '')}</td>
            <td class="min-w-64 whitespace-normal"><span class="font-medium">${esc(x.title)}</span><br><span class="text-sm text-base-content/70">${esc(x.summary)}</span></td>
            <td class="text-right whitespace-nowrap"><div class="flex items-center justify-end gap-2">${moreInfo(x)}
              <button type="button" class="btn btn-xs btn-text btn-square" data-copy-step="${esc(x.id)}" title="Copy this message" aria-label="Copy this message"><span class="icon-[tabler--copy] size-4"></span></button>
              <button type="button" class="btn btn-xs btn-text btn-square text-primary" data-prompt-step="${esc(x.id)}" title="Copy an AI prompt for this issue" aria-label="Copy an AI prompt for this issue"><span class="icon-[tabler--sparkles] size-4"></span></button></div></td>
          </tr>`;
        }).join('')}</tbody>
      </table></div>
    </div>` : `<div class="alert alert-soft alert-success flex flex-row items-center gap-3"><span class="icon-[tabler--confetti] size-6"></span>No problems found. Everything checked passed.</div>`;

    const groups = cats.map((c) => `<section class="flex flex-col gap-2">
      <h3 class="mt-2 flex items-center gap-2 text-lg font-semibold text-base-content"><span class="${CATS[c].icon} size-5"></span>${CATS[c].name}</h3>
      ${list(rep.steps.filter((x) => x.category === c))}
    </section>`).join('');
    return cards + table + `<h2 class="mt-4 text-xl font-semibold text-base-content">All checks</h2>` + groups;
  }

  function moreInfo(st) {
    if (!st.moreInfo || !/^https?:\/\//.test(st.moreInfo)) return '';
    return `<a class="link link-primary inline-flex items-center gap-1 text-sm whitespace-nowrap" href="${esc(st.moreInfo)}" target="_blank" rel="noopener noreferrer"><span class="icon-[tabler--info-circle] size-4"></span>More info</a>`;
  }

  function renderStep(st) {
    const s = STATUS[st.status] || STATUS.info;
    const details = st.details?.length
      ? `<details data-details class="mt-2" ${tech.checked ? 'open' : ''}>
           <summary class="cursor-pointer text-xs text-base-content/60 select-none">Technical details</summary>
           <pre class="bg-base-200 rounded-field mt-2 overflow-x-auto p-3 font-mono text-xs leading-5 whitespace-pre-wrap break-all">${esc(st.details.join('\n'))}</pre>
         </details>` : '';
    return `<li class="flex gap-3 p-4 scroll-mt-24 transition-colors" id="step-${esc(st.id)}">
      <span class="${s.icon} ${s.color} mt-0.5 size-6 shrink-0" title="${s.label}"></span>
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-baseline justify-between gap-x-3">
          <h3 class="font-medium text-base-content">${esc(st.title)}${st.target ? ` <span class="badge badge-soft badge-sm ms-1 max-w-full truncate align-middle font-mono font-normal">${esc(st.target)}</span>` : ''}</h3>
          <span class="flex flex-wrap items-center gap-x-3 gap-y-1">
            ${moreInfo(st)}
            <button type="button" class="btn btn-xs btn-text" data-copy-step="${esc(st.id)}" title="Copy this message"><span class="icon-[tabler--copy] size-4"></span>Copy</button>
            ${st.status === 'fail' || st.status === 'warn' ? `<button type="button" class="btn btn-xs btn-text text-primary" data-prompt-step="${esc(st.id)}" title="Copy an AI prompt for fixing just this issue"><span class="icon-[tabler--sparkles] size-4"></span>AI prompt</button>` : ''}
            ${st.durationMs ? `<span class="text-xs tabular-nums text-base-content/50">${st.durationMs} ms</span>` : ''}
          </span>
        </div>
        ${st.summary ? `<p class="text-base-content/80">${esc(st.summary)}</p>` : ''}
        ${st.hint ? `<p class="bg-base-200 rounded-field mt-2 flex gap-2 p-2 text-sm"><span class="icon-[tabler--bulb] text-warning size-5 shrink-0"></span><span><b>What to do:</b> ${esc(st.hint)}</span></p>` : ''}
        ${details}
      </div>
    </li>`;
  }

  function renderLog(rep) {
    if (!rep.log?.length) return '';
    const lines = rep.log.map((l) => `<div class="log-line" data-dir="${esc(l.dir)}"><span class="t">${(l.ms / 1000).toFixed(3)}s</span><span class="d">${esc(l.dir)}</span><span>${esc(l.text)}</span></div>`).join('');
    return `<details data-details class="card" ${tech.checked ? 'open' : ''}>
      <summary class="flex cursor-pointer items-center gap-2 px-5 py-4 font-medium select-none">
        <span class="icon-[tabler--terminal-2] size-5"></span>Technical log
        <span class="badge badge-soft badge-sm">${rep.log.length} lines</span>
        <span class="flex-1"></span>
        <button type="button" class="btn btn-xs btn-soft" data-copy-log><span class="icon-[tabler--copy] size-4"></span>Copy</button>
        <button type="button" class="btn btn-xs btn-soft" data-download><span class="icon-[tabler--download] size-4"></span>JSON</button>
      </summary>
      <div class="border-base-content/10 max-h-128 overflow-y-auto border-t py-2">${lines}</div>
      <p class="px-5 py-2 text-xs text-base-content/50">› sent by us · ‹ received from server · * info · ! error. Passwords are hidden.</p>
    </details>`;
  }

  // Tool-specific summary blocks
  function renderExtra(rep) {
    const d = rep.data;
    if (!d) return '';
    const chip = (ok, text) => `<span class="badge badge-soft ${ok === true ? 'badge-success' : ok === false ? 'badge-error' : 'badge-neutral'}">${esc(text)}</span>`;
    switch (rep.tool) {
      case 'smtp': {
        if (!d.banner) return '';
        const c = [];
        c.push(chip(d.encrypted, d.encrypted ? `Encrypted${d.tls ? ' · ' + d.tls.version : ''}` : 'Not encrypted'));
        if (d.authUsed) c.push(chip(true, 'Login: ' + d.authUsed));
        if (d.accepted?.length) c.push(chip(true, `${d.accepted.length} recipient(s) accepted`));
        if (d.rejected?.length) c.push(chip(false, `${d.rejected.length} rejected`));
        if (d.sent) c.push(chip(true, 'Message accepted'));
        return `<div class="flex flex-wrap gap-2">${c.join('')}</div>`;
      }
      case 'ports': {
        if (!Array.isArray(d) || !d.length) return '';
        const stateBadge = { open: chip(true, 'Open'), closed: chip(false, 'Closed'), filtered: chip(false, 'Blocked'), error: chip(false, 'Error') };
        return `<div class="card overflow-x-auto"><table class="table">
          <thead><tr><th>Port</th><th>Used for</th><th>Result</th><th class="text-right">Time</th></tr></thead>
          <tbody>${d.map((p) => `<tr><td class="font-mono">${p.port}</td><td>${esc(p.service)}</td><td>${stateBadge[p.state] || esc(p.state)}</td><td class="text-right tabular-nums">${p.latencyMs} ms</td></tr>`).join('')}</tbody>
        </table></div>`;
      }
      case 'tls': {
        const i = d.info;
        if (!i?.chain?.length) return '';
        const leaf = i.chain[0];
        const row = (k, v) => `<tr><th class="w-40 font-normal text-base-content/60">${k}</th><td class="break-all">${v}</td></tr>`;
        return `<div class="card overflow-x-auto"><div class="card-body">
          <h3 class="card-title"><span class="icon-[tabler--certificate] size-6"></span>${esc(leaf.subject || '(no name)')}</h3>
          <div class="flex flex-wrap gap-2">${chip(i.trusted, i.trusted ? 'Trusted' : 'Not trusted')}${chip(i.nameMatches, i.nameMatches ? 'Name matches' : 'Name mismatch')}${chip(leaf.daysLeft >= 14 ? true : false, leaf.daysLeft < 0 ? 'Expired' : leaf.daysLeft + ' days left')}${chip(null, i.version)}</div>
          <table class="table table-sm mt-2"><tbody>
            ${row('Covers names', esc((leaf.dnsNames || []).join(', ')))}
            ${row('Issued by', esc(leaf.issuer))}
            ${row('Valid from', esc(new Date(leaf.notBefore).toLocaleDateString()))}
            ${row('Valid until', esc(new Date(leaf.notAfter).toLocaleDateString()))}
            ${row('Cipher', esc(i.cipherSuite))}
            ${row('Chain', esc(i.chain.map((c) => c.subject || c.issuer).join(' → ')))}
          </tbody></table>
        </div></div>`;
      }
    }
    return '';
  }

  function bindResult(out, rep, tool) {
    const byId = Object.fromEntries(rep.steps.map((x) => [x.id, x]));
    $$('[data-copy-step]', out).forEach((b) => b.addEventListener('click', (e) => {
      e.stopPropagation();
      const st = byId[b.dataset.copyStep];
      if (st) copyText(stepText(st), b);
    }));
    $$('[data-prompt-step]', out).forEach((b) => b.addEventListener('click', (e) => {
      e.stopPropagation();
      const st = byId[b.dataset.promptStep];
      if (st) copyText(aiPrompt(tool, rep, [st]), b);
    }));
    $$('[data-jump]', out).forEach((row) => row.addEventListener('click', (e) => {
      if (e.target.closest('a, button')) return;
      const el = out.querySelector('#' + CSS.escape(row.dataset.jump));
      if (!el) return;
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      el.classList.add('bg-base-200');
      setTimeout(() => el.classList.remove('bg-base-200'), 1500);
    }));
    const copy = $('[data-copy-log]', out);
    copy?.addEventListener('click', async (e) => {
      e.preventDefault();
      const text = rep.log.map((l) => `${(l.ms / 1000).toFixed(3)}s ${l.dir} ${l.text}`).join('\n');
      copyText(text, copy);
    });
    $('[data-download]', out)?.addEventListener('click', (e) => {
      e.preventDefault();
      const blob = new Blob([JSON.stringify(rep, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `${rep.tool}-test-${new Date(rep.startedAt).toISOString().replace(/[:.]/g, '-')}.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });
  }

  // ------------------------------------------------------------ boot
  fetch('api/info').then((r) => r.json()).then((i) => { $('#version').textContent = 'Version ' + i.version; }).catch(() => {});
  paintThemeIcon();
  paintSidebar();
  route();
})();
