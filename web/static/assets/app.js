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

  // Mobile sidebar
  const sidebar = $('#sidebar'), backdrop = $('#backdrop');
  function closeMenu() { sidebar.classList.add('-translate-x-full'); backdrop.hidden = true; }
  $('#menu-toggle').addEventListener('click', () => { sidebar.classList.remove('-translate-x-full'); backdrop.hidden = false; });
  backdrop.addEventListener('click', closeMenu);

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
    domain: (f) => ({ domain: f.domain.value, selectors: f.selectors.value.split(/[\s,]+/).filter(Boolean), server: f.server.value }),
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
  $$('form[data-tool]').forEach((f) => {
    const tool = f.dataset.tool;
    const out = $(`[data-result="${tool}"]`);
    restoreForm(tool, f);
    out.replaceChildren($('#tpl-empty').content.cloneNode(true));

    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      saveForm(tool, f);
      const btn = $('button[type="submit"]', f);
      const label = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="loading loading-spinner"></span>Testing…';
      out.innerHTML = loadingCard(tool);
      try {
        const res = await fetch('api/' + tool, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(COLLECT[tool](f)),
        });
        if (!res.ok) throw new Error((await res.text()) || res.statusText);
        const rep = await res.json();
        out.innerHTML = renderReport(rep);
        bindResult(out, rep);
      } catch (err) {
        out.innerHTML = `<div class="alert alert-error"><span class="icon-[tabler--plug-x] size-6 shrink-0"></span>
          <div><h3 class="font-semibold">Couldn't reach the Email Test Tools app.</h3>
          <p class="text-sm">Is it still running? Restart it and reload this page.</p>
          <p class="mt-1 font-mono text-xs opacity-70">${esc(err.message)}</p></div></div>`;
      } finally {
        btn.disabled = false;
        btn.innerHTML = label;
        if (window.matchMedia('(max-width: 1279px)').matches) out.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  function loadingCard(tool) {
    const msg = { smtp: 'Talking to the mail server…', domain: 'Checking DNS records…', ports: 'Knocking on ports…', dns: 'Asking DNS…', tls: 'Inspecting the certificate…' }[tool];
    return `<div class="card"><div class="card-body flex-row items-center gap-4">
      <span class="loading loading-spinner loading-lg text-primary"></span>
      <div><p class="font-medium">${msg}</p><p class="text-sm text-base-content/60">This can take up to a minute if a server is slow to answer.</p></div>
    </div></div>`;
  }

  // ------------------------------------------------------------ rendering
  function renderReport(rep) {
    const s = STATUS[rep.status] || STATUS.info;
    const secs = (rep.durationMs / 1000).toFixed(1);
    return `
      <div class="flex flex-col gap-4">
        <div class="alert alert-soft ${s.alert} items-start">
          <span class="${s.icon} size-7 shrink-0"></span>
          <div class="min-w-0 flex-1">
            <h2 class="text-lg font-semibold">${esc(rep.headline)}</h2>
            ${rep.advice ? `<p class="mt-1">${esc(rep.advice)}</p>` : ''}
            <p class="mt-2 text-xs opacity-70">Finished in ${secs}s · ${new Date(rep.startedAt).toLocaleString()}</p>
          </div>
        </div>
        ${renderExtra(rep)}
        <div class="card"><div class="card-body p-0">
          <ol class="divide-base-content/10 divide-y">${rep.steps.map(renderStep).join('')}</ol>
        </div></div>
        ${renderLog(rep)}
      </div>`;
  }

  function renderStep(st) {
    const s = STATUS[st.status] || STATUS.info;
    const details = st.details?.length
      ? `<details data-details class="mt-2" ${tech.checked ? 'open' : ''}>
           <summary class="cursor-pointer text-xs text-base-content/60 select-none">Technical details</summary>
           <pre class="bg-base-200 rounded-field mt-2 overflow-x-auto p-3 font-mono text-xs leading-5 whitespace-pre-wrap break-all">${esc(st.details.join('\n'))}</pre>
         </details>` : '';
    return `<li class="flex gap-3 p-4">
      <span class="${s.icon} ${s.color} mt-0.5 size-6 shrink-0" title="${s.label}"></span>
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-baseline justify-between gap-x-3">
          <h3 class="font-medium text-base-content">${esc(st.title)}</h3>
          ${st.durationMs ? `<span class="text-xs tabular-nums text-base-content/50">${st.durationMs} ms</span>` : ''}
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
      <div class="border-base-content/10 max-h-[32rem] overflow-y-auto border-t py-2">${lines}</div>
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
      case 'domain': {
        const items = [
          ['MX', d.mx?.length > 0], ['SPF', !!d.spf], ['DKIM', Object.keys(d.dkim || {}).length > 0], ['DMARC', !!d.dmarc],
        ];
        return `<div class="grid grid-cols-2 gap-3 sm:grid-cols-4">${items.map(([k, ok]) => `
          <div class="card"><div class="card-body items-center p-4 text-center">
            <span class="${ok ? 'icon-[tabler--circle-check-filled] text-success' : 'icon-[tabler--circle-x-filled] text-error'} size-8"></span>
            <span class="font-semibold">${k}</span><span class="text-xs text-base-content/60">${ok ? 'found' : 'missing'}</span>
          </div></div>`).join('')}</div>`;
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

  function bindResult(out, rep) {
    const copy = $('[data-copy-log]', out);
    copy?.addEventListener('click', async (e) => {
      e.preventDefault();
      const text = rep.log.map((l) => `${(l.ms / 1000).toFixed(3)}s ${l.dir} ${l.text}`).join('\n');
      try { await navigator.clipboard.writeText(text); copy.innerHTML = '<span class="icon-[tabler--check] size-4"></span>Copied'; }
      catch { copy.textContent = 'Copy failed'; }
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
  route();
})();
