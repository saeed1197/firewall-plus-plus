'use strict';

/* ------------------------------------------------------------ session token
   The launcher puts the token in the URL fragment, which never travels to the
   server or into logs. We stash it for this tab and scrub it from the bar. */
const TOKEN = (() => {
  const fromHash = location.hash.replace(/^#/, '').trim();
  if (fromHash) {
    sessionStorage.setItem('fwToken', fromHash);
    history.replaceState(null, '', location.pathname);
    return fromHash;
  }
  return sessionStorage.getItem('fwToken') || '';
})();

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const arr = v => (v == null ? [] : Array.isArray(v) ? v : [v]);

const state = {
  rules: [], filtered: [], selected: new Set(),
  sort: { key: 'displayName', dir: 1 }, renderCap: 300,
  status: null, conns: [], readOnly: false,
  editing: null, timers: {},
};

/* ------------------------------------------------------------------- api */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers: { 'X-FW-Token': TOKEN, ...(opts.body ? { 'Content-Type': 'application/json' } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (opts.raw) {
    if (!res.ok) throw new Error(await res.text());
    return res;
  }
  let data;
  try { data = await res.json(); } catch { throw new Error(`Server returned ${res.status}`); }
  if (!res.ok || data.error) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

/* ------------------------------------------------------------ ui helpers */
function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, kind === 'err' ? 6000 : 3000);
  setTimeout(() => el.remove(), kind === 'err' ? 6400 : 3400);
}
const fail = e => toast(e.message || String(e), 'err');

function confirmAsk(title, body, yesLabel = 'Confirm') {
  return new Promise(resolve => {
    $('#confirmTitle').textContent = title;
    $('#confirmBody').textContent = body;
    $('#confirmYes').textContent = yesLabel;
    $('#confirmBackdrop').classList.add('show');
    const done = v => {
      $('#confirmBackdrop').classList.remove('show');
      $('#confirmYes').onclick = $('#confirmNo').onclick = null;
      resolve(v);
    };
    $('#confirmYes').onclick = () => done(true);
    $('#confirmNo').onclick = () => done(false);
  });
}

/* ------------------------------------------------------------------ tabs */
$('#tabs').addEventListener('click', e => {
  const btn = e.target.closest('button[data-tab]');
  if (!btn) return;
  $$('#tabs button').forEach(b => b.classList.toggle('active', b === btn));
  $$('.tabpane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + btn.dataset.tab));
  const load = { connections: loadConnections, log: loadLog, tools: loadTools };
  if (load[btn.dataset.tab]) load[btn.dataset.tab]();
});

/* ------------------------------------------------------------- dashboard */
async function loadStatus() {
  const s = await api('/api/status');
  state.status = s;
  state.readOnly = !s.elevated;

  $('#hostLabel').textContent = `${s.computer} · PowerShell ${s.psVersion}`;
  const badge = $('#modeBadge');
  badge.className = 'badge ' + (s.elevated ? 'badge-ok' : 'badge-warn');
  badge.textContent = s.elevated ? 'Administrator' : 'Read-only';
  badge.title = s.elevated ? 'Changes will be applied' : 'Restart the launcher elevated to make changes';

  const activeCats = new Set(arr(s.connections).map(c => c.category));
  $('#profileCards').innerHTML = arr(s.profiles).map(p => {
    const live = activeCats.has(p.name);
    return `
    <div class="pcard ${p.enabled ? 'on' : 'off'} ${live ? 'active-net' : ''}">
      <header>
        <h2>${p.name}
          <span class="badge ${p.enabled ? 'badge-ok' : 'badge-danger'}">${p.enabled ? 'On' : 'Off'}</span>
        </h2>
        ${live ? '<span class="netnote">● active network</span>' : ''}
      </header>
      <div class="prow"><span>Firewall</span>
        <button class="btn btn-sm ${p.enabled ? '' : 'btn-ok'}" data-prof="${p.name}" data-set="enabled" data-val="${!p.enabled}">
          ${p.enabled ? 'Turn off' : 'Turn on'}</button></div>
      <div class="prow"><span>Inbound default</span>
        <select data-prof="${p.name}" data-set="defaultInbound">
          ${['Block', 'Allow', 'NotConfigured'].map(v => `<option ${p.defaultInbound === v ? 'selected' : ''}>${v}</option>`).join('')}
        </select></div>
      <div class="prow"><span>Outbound default</span>
        <select data-prof="${p.name}" data-set="defaultOutbound">
          ${['Allow', 'Block', 'NotConfigured'].map(v => `<option ${p.defaultOutbound === v ? 'selected' : ''}>${v}</option>`).join('')}
        </select></div>
      <div class="prow"><span>Notify on block</span>
        <label class="chk"><input type="checkbox" data-prof="${p.name}" data-set="notifyOnListen" ${p.notifyOnListen ? 'checked' : ''}></label></div>
      <div class="prow"><span>Log dropped packets</span>
        <label class="chk"><input type="checkbox" data-prof="${p.name}" data-set="logBlocked" ${p.logBlocked ? 'checked' : ''}></label></div>
      <div class="prow"><span>Log allowed packets</span>
        <label class="chk"><input type="checkbox" data-prof="${p.name}" data-set="logAllowed" ${p.logAllowed ? 'checked' : ''}></label></div>
    </div>`;
  }).join('');

  const st = s.stats;
  $('#statGrid').innerHTML = [
    ['Total rules', st.total, ''],
    ['Enabled', st.enabled, ''],
    ['Inbound allows', st.openIn, ''],
    ['Block rules', st.block, ''],
    ['Group Policy', st.gpo, ''],
    ['Disabled', st.disabled, ''],
    ['Outbound', st.outbound, ''],
    ['Orphaned', st.orphan, st.orphan > 0 ? 'alert' : ''],
  ].map(([label, val, cls]) => `<div class="stat ${cls}"><b>${val}</b><span>${label}</span></div>`).join('');

  const bar = (label, parts) => {
    const total = parts.reduce((a, p) => a + p[0], 0) || 1;
    return `<div class="bar">
      <div class="lbl"><span>${label}</span><span>${parts.map(p => `${p[2]} ${p[0]}`).join(' · ')}</span></div>
      <div class="track">${parts.map(p => `<i style="width:${p[0] / total * 100}%;background:${p[1]}"></i>`).join('')}</div>
    </div>`;
  };
  $('#statBars').innerHTML =
    bar('Direction', [[st.inbound, 'var(--info)', 'in'], [st.outbound, 'var(--accent2)', 'out']]) +
    bar('Action', [[st.allow, 'var(--ok)', 'allow'], [st.block, 'var(--danger)', 'block']]) +
    bar('State', [[st.enabled, 'var(--ok)', 'on'], [st.disabled, '#39414d', 'off']]);
}

$('#profileCards').addEventListener('change', async e => {
  const el = e.target.closest('[data-prof]');
  if (!el || el.tagName === 'BUTTON') return;
  const body = { name: el.dataset.prof };
  body[el.dataset.set] = el.type === 'checkbox' ? el.checked : el.value;
  try {
    await api('/api/profile', { method: 'POST', body });
    toast(`${el.dataset.prof}: ${el.dataset.set} updated`, 'ok');
    loadStatus();
  } catch (err) { fail(err); loadStatus(); }
});

$('#profileCards').addEventListener('click', async e => {
  const btn = e.target.closest('button[data-prof]');
  if (!btn) return;
  if (btn.dataset.val === 'false' &&
      !(await confirmAsk('Turn the firewall off?',
        `Traffic on the ${btn.dataset.prof} profile will no longer be filtered. This leaves the machine exposed on that network.`,
        'Turn it off'))) return;
  try {
    await api('/api/profile', { method: 'POST', body: { name: btn.dataset.prof, enabled: btn.dataset.val === 'true' } });
    toast(`${btn.dataset.prof} firewall ${btn.dataset.val === 'true' ? 'enabled' : 'disabled'}`, 'ok');
    loadStatus();
  } catch (err) { fail(err); }
});

/* -------------------------------------------------------- quick actions */
$('.quick').addEventListener('click', async e => {
  const btn = e.target.closest('button[data-quick]');
  if (!btn) return;
  const kind = btn.dataset.quick;
  const body = { kind };

  if (kind === 'blockApp') {
    body.program = $('#qBlockApp').value.trim();
    body.directions = $('#qBlockDir').value;
    if (!body.program) return toast('Enter a program path first.', 'err');
  } else if (kind === 'allowApp') {
    body.program = $('#qAllowApp').value.trim();
    body.directions = $('#qAllowDir').value;
    if (!body.program) return toast('Enter a program path first.', 'err');
  } else if (kind === 'blockIp') {
    body.address = $('#qBlockIp').value.trim();
    if (!body.address) return toast('Enter an address or range first.', 'err');
  } else if (kind === 'openPort') {
    body.port = $('#qPort').value.trim();
    body.protocol = $('#qProto').value;
    body.remoteAddress = $('#qScope').value.trim() || 'Any';
    if (!body.port) return toast('Enter a port first.', 'err');
    if (body.remoteAddress.toLowerCase() === 'any' &&
        !(await confirmAsk('Open this port to the whole internet?',
          `Nothing will restrict who can reach ${body.protocol} port ${body.port}. Consider scoping it to LocalSubnet or a specific address.`,
          'Open it anyway'))) return;
  } else if (kind === 'panic') {
    if (!(await confirmAsk('Lock down all network traffic?',
      'Every profile will be switched on with both inbound and outbound defaults set to Block. Only traffic matching an explicit allow rule will pass - remote sessions and internet access will drop immediately.',
      'Lock it down'))) return;
  } else if (kind === 'restoreDefaults') {
    if (!(await confirmAsk('Restore Windows default posture?',
      'All three profiles: firewall on, inbound Block, outbound Allow. Your rules are not touched.',
      'Restore'))) return;
  }

  try {
    const r = await api('/api/quick', { method: 'POST', body });
    toast(r.created ? `Created ${r.created.length} rule(s).` : 'Done.', 'ok');
    await loadStatus();
    if (state.rules.length) loadRules(true);
  } catch (err) { fail(err); }
});

/* ---------------------------------------------------------------- audit */
$('#auditRun').addEventListener('click', async () => {
  $('#auditOut').innerHTML = '<div class="loading">Reviewing rules…</div>';
  try {
    const a = await api('/api/audit');
    const f = arr(a.findings);
    $('#auditSummary').innerHTML =
      `<span class="badge badge-danger">${a.summary.high} high</span>
       <span class="badge badge-warn">${a.summary.warn} warn</span>
       <span class="badge badge-muted">${a.summary.info} info</span>`;
    if (!f.length) { $('#auditOut').innerHTML = '<p class="muted">Nothing flagged. Your rule set looks tidy.</p>'; return; }
    const order = { high: 0, warn: 1, info: 2 };
    f.sort((x, y) => order[x.severity] - order[y.severity]);
    $('#auditOut').innerHTML = f.map(x => `
      <div class="finding ${x.severity}">
        <div class="f-main">
          <div class="f-kind">${esc(x.kind)}</div>
          <div class="f-rule">${esc(x.rule)}</div>
          <div class="f-detail">${esc(x.detail)}</div>
        </div>
        <button class="btn btn-sm" data-goto="${esc(x.name)}">Inspect</button>
      </div>`).join('') +
      (a.truncated > 0
        ? `<p class="muted">${a.truncated} further finding(s) not listed - clear the ones above and re-run.</p>`
        : '');
  } catch (err) { fail(err); $('#auditOut').innerHTML = ''; }
});

$('#auditOut').addEventListener('click', async e => {
  const btn = e.target.closest('button[data-goto]');
  if (!btn) return;
  $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === 'rules'));
  $$('.tabpane').forEach(p => p.classList.toggle('active', p.id === 'tab-rules'));
  if (!state.rules.length) await loadRules();
  const rule = state.rules.find(r => r.name === btn.dataset.goto);
  if (rule) openDrawer(rule);
});

/* ----------------------------------------------------------------- rules */
async function loadRules(force = false) {
  const store = $('#fStore').value;
  $('#rulesBody').innerHTML = '<tr><td colspan="12" class="loading">Reading firewall rules…</td></tr>';
  try {
    const d = await api(`/api/rules?store=${store}${force ? '&refresh=1' : ''}`);
    state.rules = arr(d.rules);
    const cur = $('#fGroup').value;
    $('#fGroup').innerHTML = '<option value="">Any group</option>' +
      arr(d.groups).map(g => `<option ${g === cur ? 'selected' : ''}>${esc(g)}</option>`).join('');
    renderRules();
  } catch (err) {
    fail(err);
    $('#rulesBody').innerHTML = `<tr><td colspan="12" class="loading">${esc(err.message)}</td></tr>`;
  }
}

function ruleMatches(r, q) {
  if ($('#fDirection').value && r.direction !== $('#fDirection').value) return false;
  if ($('#fAction').value && r.action !== $('#fAction').value) return false;
  const en = $('#fEnabled').value;
  if (en === '1' && !r.enabled) return false;
  if (en === '0' && r.enabled) return false;
  const pf = $('#fProfile').value;
  if (pf && r.profile !== 'Any' && !r.profile.includes(pf)) return false;
  if ($('#fGroup').value && r.group !== $('#fGroup').value) return false;
  if (!q) return true;
  return [r.displayName, r.description, r.program, r.service, r.localPort, r.remotePort,
          r.localAddress, r.remoteAddress, r.group, r.protocol]
    .join(' ').toLowerCase().includes(q);
}

function renderRules() {
  const q = $('#ruleSearch').value.trim().toLowerCase();
  const { key, dir } = state.sort;
  state.filtered = state.rules.filter(r => ruleMatches(r, q)).sort((a, b) => {
    const x = String(a[key] ?? '').toLowerCase(), y = String(b[key] ?? '').toLowerCase();
    return x < y ? -dir : x > y ? dir : 0;
  });

  // A machine can easily carry 800+ rules; rendering every row at once makes
  // the table janky, so we paint a window of them and let filters narrow it.
  const shown = state.filtered.slice(0, state.renderCap);
  const cell = v => (v === 'Any' || v === '' ? '<span class="muted">Any</span>' : esc(v));
  $('#rulesBody').innerHTML = shown.map(r => `
    <tr data-name="${esc(r.name)}" class="${r.enabled ? '' : 'off'} ${state.selected.has(r.name) ? 'sel' : ''}">
      <td class="c-check"><input type="checkbox" ${state.selected.has(r.name) ? 'checked' : ''} ${r.readOnly ? 'disabled' : ''}></td>
      <td class="c-on"><button class="switch" data-toggle title="${r.enabled ? 'Disable' : 'Enable'}"><span class="dot ${r.enabled ? 'on' : 'off'}"></span></button></td>
      <td><span class="nm">${esc(r.displayName)}${r.readOnly ? ' <span class="lock" title="From Group Policy - read-only">🔒</span>' : ''}
        ${r.programMissing ? ' <span class="lock" title="Program path no longer exists">⚠</span>' : ''}
        ${r.group ? `<small>${esc(r.group)}</small>` : ''}</span></td>
      <td class="c-sm"><span class="dir ${r.direction === 'Inbound' ? 'in' : 'out'}">${r.direction === 'Inbound' ? 'In' : 'Out'}</span></td>
      <td class="c-sm"><span class="badge ${r.action === 'Allow' ? 'badge-ok' : 'badge-danger'}">${esc(r.action)}</span></td>
      <td class="c-sm mono">${cell(r.protocol)}</td>
      <td class="mono">${cell(r.localPort)}</td>
      <td class="mono">${cell(r.remotePort)}</td>
      <td class="mono"><span class="trunc">${cell(r.remoteAddress)}</span></td>
      <td class="mono"><span class="trunc" title="${esc(r.program)}">${cell(r.program)}</span></td>
      <td class="c-sm">${esc(r.profile)}</td>
      <td class="c-sm"><button class="btn btn-sm" data-edit>Edit</button></td>
    </tr>`).join('') || '<tr><td colspan="12" class="loading">No rules match these filters.</td></tr>';

  const more = state.filtered.length - shown.length;
  $('#ruleCount').innerHTML = more > 0
    ? `Showing ${shown.length} of ${state.filtered.length} matching rules (${state.rules.length} total) -
       <a href="#" id="showMore">show ${Math.min(more, 500)} more</a> or narrow the filters`
    : `${state.filtered.length} of ${state.rules.length} rules shown`;
  const link = $('#showMore');
  if (link) link.onclick = e => { e.preventDefault(); state.renderCap += 500; renderRules(); };
  updateBulkbar();
}

function updateBulkbar() {
  const n = state.selected.size;
  $('#selCount').textContent = `${n} selected`;
  $('#bulkbar').classList.toggle('show', n > 0);
}

['#ruleSearch', '#fDirection', '#fAction', '#fEnabled', '#fProfile', '#fGroup'].forEach(sel => {
  $(sel).addEventListener('input', renderRules);
});
$('#fStore').addEventListener('change', () => { state.selected.clear(); loadRules(true); });

$$('#rulesTable thead th[data-sort]').forEach(th => th.addEventListener('click', () => {
  const k = th.dataset.sort;
  state.sort = { key: k, dir: state.sort.key === k ? -state.sort.dir : 1 };
  renderRules();
}));

$('#selAll').addEventListener('change', e => {
  state.filtered.forEach(r => {
    if (r.readOnly) return;
    e.target.checked ? state.selected.add(r.name) : state.selected.delete(r.name);
  });
  renderRules();
});
$('#selClear').addEventListener('click', () => { state.selected.clear(); renderRules(); });

$('#rulesBody').addEventListener('click', async e => {
  const tr = e.target.closest('tr[data-name]');
  if (!tr) return;
  const rule = state.rules.find(r => r.name === tr.dataset.name);
  if (!rule) return;

  if (e.target.matches('input[type=checkbox]')) {
    e.target.checked ? state.selected.add(rule.name) : state.selected.delete(rule.name);
    tr.classList.toggle('sel', e.target.checked);
    updateBulkbar();
    return;
  }
  if (e.target.closest('[data-toggle]')) {
    if (rule.readOnly) return toast('Group Policy rules cannot be changed here.', 'err');
    try {
      await api('/api/rules/bulk', { method: 'POST', body: { op: rule.enabled ? 'disable' : 'enable', names: [rule.name] } });
      rule.enabled = !rule.enabled;
      renderRules();
      toast(`${rule.displayName} ${rule.enabled ? 'enabled' : 'disabled'}`, 'ok');
    } catch (err) { fail(err); }
    return;
  }
  if (e.target.closest('[data-edit]')) openDrawer(rule);
});

$('#bulkbar').addEventListener('click', async e => {
  const btn = e.target.closest('button[data-bulk]');
  if (!btn) return;
  const op = btn.dataset.bulk;
  const names = [...state.selected];
  if (!names.length) return;
  if (op === 'delete' && !(await confirmAsk('Delete these rules?',
    `${names.length} rule(s) will be permanently removed. Consider creating a backup first (Tools tab).`, 'Delete'))) return;
  try {
    const r = await api('/api/rules/bulk', { method: 'POST', body: { op, names } });
    toast(`${r.changed} rule(s) updated` + (arr(r.errors).length ? `, ${arr(r.errors).length} failed` : ''), 'ok');
    arr(r.errors).slice(0, 3).forEach(x => toast(x, 'err'));
    state.selected.clear();
    await loadRules(true);
    loadStatus();
  } catch (err) { fail(err); }
});

/* ---------------------------------------------------------- rule drawer */
function openDrawer(rule) {
  state.editing = rule || null;
  const r = rule || {
    displayName: '', description: '', enabled: true, direction: 'Inbound', action: 'Allow',
    protocol: 'Any', localPort: 'Any', remotePort: 'Any', localAddress: 'Any', remoteAddress: 'Any',
    program: 'Any', service: 'Any', groupRaw: '', profile: 'Any', edge: 'Block', interfaceType: 'Any',
  };
  $('#drawerTitle').textContent = rule ? 'Edit rule' : 'New rule';
  $('#eDelete').style.display = rule ? '' : 'none';
  $('#drawerWarn').innerHTML = rule && rule.readOnly
    ? '<div class="warnbox">This rule comes from Group Policy or the effective (merged) store. It is read-only here - edit it in the GPO, or switch the store filter back to "Local rules".</div>'
    : (state.readOnly ? '<div class="warnbox">The console is running without Administrator rights, so saving will be refused.</div>' : '');

  $('#eName').value = r.displayName;
  $('#eDesc').value = r.description;
  $('#eEnabled').value = String(!!r.enabled);
  $('#eDirection').value = r.direction;
  $('#eAction').value = r.action;
  $('#eProtocol').value = ['Any', 'TCP', 'UDP', 'ICMPv4', 'ICMPv6'].includes(r.protocol) ? r.protocol : 'Any';
  $('#eLocalPort').value = r.localPort;
  $('#eRemotePort').value = r.remotePort;
  $('#eLocalAddress').value = r.localAddress;
  $('#eRemoteAddress').value = r.remoteAddress;
  $('#eProgram').value = r.program;
  $('#eService').value = r.service;
  $('#eGroup').value = r.groupRaw || '';
  $('#eEdge').value = ['Block', 'Allow', 'DeferToUser', 'DeferToApp'].includes(r.edge) ? r.edge : 'Block';
  $('#eInterface').value = ['Any', 'Wired', 'Wireless', 'RemoteAccess'].includes(r.interfaceType) ? r.interfaceType : 'Any';
  const profs = r.profile === 'Any' ? ['Domain', 'Private', 'Public'] : r.profile.split(',').map(s => s.trim());
  $$('.eProf').forEach(c => { c.checked = profs.includes(c.value); });

  const ro = !!(rule && rule.readOnly);
  $$('#drawer input, #drawer select, #drawer textarea').forEach(el => { el.disabled = ro; });
  $('#eSave').disabled = ro;
  $('#eDelete').disabled = ro;
  $('#eGroup').disabled = ro || !!rule;   // Group cannot be changed after creation.

  $('#drawer').classList.add('show');
  $('#drawerBackdrop').classList.add('show');
}

function closeDrawer() {
  $('#drawer').classList.remove('show');
  $('#drawerBackdrop').classList.remove('show');
  state.editing = null;
}
$('#drawerClose').onclick = $('#eCancel').onclick = $('#drawerBackdrop').onclick = closeDrawer;
$('#newRuleBtn').onclick = () => openDrawer(null);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

$('#eSave').addEventListener('click', async () => {
  const picked = $$('.eProf').filter(c => c.checked).map(c => c.value);
  const body = {
    displayName: $('#eName').value.trim(),
    description: $('#eDesc').value,
    enabled: $('#eEnabled').value === 'true',
    direction: $('#eDirection').value,
    action: $('#eAction').value,
    protocol: $('#eProtocol').value,
    localPort: $('#eLocalPort').value.trim(),
    remotePort: $('#eRemotePort').value.trim(),
    localAddress: $('#eLocalAddress').value.trim(),
    remoteAddress: $('#eRemoteAddress').value.trim(),
    program: $('#eProgram').value.trim(),
    service: $('#eService').value.trim(),
    edge: $('#eEdge').value,
    interfaceType: $('#eInterface').value,
    profile: picked.length === 3 || picked.length === 0 ? 'Any' : picked.join(','),
  };
  if (!body.displayName) return toast('A rule name is required.', 'err');

  try {
    if (state.editing) {
      body.name = state.editing.name;
      await api('/api/rules/update', { method: 'POST', body });
      toast('Rule saved.', 'ok');
    } else {
      body.group = $('#eGroup').value.trim();
      await api('/api/rules', { method: 'POST', body });
      toast('Rule created.', 'ok');
    }
    closeDrawer();
    await loadRules(true);
    loadStatus();
  } catch (err) { fail(err); }
});

$('#eDelete').addEventListener('click', async () => {
  if (!state.editing) return;
  if (!(await confirmAsk('Delete this rule?', `"${state.editing.displayName}" will be permanently removed.`, 'Delete'))) return;
  try {
    await api('/api/rules/bulk', { method: 'POST', body: { op: 'delete', names: [state.editing.name] } });
    toast('Rule deleted.', 'ok');
    closeDrawer();
    await loadRules(true);
    loadStatus();
  } catch (err) { fail(err); }
});

/* ----------------------------------------------------------- connections */
async function loadConnections() {
  $('#connBody').innerHTML = '<tr><td colspan="8" class="loading">Enumerating sockets…</td></tr>';
  try {
    const d = await api('/api/connections');
    state.conns = arr(d.connections);
    renderConnections();
  } catch (err) { fail(err); }
}

function renderConnections() {
  const q = $('#connSearch').value.trim().toLowerCase();
  const st = $('#connState').value, pr = $('#connProto').value;
  const rows = state.conns.filter(c => {
    if (pr && c.protocol !== pr) return false;
    if (st && c.state !== st) return false;
    if (!q) return true;
    return `${c.process} ${c.path} ${c.localAddress} ${c.remoteAddress} ${c.localPort} ${c.remotePort}`.toLowerCase().includes(q);
  }).sort((a, b) => (a.process || '').localeCompare(b.process || '') || a.localPort - b.localPort);

  $('#connBody').innerHTML = rows.map(c => `
    <tr>
      <td class="c-sm mono">${c.protocol}</td>
      <td class="mono">${esc(c.localAddress)}:<b>${c.localPort}</b></td>
      <td class="mono">${c.remotePort ? `${esc(c.remoteAddress)}:${c.remotePort}` : '<span class="muted">-</span>'}</td>
      <td class="c-sm">${c.state === 'Listen' ? '<span class="badge badge-info">Listen</span>' : esc(c.state)}</td>
      <td class="c-sm mono">${c.pid}</td>
      <td>${esc(c.process)}</td>
      <td class="mono"><span class="trunc" title="${esc(c.path)}">${esc(c.path) || '<span class="muted">-</span>'}</span></td>
      <td class="c-actions">
        <div style="display:flex;flex-wrap:wrap;gap:6px;">
          ${c.path ? `<button class="btn btn-sm btn-danger" data-cblock="${esc(c.path)}">Block app</button>` : ''}
          ${c.remoteAddress && !['*', '0.0.0.0', '::', '127.0.0.1'].includes(c.remoteAddress)
            ? `<button class="btn btn-sm" data-cip="${esc(c.remoteAddress)}">Block IP</button>` : ''}
        </div>
      </td>
    </tr>`).join('') || '<tr><td colspan="8" class="loading">No sockets match.</td></tr>';
  $('#connCount').textContent = `${rows.length} of ${state.conns.length} sockets`;
}

['#connSearch', '#connState', '#connProto'].forEach(s => $(s).addEventListener('input', renderConnections));
$('#connRefresh').addEventListener('click', loadConnections);
$('#connAuto').addEventListener('change', e => {
  clearInterval(state.timers.conn);
  if (e.target.checked) state.timers.conn = setInterval(loadConnections, 5000);
});

$('#connBody').addEventListener('click', async e => {
  const app = e.target.closest('[data-cblock]'), ip = e.target.closest('[data-cip]');
  if (!app && !ip) return;
  const what = app ? app.dataset.cblock : ip.dataset.cip;
  if (!(await confirmAsk(app ? 'Block this program?' : 'Block this address?',
    app ? `Outbound traffic from ${what} will be blocked.` : `Inbound and outbound traffic to ${what} will be blocked.`,
    'Create block rule'))) return;
  try {
    await api('/api/quick', {
      method: 'POST',
      body: app ? { kind: 'blockApp', program: what, directions: 'Outbound' } : { kind: 'blockIp', address: what },
    });
    toast('Block rule created.', 'ok');
    if (state.rules.length) loadRules(true);
  } catch (err) { fail(err); }
});

/* ------------------------------------------------------------------ log */
async function loadLog() {
  try {
    const d = await api('/api/log?take=500&filter=' + encodeURIComponent($('#logFilter').value.trim()));
    $('#logNotice').innerHTML = d.available
      ? `<p class="muted">Reading <code>${esc(d.path)}</code> - ${d.total} lines on disk.</p>`
      : `<div class="warnbox">${esc(d.message)}</div>`;
    const rows = arr(d.entries);
    $('#logBody').innerHTML = rows.map(e => `
      <tr>
        <td class="c-sm mono">${esc(e.time)}</td>
        <td class="c-sm"><span class="badge ${e.action === 'DROP' ? 'badge-danger' : 'badge-ok'}">${esc(e.action)}</span></td>
        <td class="c-sm mono">${esc(e.protocol)}</td>
        <td class="mono">${esc(e.srcIp)}:${esc(e.srcPort)}</td>
        <td class="mono">${esc(e.dstIp)}:${esc(e.dstPort)}</td>
        <td class="c-sm mono">${esc(e.size)}</td>
        <td class="mono"><span class="trunc">${esc(e.path)}</span></td>
        <td class="c-actions"><button class="btn btn-sm" data-lblock="${esc(e.dstIp)}">Block dest</button></td>
      </tr>`).join('') || '<tr><td colspan="8" class="loading">No log entries.</td></tr>';
    $('#logCount').textContent = `${rows.length} entries (newest first)`;
  } catch (err) { fail(err); }
}

$('#logRefresh').addEventListener('click', loadLog);
$('#logFilter').addEventListener('input', () => {
  clearTimeout(state.timers.logDebounce);
  state.timers.logDebounce = setTimeout(loadLog, 350);
});
$('#logAuto').addEventListener('change', e => {
  clearInterval(state.timers.log);
  if (e.target.checked) state.timers.log = setInterval(loadLog, 5000);
});
$('#logEnable').addEventListener('click', async () => {
  try {
    for (const name of ['Domain', 'Private', 'Public']) {
      await api('/api/profile', { method: 'POST', body: { name, logBlocked: true, logMaxKb: 16384 } });
    }
    toast('Dropped-packet logging enabled on all profiles (16 MB cap).', 'ok');
    setTimeout(loadLog, 800);
    loadStatus();
  } catch (err) { fail(err); }
});
$('#logBody').addEventListener('click', async e => {
  const btn = e.target.closest('[data-lblock]');
  if (!btn) return;
  const ip = btn.dataset.lblock;
  if (!(await confirmAsk('Block this address?', `Inbound and outbound traffic to ${ip} will be blocked.`, 'Create block rule'))) return;
  try {
    await api('/api/quick', { method: 'POST', body: { kind: 'blockIp', address: ip } });
    toast('Block rule created.', 'ok');
  } catch (err) { fail(err); }
});

/* ---------------------------------------------------------------- tools */
async function loadTools() { loadBackups(); loadHistory(); }

async function loadBackups() {
  try {
    const d = await api('/api/backups');
    const b = arr(d.backups);
    $('#backupList').innerHTML = b.map(x => `
      <div class="backuprow">
        <span class="bname" title="${esc(x.path)}">${esc(x.name)}</span>
        <span class="muted">${esc(x.modified)} · ${x.sizeKb} KB</span>
        <button class="btn btn-sm" data-restore="${esc(x.path)}">Restore</button>
      </div>`).join('') || '<p class="muted">No backups yet.</p>';
  } catch (err) { fail(err); }
}

$('#backupBtn').addEventListener('click', async () => {
  try {
    const r = await api('/api/backup', { method: 'POST' });
    toast('Backup written to ' + r.path, 'ok');
    loadBackups();
  } catch (err) { fail(err); }
});

$('#backupList').addEventListener('click', async e => {
  const btn = e.target.closest('[data-restore]');
  if (!btn) return;
  if (!(await confirmAsk('Restore this policy?',
    'The entire current firewall policy - every rule and profile setting - is replaced by the contents of this backup. This cannot be undone.',
    'Restore'))) return;
  try {
    await api('/api/restore', { method: 'POST', body: { path: btn.dataset.restore } });
    toast('Policy restored.', 'ok');
    await loadStatus();
    loadRules(true);
  } catch (err) { fail(err); }
});

$$('[data-export]').forEach(a => a.addEventListener('click', async () => {
  try {
    const res = await api('/api/export?format=' + a.dataset.export, { raw: true });
    const blob = await res.blob();
    const disp = res.headers.get('Content-Disposition') || '';
    const name = (disp.match(/filename="([^"]+)"/) || [, `firewall-rules.${a.dataset.export}`])[1];
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement('a'), { href: url, download: name });
    document.body.appendChild(link); link.click(); link.remove();
    URL.revokeObjectURL(url);
    toast('Exported ' + name, 'ok');
  } catch (err) { fail(err); }
}));

$('#wRun').addEventListener('click', async () => {
  const body = {
    direction: $('#wDirection').value, profile: $('#wProfile').value, protocol: $('#wProtocol').value,
    port: $('#wPort').value.trim(), address: $('#wAddress').value.trim(), program: $('#wProgram').value.trim(),
  };
  try {
    const r = await api('/api/whatif', { method: 'POST', body });
    const blocked = /block/i.test(r.verdict);
    const m = arr(r.matches);
    $('#wOut').innerHTML = `
      <div class="verdict ${blocked ? 'block' : 'allow'}">
        <div class="v-head">${esc(r.verdict)}</div>
        <div class="muted">${esc(r.reason)}</div>
        ${r.note ? `<div class="warnbox" style="margin-top:10px">${esc(r.note)}</div>` : ''}
        ${m.length ? `<ol>${m.slice(0, 40).map(x =>
          `<li><b>${x.action}</b> - ${esc(x.displayName)} <span class="muted">(${esc(x.protocol)} ${esc(x.localPort)}/${esc(x.remotePort)}, ${esc(x.profile)})</span></li>`).join('')}</ol>`
        : ''}
      </div>`;
  } catch (err) { fail(err); }
});

async function loadHistory() {
  try {
    const d = await api('/api/history');
    const e = arr(d.entries);
    $('#histBody').innerHTML = e.map(x => `
      <tr>
        <td class="c-sm mono">${esc(String(x.time).replace('T', ' ').slice(0, 19))}</td>
        <td>${esc(x.user)}</td>
        <td class="mono">${esc(x.action)}</td>
        <td><span class="trunc">${esc(x.target)}</span></td>
        <td class="c-sm"><span class="badge ${x.result === 'ok' ? 'badge-ok' : 'badge-warn'}">${esc(x.result)}</span></td>
      </tr>`).join('') || '<tr><td colspan="5" class="loading">No changes recorded yet.</td></tr>';
  } catch (err) { fail(err); }
}
$('#histRefresh').addEventListener('click', loadHistory);

/* ----------------------------------------------------------------- boot */
$('#refreshBtn').addEventListener('click', async () => {
  await loadStatus();
  if (state.rules.length) await loadRules(true);
  toast('Refreshed.', 'ok');
});

(async function boot() {
  if (!TOKEN) {
    document.body.innerHTML = '<div class="loading">No session token. Open the URL printed by the launcher window.</div>';
    return;
  }
  try {
    await loadStatus();
    await loadRules();
  } catch (err) { fail(err); }
})();

/* ---------------------------------------------------------- theme toggle */
(function initTheme() {
  const btn = $('#themeToggle');
  const html = document.documentElement;
  const saved = localStorage.getItem('fwTheme');
  if (saved === 'light') { html.dataset.theme = 'light'; btn.textContent = '☀️'; }

  btn.addEventListener('click', () => {
    if (html.dataset.theme === 'light') {
      delete html.dataset.theme;
      btn.textContent = '🌙';
      localStorage.setItem('fwTheme', 'dark');
    } else {
      html.dataset.theme = 'light';
      btn.textContent = '☀️';
      localStorage.setItem('fwTheme', 'light');
    }
  });
})();
