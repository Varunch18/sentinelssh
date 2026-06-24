/* Dashboard orchestration: initial REST load, live updates, modal, logout. */
(() => {
  const feedEl = document.getElementById('feed');
  const incidentsEl = document.getElementById('incidents');
  const alertsEl = document.getElementById('alerts');
  const commandsEl = document.getElementById('commands');
  let feedItems = [];
  let modal;

  // ---------- KPI / stats ----------
  function renderStats(s) {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('kpiTotal', s.total_attacks ?? 0);
    set('kpiLast24', 'last 24h: ' + (s.last_24h ?? 0));
    set('kpiActive', s.active_incidents ?? 0);
    set('kpiTotalInc', 'total: ' + (s.total_incidents ?? 0));
    set('kpiCritical', s.critical_incidents ?? 0);
    set('kpiUnique', s.unique_ips ?? 0);
    set('kpiTopCountry', 'top: ' + (s.top_country || '—'));
  }

  async function refreshStats() {
    try { renderStats(await API.get('/stats')); } catch (e) {}
  }

  async function refreshHealth() {
    try {
      const h = await API.get('/system-health');
      UI.setStatusDot(document.getElementById('hDb'), h.database);
      UI.setStatusDot(document.getElementById('hSocket'), h.socketio);
      UI.setStatusDot(document.getElementById('hHoney'), h.honeypot);
      UI.setStatusDot(document.getElementById('hEvent'), h.last_event ? 'online' : 'waiting');
      document.getElementById('hLastEvent').textContent = h.last_event ? 'last event: ' + UI.fmtAgo(h.last_event) : 'no events yet';
    } catch (e) {}
  }

  // ---------- Feed ----------
  function renderFeed() {
    feedEl.innerHTML = feedItems.length
      ? feedItems.map((a, i) => UI.feedRow(a, false)).join('')
      : '<div class="empty">Waiting for attacks…</div>';
  }
  async function loadFeed() {
    feedItems = await API.get('/recent?limit=25');
    renderFeed();
  }
  function prependAttack(a) {
    feedItems.unshift(a);
    feedItems = feedItems.slice(0, 40);
    feedEl.insertAdjacentHTML('afterbegin', UI.feedRow(a, true));
    const rows = feedEl.querySelectorAll('.feed-row');
    rows.forEach((r, i) => { if (i >= 40) r.remove(); });
    if (feedEl.querySelector('.empty')) feedEl.querySelector('.empty').remove();
  }

  // ---------- Incidents / alerts / intel / commands ----------
  async function loadIncidents() {
    const list = await API.get('/incidents?per_page=12&sort=last_seen&order=desc');
    incidentsEl.innerHTML = list.length ? list.map(UI.incidentItem).join('') : '<div class="empty">No incidents</div>';
  }
  async function loadAlerts() {
    const list = await API.get('/alerts?limit=12');
    alertsEl.innerHTML = list.length ? list.map(UI.alertRow).join('') : '<div class="empty">No high-risk alerts</div>';
  }
  async function loadIntel() {
    const [countries, usernames, passwords, mitre] = await Promise.all([
      API.get('/top-countries?limit=6'), API.get('/top-usernames?limit=6'),
      API.get('/top-passwords?limit=6'), API.get('/mitre?limit=6'),
    ]);
    document.getElementById('topCountries').innerHTML = UI.barList(countries);
    document.getElementById('topUsernames').innerHTML = UI.barList(usernames);
    document.getElementById('topPasswords').innerHTML = UI.barList(passwords);
    document.getElementById('topMitre').innerHTML = UI.barList(mitre);
  }
  async function loadCommands() {
    const cmds = await API.get('/commands?limit=20');
    commandsEl.innerHTML = cmds.length ? cmds.map(UI.commandRow).join('')
      : '<tr><td colspan="5" class="empty">No commands captured</td></tr>';
  }

  // ---------- Charts ----------
  async function loadCharts() {
    try {
      const [dist, countries, mitre, hourly] = await Promise.all([
        API.get('/risk-distribution'), API.get('/top-countries?limit=7'),
        API.get('/mitre?limit=7'), API.get('/attacks-per-hour?hours=24'),
      ]);
      Charts.updateRisk(dist.by_level);
      Charts.updateCountries(countries);
      Charts.updateMitre(mitre);
      Charts.updateHourly(hourly);
    } catch (e) {}
  }

  // ---------- Modal: attack details + timeline ----------
  function buildTimeline(a) {
    const items = [];
    const t0 = a.timestamp;
    items.push({ cls: '', time: t0, title: 'Connection Established', desc: `${a.source_ip}${a.country ? ' · ' + a.country : ''} · ${a.ssh_version || 'unknown client'}` });
    items.push({ cls: 'auth', time: t0, title: 'Authentication Attempt', desc: `${UI.escapeHtml(a.username || '—')} / ${UI.escapeHtml(a.password || '—')} · ${a.auth_attempts} attempt(s)` });
    (a.commands || []).forEach((c) => {
      items.push({ cls: 'cmd', time: c.timestamp, title: 'Command Executed', desc: `<code>${UI.escapeHtml(c.command)}</code> <span class="tag">${c.command_type}</span>` });
    });
    if (a.behaviors && a.behaviors.length) {
      items.push({ cls: 'behavior', time: t0, title: 'Behaviors Detected', desc: a.behaviors.map((b) => `<span class="tag">${UI.escapeHtml(b)}</span>`).join(' ') });
    }
    const end = a.timestamp ? new Date(new Date(a.timestamp).getTime() + (a.duration || 0) * 1000).toISOString() : null;
    items.push({ cls: 'disconnect', time: end, title: 'Disconnect', desc: `session closed after ${(a.duration || 0).toFixed(2)}s` });
    return `<div class="timeline">${items.map((i) => `
      <div class="tl-item ${i.cls}">
        <div class="tl-time">${UI.fmtTime(i.time)}</div>
        <div class="tl-title">${i.title}</div>
        <div class="tl-desc">${i.desc}</div>
      </div>`).join('')}</div>`;
  }

  async function openAttack(id) {
    try {
      const a = await API.get('/attacks/' + id);
      document.getElementById('modalTitle').innerHTML = `Attack #${a.id} — ${UI.escapeHtml(a.source_ip)} ${UI.sevBadge(a.risk_score)}`;
      const mitre = (a.mitre || []).map((m) => `<span class="tag mitre" title="${UI.escapeHtml(m.tactic)}">${UI.escapeHtml(m.id)} ${UI.escapeHtml(m.name)}</span>`).join(' ') || '—';
      const behaviors = (a.behaviors || []).map((b) => `<span class="tag">${UI.escapeHtml(b)}</span>`).join(' ') || '—';
      document.getElementById('modalBody').innerHTML = `
        <div class="kv">
          <b>${UI.escapeHtml(a.country || 'Unknown')}</b> · ASN ${UI.escapeHtml(a.asn || '—')} · ${UI.escapeHtml(a.isp || '—')}<br/>
          user <b>${UI.escapeHtml(a.username || '—')}</b> / pass <b>${UI.escapeHtml(a.password || '—')}</b> ·
          ${UI.escapeHtml(a.ssh_version || '—')} · ${a.duration?.toFixed ? a.duration.toFixed(2) : a.duration}s ·
          ${a.is_malicious ? '<span class="tag" style="color:#fca5a5;border-color:#7f1d1d">malicious source</span>' : ''}
          ${a.incident_id ? ' · incident #' + a.incident_id : ''}
        </div>
        <div class="detail-section"><h4>MITRE ATT&CK Techniques</h4><div>${mitre}</div></div>
        <div class="detail-section"><h4>Behaviors Detected</h4><div>${behaviors}</div></div>
        <div class="detail-section"><h4>Attack Timeline</h4>${buildTimeline(a)}</div>`;
      modal.show();
    } catch (e) { console.error(e); }
  }

  // ---------- Events ----------
  function bindClicks() {
    feedEl.addEventListener('click', (e) => { const r = e.target.closest('[data-attack]'); if (r) openAttack(r.dataset.attack); });
    alertsEl.addEventListener('click', (e) => { const r = e.target.closest('[data-attack]'); if (r) openAttack(r.dataset.attack); });
    incidentsEl.addEventListener('click', async (e) => {
      const r = e.target.closest('[data-incident]'); if (!r) return;
      try { const inc = await API.get('/incidents/' + r.dataset.incident);
        if (inc.related_attacks && inc.related_attacks.length) openAttack(inc.related_attacks[0].id);
      } catch (err) {}
    });
  }

  let chartRefresh;
  function scheduleChartRefresh() {
    clearTimeout(chartRefresh);
    chartRefresh = setTimeout(loadCharts, 1500);
  }

  // ---------- Live handlers ----------
  const liveHandlers = {
    onAttack(a) { prependAttack(a); loadCommands(); loadAlerts(); scheduleChartRefresh(); },
    onStats(s) { renderStats(s); refreshHealth(); },
    onIncident() { loadIncidents(); },
  };

  // ---------- Init ----------
  async function init() {
    modal = new bootstrap.Modal(document.getElementById('attackModal'));
    document.getElementById('logoutBtn').addEventListener('click', async () => {
      try { await API.post('/auth/logout'); } catch (e) {}
      window.location.href = '/login';
    });
    try { const me = await API.get('/auth/me'); document.getElementById('userName').textContent = me.username; } catch (e) {}

    Charts.init();
    bindClicks();
    await Promise.all([refreshStats(), refreshHealth(), loadFeed(), loadIncidents(), loadAlerts(), loadIntel(), loadCommands(), loadCharts()]);
    Live.connect(liveHandlers);

    // Periodic safety refresh (in case a socket event is missed).
    setInterval(() => { refreshHealth(); }, 30000);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
