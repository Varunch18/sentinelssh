/* Pure rendering helpers + severity model (no network calls). */
const UI = (() => {
  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  // 4-tier severity from risk score. Critical=red High=orange Medium=yellow Low=blue
  function severity(score) {
    if (score >= 90) return { key: 'critical', label: 'CRITICAL' };
    if (score >= 71) return { key: 'high', label: 'HIGH' };
    if (score >= 31) return { key: 'medium', label: 'MEDIUM' };
    return { key: 'low', label: 'LOW' };
  }

  function sevBadge(score) {
    const s = severity(score);
    return `<span class="badge-sev sev-${s.key}">${s.label} ${score}</span>`;
  }

  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fmtAgo(iso) {
    if (!iso) return '—';
    const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (secs < 60) return Math.floor(secs) + 's ago';
    if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
    if (secs < 86400) return Math.floor(secs / 3600) + 'h ago';
    return Math.floor(secs / 86400) + 'd ago';
  }

  function mitreTags(mitre, max = 3) {
    if (!mitre || !mitre.length) return '';
    const shown = mitre.slice(0, max).map((m) => `<span class="tag mitre" title="${escapeHtml(m.name)}">${escapeHtml(m.id)}</span>`).join('');
    const more = mitre.length > max ? `<span class="tag">+${mitre.length - max}</span>` : '';
    return shown + more;
  }

  function feedRow(a, isNew) {
    return `<div class="feed-row ${isNew ? 'feed-new' : ''}" data-attack="${a.id}">
      <div class="time">${fmtTime(a.timestamp)}</div>
      <div class="main">
        <div><span class="ip">${escapeHtml(a.source_ip)}</span>
          <span class="flag">${a.country ? '· ' + escapeHtml(a.country) : ''}</span>
          ${sevBadge(a.risk_score)}</div>
        <div class="creds">${escapeHtml(a.username || '—')} / ${escapeHtml(a.password || '—')}</div>
        <div class="tags">${mitreTags(a.mitre)}</div>
      </div>
    </div>`;
  }

  function incidentItem(inc) {
    const s = severity(inc.max_risk_score);
    return `<div class="list-item" data-incident="${inc.id}">
      <div class="row1"><span class="ip">${escapeHtml(inc.source_ip)} ${inc.country ? '· ' + escapeHtml(inc.country) : ''}</span>
        <span class="badge-sev sev-${s.key}">${s.label}</span></div>
      <div class="sub">${inc.attempt_count} attacks · ${fmtAgo(inc.last_seen)} · ${mitreTags(inc.mitre, 2)}</div>
    </div>`;
  }

  function alertRow(al) {
    const s = severity(al.risk_score);
    const tech = al.mitre ? `<span class="tag mitre">${escapeHtml(al.mitre.id)}</span>` : '';
    return `<div class="alert-row ${s.key}" data-attack="${al.id}">
      <div class="sev-stripe"></div>
      <div class="body">
        <div class="type">${escapeHtml(al.alert_type)}</div>
        <div class="meta">${escapeHtml(al.source_ip)} ${al.country ? '· ' + escapeHtml(al.country) : ''} · ${tech} · ${fmtTime(al.timestamp)}</div>
      </div>
      <div class="score sev-${s.key}" style="color:var(--${s.key})">${al.risk_score}</div>
    </div>`;
  }

  function barList(items, max) {
    if (!items || !items.length) return '<div class="empty" style="padding:8px">No data</div>';
    const top = max || Math.max(...items.map((i) => i.count), 1);
    return items.map((i) => {
      const label = i.value !== undefined ? i.value : (i.id + ' ' + (i.name || ''));
      const pct = Math.round((i.count / top) * 100);
      return `<div class="bar-item">
        <div class="name" title="${escapeHtml(label)}">${escapeHtml(label || '—')}</div>
        <div class="count">${i.count}</div>
        <div class="track"><div class="fill" style="width:${pct}%"></div></div>
      </div>`;
    }).join('');
  }

  function commandRow(c) {
    const tech = (c.mitre || []).map((m) => `<span class="tag mitre">${escapeHtml(m.id)}</span>`).join('') || '—';
    const sess = (c.session_id || '').slice(0, 8);
    return `<tr>
      <td class="mono" style="color:var(--muted-2)">${fmtTime(c.timestamp)}</td>
      <td class="mono">${escapeHtml(sess)}</td>
      <td class="mono">${escapeHtml(c.source_ip)}</td>
      <td><code>${escapeHtml(c.command)}</code></td>
      <td>${tech}</td>
    </tr>`;
  }

  function setStatusDot(el, status) {
    el.className = 'status-dot ' + (status || '');
  }

  return { escapeHtml, severity, sevBadge, fmtTime, fmtAgo, mitreTags, feedRow, incidentItem, alertRow, barList, commandRow, setStatusDot };
})();
