const $ = (s, r = document) => r.querySelector(s);
const COL = { scam: '#fb7185', suspicious: '#fbbf24', safe: '#34d399' };
const HEAD = { scam: 'Likely scam - do not engage', suspicious: 'Suspicious - be careful', safe: 'Looks legitimate' };
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));

function count(el, to) {
  const t0 = performance.now(), from = +el.dataset.v || 0; el.dataset.v = to;
  (function f(t) { const p = Math.min(1, (t - t0) / 900); el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3))).toLocaleString(); if (p < 1) requestAnimationFrame(f); })(t0);
}

/* ---------- analyzer (home) ---------- */
async function initAnalyzer() {
  const form = $('#az-form'); if (!form) return;
  document.querySelectorAll('.chip').forEach(c => c.onclick = () => { $('#az-text').value = c.dataset.text; $('#az-text').focus(); });
  form.onsubmit = async e => {
    e.preventDefault();
    const btn = $('#az-btn'), out = $('#az-out'), text = $('#az-text').value.trim();
    if (text.length < 8) { out.innerHTML = '<div class="idle"><div class="big">✍️</div>Paste at least a short message to analyse.</div>'; return; }
    btn.disabled = true; btn.textContent = 'Running pipeline...';
    out.innerHTML = '<div class="steps">' + ['Ingest', 'Queue', 'Classify', 'Store'].map(s => `<span class="step">${s}</span>`).join('') + '</div><div class="idle"><div class="big">🛰️</div>Event travelling through the pipeline...</div>';
    for (const s of out.querySelectorAll('.step')) { await sleep(260); s.classList.add('on'); }
    try {
      const res = await fetch('/api/v1/reports/', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, channel: $('#az-channel').value, sender: $('#az-sender').value }) });
      let d = await res.json();
      if (!res.ok) throw new Error(d.detail || d.error);
      for (let i = 0; i < 10 && d.status !== 'processed'; i++) { await sleep(700); d = await (await fetch('/api/v1/reports/' + d.id + '/')).json(); }
      render(d, out);
    } catch (err) { out.innerHTML = `<div class="idle"><div class="big">⚠️</div>${esc(err.message)}</div>`; }
    btn.disabled = false; btn.textContent = 'Analyse & report';
  };
}
function render(d, out) {
  const pct = Math.round(d.score * 100), C = 2 * Math.PI * 80, col = COL[d.label];
  out.innerHTML = `<div class="fade">
   <div class="gauge"><svg width="190" height="190" viewBox="0 0 190 190"><circle class="bgc" cx="95" cy="95" r="80"/><circle class="fg" cx="95" cy="95" r="80" stroke="${col}" stroke-dasharray="${C}" stroke-dashoffset="${C}"/></svg>
   <div class="num"><div><b style="color:${col}">${pct}</b><small>RISK SCORE</small></div></div></div>
   <div class="verdict"><span class="tag ${d.label}">${d.label}</span><h3>${HEAD[d.label]}</h3>
   <p class="meta" style="white-space:normal;margin-top:4px">${esc(d.category)} · processed in ${d.processing_ms} ms${d.campaign_size > 1 ? ' · seen in ' + d.campaign_size + ' reports' : ''}</p></div>
   <ul class="reasons">${d.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
   <p class="meta" style="margin-top:10px;white-space:normal">Pipeline: ${d.pipeline.map(p => esc(p.event)).join(' → ')} · <a href="/reports/${d.id}/" style="color:var(--a2)">open report →</a></p></div>`;
  requestAnimationFrame(() => requestAnimationFrame(() => { out.querySelector('.fg').style.strokeDashoffset = C * (1 - d.score); }));
}

/* ---------- dashboard ---------- */
const charts = {};
function mk(id, cfg) { if (charts[id]) { charts[id].data = cfg.data; charts[id].update(); return; } charts[id] = new Chart($('#' + id), cfg); }
async function loadStats() {
  if (!$('#c-daily')) return;
  const s = await (await fetch('/api/v1/stats/')).json(), k = s.kpis;
  Chart.defaults.color = '#8c96b5'; Chart.defaults.font.family = 'Inter'; Chart.defaults.borderColor = 'rgba(255,255,255,.06)';
  [['k-total', k.total], ['k-scam', k.scam], ['k-susp', k.suspicious], ['k-rate', k.scam_rate], ['k-24', k.last24h], ['k-camp', k.campaigns]].forEach(([i, v]) => $('#' + i) && count($('#' + i), v));
  $('#k-ms').textContent = k.avg_ms + ' ms';
  const ds = (l, key, c) => ({ label: l, data: s.daily[key], borderColor: c, backgroundColor: c + '33', fill: true, tension: .4, pointRadius: 2, borderWidth: 2 });
  mk('c-daily', { type: 'line', data: { labels: s.daily.labels, datasets: [ds('Scam', 'scam', '#fb7185'), ds('Suspicious', 'suspicious', '#fbbf24'), ds('Safe', 'safe', '#34d399')] }, options: { maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } }, scales: { y: { beginAtZero: true } } } });
  mk('c-cat', { type: 'doughnut', data: { labels: s.categories.map(c => c.name), datasets: [{ data: s.categories.map(c => c.count), backgroundColor: ['#7c5cff', '#22d3ee', '#fb7185', '#fbbf24', '#34d399', '#ec4899', '#60a5fa', '#a3e635'], borderWidth: 0 }] }, options: { maintainAspectRatio: false, cutout: '64%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } } } });
  mk('c-chan', { type: 'bar', data: { labels: s.channels.map(c => c.name), datasets: [{ data: s.channels.map(c => c.count), backgroundColor: '#7c5cff', borderRadius: 8 }] }, options: { maintainAspectRatio: false, plugins: { legend: { display: false } } } });
  const max = Math.max(1, ...s.top_domains.map(d => d.count));
  $('#t-dom').innerHTML = s.top_domains.map(d => `<tr><td><code>${esc(d.domain)}</code></td><td style="width:45%"><div class="bar"><i style="width:${100 * d.count / max}%"></i></div></td><td>${d.count}</td></tr>`).join('') || '<tr><td colspan=3 class="meta">No suspicious domains yet</td></tr>';
  $('#t-camp').innerHTML = s.campaigns.map(c => `<tr><td>${esc(c.text)}…<div class="meta">${esc(c.category)}</div></td><td><span class="tag scam">${c.count}×</span></td></tr>`).join('') || '<tr><td class="meta">No campaigns yet</td></tr>';
  $('#ev').innerHTML = s.events.map(e => `<div class="ev"><span>${e.at}</span><b>${esc(e.name)}</b> ${esc(e.detail)}</div>`).join('');
  $('#gen').textContent = 'Updated ' + s.generated_at;
}
initAnalyzer(); loadStats(); if ($('#c-daily')) setInterval(loadStats, 15000);
