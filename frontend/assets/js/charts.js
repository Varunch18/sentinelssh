/* Chart.js setup + update helpers for the analytics row. */
const Charts = (() => {
  const GRID = '#1b2335';
  const TICK = '#8b98ad';
  const SEV = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

  Chart.defaults.color = TICK;
  Chart.defaults.font.family = 'Inter, sans-serif';
  Chart.defaults.font.size = 11;

  let hourly, risk, countries, mitre;

  function baseScales(extra = {}) {
    return {
      x: { grid: { color: GRID }, ticks: { color: TICK }, ...(extra.x || {}) },
      y: { grid: { color: GRID }, ticks: { color: TICK, precision: 0 }, beginAtZero: true, ...(extra.y || {}) },
    };
  }
  const noLegend = { plugins: { legend: { display: false } } };

  function init() {
    hourly = new Chart(document.getElementById('chartHourly'), {
      type: 'line',
      data: { labels: [], datasets: [{ data: [], borderColor: '#38bdf8', backgroundColor: 'rgba(56,189,248,.15)', fill: true, tension: .35, pointRadius: 0, borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, ...noLegend, scales: baseScales() },
    });

    risk = new Chart(document.getElementById('chartRisk'), {
      type: 'doughnut',
      data: { labels: ['Low', 'Medium', 'High'], datasets: [{ data: [0, 0, 0], backgroundColor: [SEV.low, SEV.medium, SEV.high], borderColor: '#141b29', borderWidth: 2 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '62%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, padding: 12 } } } },
    });

    countries = new Chart(document.getElementById('chartCountries'), {
      type: 'bar',
      data: { labels: [], datasets: [{ data: [], backgroundColor: '#0ea5e9', borderRadius: 4 }] },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, ...noLegend, scales: baseScales() },
    });

    mitre = new Chart(document.getElementById('chartMitre'), {
      type: 'bar',
      data: { labels: [], datasets: [{ data: [], backgroundColor: '#a78bfa', borderRadius: 4 }] },
      options: { responsive: true, maintainAspectRatio: false, ...noLegend, scales: baseScales() },
    });
  }

  function updateHourly(points) {
    hourly.data.labels = points.map((p) => p.label);
    hourly.data.datasets[0].data = points.map((p) => p.count);
    hourly.update('none');
  }
  function updateRisk(byLevel) {
    const map = Object.fromEntries(byLevel.map((b) => [b.label, b.count]));
    risk.data.datasets[0].data = [map.low || 0, map.medium || 0, map.high || 0];
    risk.update('none');
  }
  function updateCountries(items) {
    countries.data.labels = items.map((i) => i.value || '—');
    countries.data.datasets[0].data = items.map((i) => i.count);
    countries.update('none');
  }
  function updateMitre(items) {
    mitre.data.labels = items.map((i) => i.id);
    mitre.data.datasets[0].data = items.map((i) => i.count);
    mitre.update('none');
  }

  return { init, updateHourly, updateRisk, updateCountries, updateMitre };
})();
