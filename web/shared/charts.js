// Shared chart rendering utilities for CNA Scorecard
// Placeholder for sparkline, bar, donut chart rendering (to be replaced with Chart.js or similar)

// Example: Render a sparkline using Chart.js
function renderSparkline(canvasId, data) {
  if (!window.Chart) return;
  const ctx = document.getElementById(canvasId).getContext('2d');
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.labels,
      datasets: [{
        data: data.values,
        borderColor: '#1ec6e6',
        backgroundColor: 'rgba(30,198,230,0.15)',
        pointRadius: 0,
        borderWidth: 2,
        fill: true,
        tension: 0.35
      }]
    },
    options: {
      responsive: false,
      plugins: { legend: { display: false } },
      scales: { x: { display: false }, y: { display: false } },
      elements: { line: { borderJoinStyle: 'round' } }
    }
  });
}

// Example: Render a bar chart for category breakdown
function renderBarChart(canvasId, labels, values, colors) {
  if (!window.Chart) return;
  const ctx = document.getElementById(canvasId).getContext('2d');
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors
      }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: { x: { display: true }, y: { display: true } }
    }
  });
}
