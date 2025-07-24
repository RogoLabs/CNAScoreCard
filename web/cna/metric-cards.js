// Metric Cards Rendering for CNA Detail Page
// This will render cards for each scoring criterion with percentage, points, and tooltip

/**
 * Example metric data structure:
 * [
 *   { title: 'Provides Specific CWE IDs', percent: 92, points: 5, color: 'great', tooltip: 'Specific CWE IDs help root cause analysis.' },
 *   { title: 'Has Patch Info', percent: 80, points: 10, color: 'good', tooltip: 'Patch info enables remediation.' },
 *   { title: 'Has Valid CPE', percent: 50, points: 10, color: 'needs-work', tooltip: 'CPEs help identify affected software.' },
 *   { title: 'CVSS Vector Present', percent: 100, points: 5, color: 'great', tooltip: 'CVSS vectors provide severity context.' },
 *   { title: 'References Provided', percent: 75, points: 10, color: 'good', tooltip: 'References support transparency.' }
 * ]
 */

function renderMetricCards(metrics) {
  const container = document.getElementById('metricCards');
  if (!container) return;
  container.innerHTML = '';
  metrics.forEach(metric => {
    const card = document.createElement('div');
    card.className = `metric-card metric-${metric.color}`;
    card.innerHTML = `
      <div class="metric-title">${metric.title}</div>
      <div class="metric-value" style="color: var(--grade-${metric.color});">${metric.percent}%</div>
      <div class="metric-points">${metric.points} pts</div>
      <div class="metric-tooltip" title="${metric.tooltip}"><i class='fa fa-info-circle'></i> <span class='tooltip-text'>${metric.tooltip}</span></div>
    `;
    container.appendChild(card);
  });
}

// Example usage (replace with real data fetch):
document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('metricCards')) {
    renderMetricCards([
      { title: 'Provides Specific CWE IDs', percent: 92, points: 5, color: 'great', tooltip: 'Specific CWE IDs help root cause analysis.' },
      { title: 'Has Patch Info', percent: 80, points: 10, color: 'good', tooltip: 'Patch info enables remediation.' },
      { title: 'Has Valid CPE', percent: 50, points: 10, color: 'needs-work', tooltip: 'CPEs help identify affected software.' },
      { title: 'CVSS Vector Present', percent: 100, points: 5, color: 'great', tooltip: 'CVSS vectors provide severity context.' },
      { title: 'References Provided', percent: 75, points: 10, color: 'good', tooltip: 'References support transparency.' }
    ]);
  }
});
