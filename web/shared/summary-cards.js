// summary-cards.js: Render global summary info as plain text in the footer

document.addEventListener('DOMContentLoaded', () => {
  const footer = document.querySelector('.footer-main');
  if (!footer) return;

  fetch('../data/completeness_summary.json')
    .then(resp => resp.json())
    .then(summary => {
      const summaryDiv = document.createElement('div');
      summaryDiv.className = 'footer-summary-line';
      summaryDiv.innerHTML = `
        <div>Analysis Period: <span class="footer-summary-date">${summary.analysis_period_start} to ${summary.analysis_period_end}</span></div>
        <div>CVEs Analyzed: <span class="footer-summary-count">${summary.cve_count.toLocaleString()}</span></div>
      `;
      footer.insertBefore(summaryDiv, footer.firstChild);
    });
});
