// Actionable Insights Rendering for CNA Detail Page
// This will render prioritized recommendations based on missing fields/percentages

/**
 * Example improvement data structure:
 * [
 *   { impact: 'HIGH', description: 'Add affected product info to the 30% of records where it is missing to gain up to 15 points.' },
 *   ...
 * ]
 */

function renderActionableInsights(improvements) {
  const list = document.getElementById('improvementList');
  if (!list) return;
  list.innerHTML = '';
  improvements.forEach(item => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${item.impact} IMPACT:</strong> ${item.description}`;
    list.appendChild(li);
  });
}

// Example usage (replace with real data fetch):
document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('improvementList')) {
    renderActionableInsights([
      { impact: 'HIGH', description: 'Add affected product info to the 30% of records where it is missing to gain up to 15 points.' },
      { impact: 'MEDIUM', description: 'Add references to the 20% of records missing them to gain up to 10 points.' },
      { impact: 'LOW', description: 'Provide specific CWE IDs for the remaining 8% of records for a small score boost.' }
    ]);
  }
});
