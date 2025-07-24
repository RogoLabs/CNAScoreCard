// Shared chart rendering utilities for CNA Scorecard
// Uses CSS variables from theme.css for consistent coloring

// Helper function to get CSS variable values
function getCSSVariable(variableName) {
  return getComputedStyle(document.documentElement).getPropertyValue(variableName).trim();
}

// Get chart color palette from CSS variables
function getChartColors() {
  return [
    getCSSVariable('--chart-color-1'), // Primary blue
    getCSSVariable('--chart-color-2'), // Green
    getCSSVariable('--chart-color-3'), // Yellow
    getCSSVariable('--chart-color-4'), // Orange
    getCSSVariable('--chart-color-5'), // Red
    getCSSVariable('--chart-color-6'), // Teal
    getCSSVariable('--chart-color-7'), // Purple
    getCSSVariable('--chart-color-8')  // Orange variant
  ];
}

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
        borderColor: getCSSVariable('--primary-color'),
        backgroundColor: getCSSVariable('--primary-color') + '26', // Add alpha
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

// Create horizontal bar chart for field utilization
function createHorizontalBarChart(canvasId, data, options = {}) {
  if (!window.Chart) {
    console.warn('Chart.js not loaded');
    return;
  }
  
  const ctx = document.getElementById(canvasId).getContext('2d');
  const defaultOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        callbacks: {
          label: function(context) {
            return `${context.parsed.x.toFixed(1)}%`;
          }
        }
      }
    },
    scales: {
      x: {
        beginAtZero: true,
        max: 100,
        ticks: {
          callback: function(value) {
            return value + '%';
          },
          color: '#94a3b8'
        },
        grid: {
          color: 'rgba(148, 163, 184, 0.1)'
        }
      },
      y: {
        ticks: {
          color: '#94a3b8'
        },
        grid: {
          display: false
        }
      }
    }
  };
  
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.labels,
      datasets: [{
        data: data.values,
        backgroundColor: options.color || getCSSVariable('--chart-color-1'),
        borderRadius: 4,
        borderSkipped: false
      }]
    },
    options: { ...defaultOptions, ...options }
  });
}

// Export functions for module usage
export { renderSparkline, renderBarChart, createHorizontalBarChart };
