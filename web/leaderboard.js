// Leaderboard Page Logic for CNA Scorecard
// Fetches CNA data, renders leaderboard, top performers, and handles search/sort/filter

// Global variables for CNA data
let CNA_DATA = [];
let filteredData = [];
let currentPage = 1;
const CNA_PER_PAGE = 25;
let isShowingDetails = false;
let isDataLoaded = false;

const GRADE_CLASS = {
  'Great': 'badge-great',
  'Good': 'badge-good',
  'Needs Work': 'badge-needs-work',
  'Missing Data': 'badge-missing',
  'Perfect': 'badge-perfect'
};

// Global function definitions for cross-function accessibility
function updateTopCards() {
  // Show top 3 by score if no search, else show filtered results
  let cardsToShow = filteredData;
  const searchBar = document.getElementById('searchBar');
  if (!searchBar || !searchBar.value) {
    cardsToShow = [...CNA_DATA].sort((a, b) => b.score - a.score).slice(0, 3);
  }
  renderTopPerformers(cardsToShow);
}

function updateLeaderboard() {
  renderLeaderboard(filteredData);
}

// Function to load CNA data from JSON file
async function loadCNAData() {
  try {
    const response = await fetch('../data/cna_combined.json');
    const data = await response.json();
    
    // Transform data to match expected structure
    CNA_DATA = data.map(cna => ({
      name: cna.shortName || '',
      shortName: cna.shortName || '',
      organizationName: cna.organizationName || cna.shortName || '',
      score: cna.scores?.overall_average_score || 0,
      foundationalCompleteness: cna.scores?.foundational_completeness || 0,
      rootCauseAnalysis: cna.scores?.root_cause_analysis || 0,
      softwareIdentification: cna.scores?.software_identification || 0,
      severityAndImpact: cna.scores?.severity_and_impact || 0,
      patchinfo: cna.scores?.patchinfo || 0,
      type: cna.cnaType || 'Unknown',
      trend: cna.trend?.monthly_data || Array(12).fill(0),
      trendDirection: cna.trend?.direction || 'steady',
      trendDescription: cna.trend?.description || '➡️ No change',
      cveCount: cna.total_cves || 0,
      recentCves: cna.recent_cves || 0,
      rank: cna.rank || 0,
      percentile: cna.percentile || 0
    }));
    
    // Sort by score (highest first)
    CNA_DATA.sort((a, b) => b.score - a.score);
    
    filteredData = [...CNA_DATA];
    isDataLoaded = true;
    
    // Render initial data
    renderLeaderboard(CNA_DATA);
    updateTopCards();
    
    console.log(`Loaded ${CNA_DATA.length} CNAs`);
  } catch (error) {
    console.error('Error loading CNA data:', error);
    // Fallback to placeholder data
    CNA_DATA = [
      { name: 'Data Loading Error', score: 0, grade: 'Missing Data', type: 'Unknown', trend: Array(12).fill(0), cveCount: 0 }
    ];
    filteredData = [...CNA_DATA];
    renderLeaderboard(CNA_DATA);
  }
}

function renderLeaderboard(data) {
  const tbody = document.querySelector('#leaderboardTable tbody');
  if (!tbody) return;
  
  tbody.innerHTML = '';
  
  // Update counters and pagination info
  const total = data.length;
  const startIndex = (currentPage - 1) * CNA_PER_PAGE;
  const endIndex = Math.min(startIndex + CNA_PER_PAGE, total);
  
  // Update counter display
  document.getElementById('cnaTotal').textContent = total;
  document.getElementById('cnaStart').textContent = startIndex + 1;
  document.getElementById('cnaEnd').textContent = endIndex;
  
  // Get current page data
  const displayData = data.slice(startIndex, endIndex);
  
  displayData.forEach((cna, index) => {
    const tr = document.createElement('tr');
    
    // Format scores for display with visual indicators
    const formatScoreWithBar = (score, isPercentage = false, max = 100) => {
      const value = score || 0;
      const percentage = isPercentage ? value : Math.min(100, (value / max) * 100);
      let colorClass = 'score-low';
      
      if (percentage >= 80) {
        colorClass = 'score-great';
      } else if (percentage >= 60) {
        colorClass = 'score-good';
      } else if (percentage >= 40) {
        colorClass = 'score-medium';
      }
      
      const displayValue = isPercentage ? `${value.toFixed(1)}%` : value.toFixed(1);
      
      return `
        <div class="score-display">
          <div>${displayValue}</div>
          <div class="score-bar">
            <div class="score-fill ${colorClass}" style="width: ${percentage}%"></div>
          </div>
        </div>
      `;
    };
    
    const formatScore = (score) => score ? score.toFixed(1) : '0.0';
    
    tr.innerHTML = `
      <td>${cna.rank}</td>
      <td>
        <div class="cna-name-cell">
          <a href="cna-detail.html?shortName=${cna.shortName}" class="cna-name-link">
            <strong>${cna.name}</strong>
          </a>
          <div class="cna-details">
            <div class="org-name">${cna.organizationName}</div>
            <div class="percentile-badge">Percentile: ${cna.percentile}</div>
          </div>
        </div>
      </td>
      <td>${cna.type}</td>
      <td>${cna.cveCount}</td>
      <td>${formatScoreWithBar(cna.score)}</td>
      <td>${formatScoreWithBar(cna.foundationalCompleteness, true)}</td>
      <td>${formatScoreWithBar(cna.rootCauseAnalysis, true)}</td>
      <td>${formatScoreWithBar(cna.softwareIdentification, true)}</td>
      <td>${formatScoreWithBar(cna.severityAndImpact, true)}</td>
      <td>${formatScoreWithBar(cna.patchinfo, true)}</td>
      <td>
        <div class="trend-container">
          <span class="trend-indicator" title="${cna.trendDescription}">
            ${cna.trendDirection === 'improving' ? '↗️' : cna.trendDirection === 'declining' ? '↘️' : '➡️'}
          </span>
          <canvas id="trend-${index}" width="80" height="20"></canvas>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
    
    // Render sparkline for trend
    setTimeout(() => {
      if (window.renderSparkline) {
        renderSparkline(`trend-${cna.cnaId || index}`, { 
          labels: Array(12).fill(''), 
          values: cna.trend 
        });
      }
    }, 0);
  });
  
  // Add "showing X of Y" message if more data available
  if (data.length > 50) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td colspan="4" class="showing-message">
        <em>Showing top 50 of ${data.length} CNAs. Use search to find specific CNAs.</em>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function renderTopPerformers(data) {
  const top = data.slice(0,3);
  const container = document.getElementById('topPerformers');
  
  // Check if the container exists (some pages don't have top performers section)
  if (!container) {
    console.log('Top performers container not found - skipping render');
    return;
  }
  
  container.innerHTML = '';
  // Standardized scoring categories
  const scoringCategories = [
    { field: 'Foundational Completeness', color: '#1ec6e6', importance: 'High' },
    { field: 'Root Cause Analysis', color: '#f4d35e', importance: 'High' },
    { field: 'Severity & Impact Context', color: '#27ae60', importance: 'Medium' },
    { field: 'Software Identification', color: '#e67e22', importance: 'Low' },
    { field: 'Patch Info', color: '#0fa3b1', importance: 'Medium' }
  ];
  top.forEach(cna => {
    const card = document.createElement('div');
    card.className = 'top-cna-card';
    card.style.display = 'flex';
    card.style.flexDirection = 'column';
    card.style.alignItems = 'stretch';
    card.innerHTML = `<h3>${cna.name}</h3>`;
    scoringCategories.forEach((cat, idx) => {
      // Mock grade data for demo
      const gradeList = ['Great','Great','Good','Needs Work','Missing Data'];
      const grade = gradeList[idx] || 'Needs Work';
      const badgeClass = GRADE_CLASS[grade] || '';
      const fieldCard = document.createElement('div');
      fieldCard.className = 'field-card';
      fieldCard.style.width = '100%';
      fieldCard.style.marginBottom = '0.5rem';
      fieldCard.style.background = '#f8fafc';
      fieldCard.style.borderRadius = '10px';
      fieldCard.style.boxShadow = '0 1px 4px rgba(30,198,230,0.04)';
      fieldCard.style.padding = '0.7rem 1.1rem 0.5rem 1.1rem';
      fieldCard.style.display = 'flex';
      fieldCard.style.flexDirection = 'column';
      fieldCard.style.alignItems = 'center';
      fieldCard.style.border = '1px solid var(--border-color)';
      fieldCard.innerHTML = `
        <div class="field-category" style="font-weight:700;font-size:0.98em;color:#0074d9;margin-bottom:0.18em;text-align:center;">${cat.field}</div>
        <div class="badge-grade ${badgeClass}" style="margin-bottom:0.13em;margin-top:0.05em;font-size:0.93em;padding:0.18em 0.7em;">${grade}</div>
      `;
      card.appendChild(fieldCard);
    });
    container.appendChild(card);
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  // Load CNA data from JSON file
  await loadCNAData();
  
  // Setup pagination and column toggle
  setupPagination();
  setupColumnToggle();
  
  function updateTopCards() {
    // Show top 3 by score if no search, else show filtered results
    let cardsToShow = filteredData;
    const searchBar = document.getElementById('searchBar');
    if (!searchBar || !searchBar.value) {
      cardsToShow = [...CNA_DATA].sort((a, b) => b.score - a.score).slice(0, 3);
    }
    renderTopPerformers(cardsToShow);
  }

  function updateLeaderboard() {
    renderLeaderboard(filteredData);
  }

  // Search functionality
  const searchBar = document.getElementById('searchBar');
  if (searchBar) {
    searchBar.addEventListener('input', () => {
      const q = searchBar.value.toLowerCase().trim();
      if (q === '') {
        filteredData = [...CNA_DATA];
      } else {
        filteredData = CNA_DATA.filter(cna => 
          cna.name.toLowerCase().includes(q) || 
          cna.type.toLowerCase().includes(q)
        );
      }
      updateLeaderboard();
      updateTopCards();
    });
  }

  // Sort functionality
  const sortSelect = document.getElementById('sortSelect');
  if (sortSelect) {
    sortSelect.addEventListener('change', () => {
      const sortBy = sortSelect.value;
      filteredData.sort((a, b) => {
        switch(sortBy) {
          case 'score':
            return b.score - a.score;
          case 'grade':
            const gradeOrder = {'Perfect': 5, 'Great': 4, 'Good': 3, 'Needs Work': 2, 'Missing Data': 1};
            return (gradeOrder[b.grade] || 0) - (gradeOrder[a.grade] || 0);
          case 'type':
            return a.type.localeCompare(b.type);
          case 'trend':
            const aAvg = a.trend.reduce((sum, val) => sum + val, 0) / a.trend.length;
            const bAvg = b.trend.reduce((sum, val) => sum + val, 0) / b.trend.length;
            return bAvg - aAvg;
          default:
            return b.score - a.score;
        }
      });
      updateLeaderboard();
    });
  }

  // Active CNAs filter
  const activeOnlyCheckbox = document.getElementById('activeOnly');
  if (activeOnlyCheckbox) {
    activeOnlyCheckbox.addEventListener('change', () => {
      if (activeOnlyCheckbox.checked) {
        filteredData = filteredData.filter(cna => cna.cveCount > 0);
      } else {
        // Reset to current search results
        const searchBar = document.getElementById('searchBar');
        const q = searchBar ? searchBar.value.toLowerCase().trim() : '';
        if (q === '') {
          filteredData = [...CNA_DATA];
        } else {
          filteredData = CNA_DATA.filter(cna => 
            cna.name.toLowerCase().includes(q) || 
            cna.type.toLowerCase().includes(q)
          );
        }
      }
      updateLeaderboard();
      updateTopCards();
    });
  }
});
