// CNA Detail Page - Complete Refactored Implementation
// All utility functions and page logic in one clean file

console.log('Loading CNA Detail JavaScript...');

// ================================
// UTILITY FUNCTIONS
// ================================

// Get URL parameter value
function getUrlParameter(name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
}

// Handle back button navigation with smart fallback
function handleBackNavigation(event) {
  event.preventDefault();
  
  // Try to go back in browser history if available
  if (window.history.length > 1 && document.referrer.includes(window.location.origin)) {
    console.log('Using browser back navigation');
    window.history.back();
  } else {
    // Fallback to CNA list page
    console.log('Navigating to CNA list page');
    window.location.href = '../index.html';
  }
}

// Calculate grade based on score
function calculateGrade(score) {
  if (score >= 95) return 'Perfect';
  if (score >= 85) return 'Great';
  if (score >= 75) return 'Good';
  if (score >= 65) return 'Fair';
  if (score >= 50) return 'Poor';
  return 'Missing Data';
}

// Alias for backward compatibility
function getGrade(score) {
  return calculateGrade(score);
}

// Format number as ordinal (1st, 2nd, 3rd, etc.)
function formatOrdinal(num) {
  if (!num || num === 'N/A' || num === 0) return 'N/A';
  
  const number = parseInt(num);
  if (isNaN(number)) return 'N/A';
  
  const suffix = ['th', 'st', 'nd', 'rd'];
  const v = number % 100;
  return number + (suffix[(v - 20) % 10] || suffix[v] || suffix[0]);
}

// Categorize CNA type based on name and CVE count
function categorizeCnaType(shortName, cveCount) {
  if (!shortName) return 'Unknown';
  
  const shortNameLower = shortName.toLowerCase();
  
  const vendorIndicators = ['corp', 'inc', 'ltd', 'llc', 'gmbh', 'ag', 'sa', 'co', 'technologies', 'systems'];
  if (vendorIndicators.some(indicator => shortNameLower.includes(indicator))) {
    return 'Vendor';
  }
  
  const researchIndicators = ['research', 'university', 'lab', 'institute', 'academic', 'edu', 'researcher'];
  if (researchIndicators.some(indicator => shortNameLower.includes(indicator))) {
    return 'Researcher';
  }
  
  const govIndicators = ['gov', 'cert', 'cisa', 'dhs', 'nist', 'government', 'federal'];
  if (govIndicators.some(indicator => shortNameLower.includes(indicator))) {
    return 'Government';
  }
  
  if (cveCount > 100) return 'Vendor';
  if (cveCount > 20) return 'Researcher';
  return 'Other';
}

// Alias for backward compatibility
function getCnaType(type) {
  return type || 'Unknown';
}

// ================================
// DATA LOADING AND CONVERSION
// ================================

// Load CNA data from individual JSON file
async function loadCnaData(shortName) {
  try {
    console.log(`Loading CNA data for: ${shortName}`);
    const response = await fetch(`../data/cna/${shortName}.json`);
    
    if (!response.ok) {
      throw new Error(`Failed to load CNA data for ${shortName}: ${response.status}`);
    }
    
    const cnaData = await response.json();
    console.log('CNA data loaded successfully:', cnaData);
    
    return convertCnaData(cnaData);
  } catch (error) {
    console.error('Error loading CNA data:', error);
    
    // Return fallback data structure
    return {
      name: shortName || 'Unknown CNA',
      organizationName: shortName || 'Unknown Organization',
      type: 'Unknown',
      score: 0,
      grade: 'Missing Data',
      trend: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      trend_direction: 'steady',
      trend_description: 'No trend data available',
      scope: 'Not Provided',
      advisories: [],
      email: [],
      officialCnaID: '',
      categories: [
        { label: 'Foundational Completeness', value: 0, max: 50, color: '#1ec6e6' },
        { label: 'Root Cause Analysis', value: 0, max: 15, color: '#0fa3b1' },
        { label: 'Software Identification', value: 0, max: 10, color: '#f4d35e' },
        { label: 'Severity & Impact', value: 0, max: 15, color: '#27ae60' },
        { label: 'Patch Info', value: 0, max: 10, color: '#e67e22' }
      ],
      metrics: [
        { title: 'Total CVEs Published', value: 0, unit: '', color: 'poor' },
        { title: 'Overall Score', value: '0%', unit: '', color: 'poor' },
        { title: 'Current Rank', value: 'N/A', unit: '', color: 'poor' },
        { title: 'Performance Percentile', value: 'N/A', unit: '', color: 'poor' }
      ],
      improvements: [{ impact: 'HIGH', description: 'CNA data not found. Please check the CNA name.' }],
      peerAvg: 0,
      recentCves: []
    };
  }
}

// Convert CNA JSON data to format expected by the page
function convertCnaData(cnaData) {
  try {
    console.log('Converting CNA data:', cnaData);
    
    // Validate input data
    if (!cnaData || !cnaData.cna_info) {
      throw new Error('Invalid CNA data structure');
    }
    
    const cnaInfo = cnaData.cna_info;
    const cnaScoring = (cnaData.cna_scoring && cnaData.cna_scoring[0]) || {};
    const score = cnaInfo.overall_average_score || 0; // Overall CNA Score
    const grade = calculateGrade(score);
    const type = categorizeCnaType(cnaInfo.cna || 'Unknown', cnaInfo.total_cves || 0);
    
    console.log(`Converting data for CNA: ${cnaInfo.cna}, Score: ${score}, Grade: ${grade}, Type: ${type}`);
    
    // Generate trend data based on current score
    const trendData = [];
    const baseScore = Math.max(20, score - 10);
    for (let i = 0; i < 12; i++) {
      const variation = (Math.random() - 0.5) * 10;
      const trendScore = Math.min(100, Math.max(0, baseScore + (i * 0.5) + variation));
      trendData.push(Math.round(trendScore * 10) / 10);
    }
    trendData[11] = score; // Ensure last value matches current score
    
    // Convert to expected format with enhanced metadata
    return {
      name: cnaInfo.cna,
      organizationName: cnaInfo.organizationName || cnaInfo.cna,
      type: type,
      score: score,
      grade: grade,
      trend: trendData,
      // Real trend analysis data from pipeline
      trend_direction: cnaInfo.trend_direction || 'steady',
      trend_description: cnaInfo.trend_description || 'No trend data available',
      // Enhanced metadata for rich header display
      scope: cnaInfo.scope || 'Not Provided',
      advisories: cnaInfo.advisories || [],
      email: cnaInfo.email || [],
      officialCnaID: cnaInfo.officialCnaID || '',
      // New enhanced metadata fields
      cnaTypes: cnaInfo.cnaTypes || [],
      country: cnaInfo.country || '',
      disclosurePolicy: cnaInfo.disclosurePolicy || [],
      rootCnaInfo: cnaInfo.rootCnaInfo || {},
      rank: (typeof cnaData.rank !== 'undefined') ? cnaData.rank : (cnaInfo.rank || null),
      percentile: (typeof cnaData.percentile !== 'undefined') ? cnaData.percentile : (cnaInfo.percentile || null),
      categories: [
        { label: 'Foundational Completeness', value: cnaScoring.percent_foundational_completeness || 0, max: 100, color: '#1ec6e6' },
        { label: 'Root Cause Analysis', value: cnaScoring.percent_root_cause_analysis || 0, max: 100, color: '#0fa3b1' },
        { label: 'Software Identification', value: cnaScoring.percent_software_identification || 0, max: 100, color: '#f4d35e' },
        { label: 'Severity & Impact', value: cnaScoring.percent_severity_and_impact || 0, max: 100, color: '#27ae60' },
        { label: 'Patch Info', value: cnaScoring.percent_patchinfo || 0, max: 100, color: '#e67e22' }
      ],
      metrics: [
        { title: 'Total CVEs Published', value: cnaInfo.total_cves || 0, unit: '', color: 'great' },
        { title: 'Overall Score', value: (typeof cnaScoring.overall_average_score !== 'undefined') ? `${Math.round(cnaScoring.overall_average_score)}%` : (typeof score !== 'undefined' ? `${Math.round(score)}%` : 'N/A'), unit: '', color: grade.toLowerCase().replace(' ', '-') },
        { title: 'Current Rank', value: (typeof cnaData.rank !== 'undefined' && cnaData.rank > 0) ? formatOrdinal(cnaData.rank) : (cnaInfo.rank && cnaInfo.rank > 0 ? formatOrdinal(cnaInfo.rank) : 'N/A'), unit: '', color: 'good' },
        { title: 'Performance Percentile', value: (typeof cnaData.percentile !== 'undefined' && cnaData.percentile > 0) ? `${cnaData.percentile}th` : (cnaInfo.percentile && cnaInfo.percentile > 0 ? `${cnaInfo.percentile}th` : 'N/A'), unit: '', color: 'good' }
      ],
      improvements: [
        { impact: 'MEDIUM', description: 'Continue maintaining high standards in CVE documentation.' },
        { impact: 'LOW', description: 'Consider expanding actionable intelligence in vulnerability reports.' }
      ],
      peerAvg: 75,
      recentCves: cnaData.recent_cves || []
    };
    
  } catch (error) {
    console.error('Error in convertCnaData:', error);
    // Return fallback data structure
    return {
      name: 'Unknown CNA',
      organizationName: 'Unknown Organization',
      type: 'Unknown',
      score: 0,
      grade: 'Poor',
      trend: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      trend_direction: 'steady',
      trend_description: 'No trend data available',
      scope: 'Not Provided',
      advisories: [],
      email: [],
      officialCnaID: '',
      categories: [
        { label: 'Foundational Completeness', value: 0, max: 50, color: '#1ec6e6' },
        { label: 'Root Cause Analysis', value: 0, max: 15, color: '#0fa3b1' },
        { label: 'Software Identification', value: 0, max: 10, color: '#f4d35e' },
        { label: 'Severity & Impact', value: 0, max: 15, color: '#27ae60' },
        { label: 'Patch Info', value: 0, max: 10, color: '#e67e22' }
      ],
      metrics: [],
      improvements: [{ impact: 'HIGH', description: 'Error loading CNA data.' }],
      peerAvg: 0,
      recentCves: []
    };
  }
}

// ================================
// RENDERING FUNCTIONS
// ================================

function renderRecentCveCards(recentCves) {
  const mainContainer = document.querySelector('main.container');
  if (!mainContainer) return;
  // Remove old section if present
  let oldSection = document.getElementById('recentCveCardsSection');
  if (oldSection) oldSection.remove();

  const section = document.createElement('section');
  section.id = 'recentCveCardsSection';
  section.className = 'recent-cve-cards-section';
  section.innerHTML = `
    <h2>Recent CVEs (Last 6 Months)</h2>
    <div class="recent-cve-cards"></div>
  `;
  mainContainer.appendChild(section);

  const cardsContainer = section.querySelector('.recent-cve-cards');
  if (!recentCves || recentCves.length === 0) {
    cardsContainer.innerHTML = '<p>No recent CVEs for this CNA in the last 6 months.</p>';
    return;
  }
  // Sort by publish date descending (newest first)
  recentCves = recentCves.slice().sort((a, b) => {
    const da = new Date(a.datePublished || a.date_published || 0);
    const db = new Date(b.datePublished || b.date_published || 0);
    return db - da;
  });
  recentCves.forEach(cve => {
    const score = cve.totalCveScore || 0;
    const grade = calculateGrade(score);
    let badgeClass = '';
    switch (grade) {
      case 'Perfect': badgeClass = 'badge-perfect'; break;
      case 'Great': badgeClass = 'badge-great'; break;
      case 'Good': badgeClass = 'badge-good'; break;
      case 'Fair': badgeClass = 'badge-fair'; break;
      case 'Poor': badgeClass = 'badge-poor'; break;
      default: badgeClass = 'badge-missing';
    }
    const card = document.createElement('div');
    card.className = 'recent-cve-card';
    // Render five category indicators
    const categories = [
      { key: 'foundationalCompleteness', label: 'Foundational', color: '#1ec6e6' },
      { key: 'rootCauseAnalysis', label: 'Root Cause', color: '#0fa3b1' },
      { key: 'softwareIdentification', label: 'Software ID', color: '#f4d35e' },
      { key: 'severityAndImpactContext', label: 'Severity', color: '#27ae60' },
      { key: 'patchinfo', label: 'Patch', color: '#e67e22' }
    ];
    const breakdown = cve.scoreBreakdown || {};
    const indicators = categories.map(cat => {
      const present = breakdown[cat.key] && breakdown[cat.key] > 0;
      return `<div class="cve-cat-indicator" title="${cat.label}" style="color: ${present ? '#444' : '#bbb'}; font-weight: ${present ? 'bold' : 'normal'}; margin-bottom: 0.1em; display: flex; align-items: center;">
        <span class="cve-cat-label">${cat.label}</span>
      </div>`;
    }).join('');
    // Map grade to pill color class (matching main index)
    let pillClass = '';
    switch (grade) {
      case 'Perfect': pillClass = 'badge-perfect'; break;
      case 'Great': pillClass = 'badge-great'; break;
      case 'Good': pillClass = 'badge-good'; break;
      case 'Fair': pillClass = 'badge-fair'; break;
      case 'Poor': pillClass = 'badge-poor'; break;
      default: pillClass = 'badge-missing';
    }
    card.innerHTML = `
      <div class="cve-id-row"><a href="https://www.cve.org/CVERecord?id=${cve.cveId}" target="_blank" rel="noopener noreferrer"><strong>${cve.cveId}</strong></a></div>
      <div class="cve-date">${(cve.datePublished || '').slice(0,10)}</div>
      <div class="cve-cat-indicators" style="margin-top: 0.5em; display: flex; flex-direction: column; gap: 0.1em 0;">${indicators}</div>
      <div class="cve-score-pill ${pillClass}">${score} <span class="cve-grade-pill">${grade}</span></div>
    `;
    
    // Force the correct color for Good badges with inline styles
    if (grade === 'Good') {
      const pillElement = card.querySelector('.cve-score-pill');
      if (pillElement) {
        pillElement.style.background = 'linear-gradient(135deg, #3b82f6, #2563eb)';
        pillElement.style.color = '#fff';
      }
    }
    cardsContainer.appendChild(card);
  });
}


// Get country flag emoji based on country name
function getCountryFlag(country) {
  const flagMap = {
    'USA': '🇺🇸',
    'United States': '🇺🇸',
    'Canada': '🇨🇦',
    'UK': '🇬🇧',
    'United Kingdom': '🇬🇧',
    'Germany': '🇩🇪',
    'France': '🇫🇷',
    'Netherlands': '🇳🇱',
    'Spain': '🇪🇸',
    'China': '🇨🇳',
    'Switzerland': '🇨🇭',
    'Australia': '🇦🇺',
    'Sweden': '🇸🇪',
    'Romania': '🇷🇴',
    'Israel': '🇮🇱',
    'India': '🇮🇳',
    'Ireland': '🇮🇪',
    'Belgium': '🇧🇪',
    'Slovak Republic': '🇸🇰',
    'Slovakia': '🇸🇰',
    'Colombia': '🇨🇴',
    'Japan': '🇯🇵',
    'South Korea': '🇰🇷',
    'Brazil': '🇧🇷',
    'Italy': '🇮🇹',
    'Norway': '🇳🇴',
    'Finland': '🇫🇮',
    'Denmark': '🇩🇰'
  };
  
  return flagMap[country] || '🌐';
}

// Render CNA type badges
function renderCnaTypeBadges(cnaTypes) {
  if (!Array.isArray(cnaTypes) || cnaTypes.length === 0) {
    return '';
  }
  
  return cnaTypes.map(type => {
    const colorMap = {
      'Vendor': { bg: '#3b82f6', text: 'white' },
      'Researcher': { bg: '#10b981', text: 'white' },
      'Coordinator': { bg: '#f59e0b', text: 'white' },
      'Government': { bg: '#8b5cf6', text: 'white' }
    };
    
    const colors = colorMap[type] || { bg: '#6b7280', text: 'white' };
    
    return `<span class="cna-type-badge" style="background: ${colors.bg}; color: ${colors.text}; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; margin-right: 0.5rem;">${type}</span>`;
  }).join('');
}

// Render country information with flag
function renderCountryInfo(country) {
  if (!country) {
    return '<span class="country-info">🌐 Global</span>';
  }
  
  const flag = getCountryFlag(country);
  return `<span class="country-info" style="display: inline-flex; align-items: center; gap: 0.5rem; font-weight: 500;">${flag} ${country}</span>`;
}

// Render trend badge using real trend analysis data
function renderTrendBadge(trendDirection, trendDescription) {
  const trendElement = document.getElementById('cnaTrend');
  if (!trendElement) {
    console.warn('Trend element not found');
    return;
  }
  
  // Set trend icon and text based on direction
  let icon = '';
  let background = '';
  let trendText = '';
  
  switch (trendDirection) {
    case 'improving':
      icon = '↗️';
      background = 'linear-gradient(135deg, #10b981, #059669)';
      trendText = 'Improving';
      break;
    case 'declining':
      icon = '↘️';
      background = 'linear-gradient(135deg, #dc3545, #c82333)';
      trendText = 'Declining';
      break;
    case 'steady':
    default:
      icon = '➡️';
      background = 'linear-gradient(135deg, #6b7280, #4b5563)';
      trendText = 'Steady';
      break;
  }
  
  // Apply uniform pill styling with proper colors
  trendElement.className = `trend-badge trend-${trendDirection} uniform-pill`;
  trendElement.style.background = background;
  trendElement.style.color = 'white';
  trendElement.style.padding = '0.5rem 0.5rem';
  trendElement.style.borderRadius = '20px';
  trendElement.style.fontSize = '0.875rem';
  trendElement.style.fontWeight = '600';
  trendElement.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
  trendElement.style.display = 'inline-flex';
  trendElement.style.alignItems = 'center';
  trendElement.style.justifyContent = 'center';
  trendElement.style.gap = '0.25rem';
  trendElement.style.width = '90px';
  trendElement.style.textAlign = 'center';
  trendElement.style.whiteSpace = 'nowrap';
  trendElement.style.overflow = 'hidden';
  trendElement.title = trendDescription;
  trendElement.textContent = `${icon} ${trendText}`;
  
  console.log('Trend badge rendered:', trendDirection);
}

// Render category breakdown with large numbers and explanatory text
function renderCategoryBreakdown(categories) {
  const container = document.querySelector('#categoryCharts');
  if (!container) {
    console.warn('Category charts container not found');
    return;
  }
  
  container.innerHTML = '';
  
  // Map category labels to their explanatory text
  const explanations = {
    'Foundational Completeness': '(Basic CVE Fields)',
    'Root Cause Analysis': '(CWE)',
    'Software Identification': '(CPE)',
    'Severity & Impact': '(CVSS)',
    'Patch Info': '(Patch Link)'
  };
  
  categories.forEach(category => {
    const categoryCard = document.createElement('div');
    categoryCard.className = 'category-card';
    const explanation = explanations[category.label] || '';
    categoryCard.innerHTML = `
      <div class="category-score" style="color: ${category.color}">${Math.round(category.value)}%</div>
      <div class="category-label">${category.label}</div>
      <div class="category-explanation">${explanation}</div>
    `;
    container.appendChild(categoryCard);
  });
  
  console.log('Category breakdown rendered with explanations');
}

// Render metric cards
function renderMetricCards(metrics) {
  const container = document.querySelector('.metric-cards');
  if (!container) {
    console.warn('Metric cards container not found');
    return;
  }
  
  container.innerHTML = '';
  
  metrics.forEach(metric => {
    const metricCard = document.createElement('div');
    metricCard.className = `metric-card metric-${metric.color}`;
    metricCard.innerHTML = `
      <div class="metric-value">${metric.value}</div>
      <div class="metric-unit">${metric.unit}</div>
      <div class="metric-title">${metric.title}</div>
    `;
    if (metric.tooltip) {
      metricCard.title = metric.tooltip;
    }
    container.appendChild(metricCard);
  });
  
  console.log('Metric cards rendered');
}



// ================================

// Note: Old benchmark dropdown functions removed - functionality now integrated into clickable score pill

// ================================
// MAIN INITIALIZATION
// ================================

// Main initialization function
async function initializePage() {
  try {
    console.log('Initializing CNA detail page...');
    
    // Get CNA short name from URL parameter
    const shortName = getUrlParameter('shortName') || 'palo_alto';
    console.log(`CNA shortName: ${shortName}`);
    
    // Load CNA data from individual JSON file
    const CNA_DETAIL = await loadCnaData(shortName);
    console.log('Converted CNA data:', CNA_DETAIL);
    
    // Validate that we have valid CNA data
    if (!CNA_DETAIL || !CNA_DETAIL.name) {
      console.error('Failed to load valid CNA data');
      throw new Error('Invalid CNA data loaded');
    }

    // ================================
    // RENDER CNA HEADER
    // ================================
    
    console.log('Rendering CNA header...');
    
    // Update header information with null checks
    const cnaNameElement = document.getElementById('cnaName');
    if (cnaNameElement) {
      cnaNameElement.textContent = CNA_DETAIL.name || 'Unknown CNA';
    }
    
    const organizationNameElement = document.getElementById('organizationName');
    if (organizationNameElement) {
      organizationNameElement.textContent = CNA_DETAIL.organizationName || CNA_DETAIL.name || 'Unknown Organization';
    }
    
    // Update CNA type with enhanced badges (in metadata badges container under organization name)
    const cnaTypeElement = document.querySelector('.cna-metadata-badges #cnaType');
    if (cnaTypeElement) {
      if (CNA_DETAIL.cnaTypes && CNA_DETAIL.cnaTypes.length > 0) {
        cnaTypeElement.innerHTML = renderCnaTypeBadges(CNA_DETAIL.cnaTypes);
      } else {
        cnaTypeElement.textContent = CNA_DETAIL.type || 'Not Provided';
      }
    }
    
    // Update country flag in metadata badges container with hover tooltip
    const countryFlagElement = document.querySelector('.cna-metadata-badges #cnaCountryFlag');
    if (countryFlagElement && CNA_DETAIL.country) {
      const flagEmoji = getCountryFlag(CNA_DETAIL.country);
      countryFlagElement.textContent = flagEmoji;
      countryFlagElement.title = CNA_DETAIL.country; // Set hover tooltip
    } else if (countryFlagElement) {
      countryFlagElement.textContent = '🌐';
      countryFlagElement.title = 'Global';
    }
    

    
    // Update score and grade with null checks
    const cnaScoreElement = document.getElementById('cnaScore');
    if (cnaScoreElement) {
      cnaScoreElement.textContent = `${CNA_DETAIL.score || 0}%`;
    }
    
    const cnaGradeElement = document.getElementById('cnaGrade');
    if (cnaGradeElement) {
      // Use the same logic as metric card: grade is calculated from overall_average_score
      let scoreForGrade = 0;
      if (CNA_DETAIL.metrics && Array.isArray(CNA_DETAIL.metrics) && CNA_DETAIL.metrics.length > 1) {
        const val = CNA_DETAIL.metrics[1].value;
        if (typeof val === 'string' && val.endsWith('%')) {
          scoreForGrade = parseFloat(val.replace('%',''));
        } else if (!isNaN(val)) {
          scoreForGrade = Number(val);
        }
      } else if (CNA_DETAIL && typeof CNA_DETAIL.score !== 'undefined') {
        scoreForGrade = CNA_DETAIL.score;
      }
      const grade = calculateGrade(scoreForGrade);
      cnaGradeElement.textContent = grade;
      // Apply proper grade class for colors and uniform pill styling
      const gradeClass = `badge-${grade.toLowerCase()}`;
      cnaGradeElement.className = `badge-grade ${gradeClass} uniform-pill`;
    }
    
    // Update metadata fields
    const scopeElement = document.getElementById('cnaScope');
    if (scopeElement) {
      scopeElement.textContent = CNA_DETAIL.scope;
    }
    
    const officialIdElement = document.getElementById('cnaOfficialId');
    if (officialIdElement) {
      officialIdElement.textContent = CNA_DETAIL.officialCnaID;
    }
    
    // Initialize action buttons handling - declare variables first
    const actionButtonsContainer = document.querySelector('.cna-action-buttons');
    let hasActionButtons = false;
    
    // Handle disclosure policy - styled as button in action section
    const disclosurePolicyElement = document.getElementById('cnaDisclosurePolicy');
    if (disclosurePolicyElement && CNA_DETAIL.disclosurePolicy && CNA_DETAIL.disclosurePolicy.length > 0) {
      const policyLinks = CNA_DETAIL.disclosurePolicy.map(policy => 
        `<a href="${policy.url}" target="_blank" rel="noopener noreferrer" class="cna-action-button policy-button">${policy.label || 'Disclosure Policy'}</a>`
      ).join(' ');
      
      if (policyLinks) {
        disclosurePolicyElement.innerHTML = policyLinks;
        disclosurePolicyElement.style.display = 'inline-block';
        hasActionButtons = true;
      } else {
        disclosurePolicyElement.style.display = 'none';
      }
    } else {
      disclosurePolicyElement.style.display = 'none';
    }
    
    // Add root CNA information if available
    const rootCnaElement = document.getElementById('cnaRootInfo');
    const rootCnaDiv = rootCnaElement ? rootCnaElement.closest('.cna-detail-item') : null;
    let rootInfo = '';
    if (CNA_DETAIL.rootCnaInfo && (CNA_DETAIL.rootCnaInfo.shortName || CNA_DETAIL.rootCnaInfo.organizationName)) {
      if (CNA_DETAIL.rootCnaInfo.organizationName && CNA_DETAIL.rootCnaInfo.shortName) {
        rootInfo = `${CNA_DETAIL.rootCnaInfo.organizationName} (${CNA_DETAIL.rootCnaInfo.shortName})`;
      } else if (CNA_DETAIL.rootCnaInfo.organizationName) {
        rootInfo = CNA_DETAIL.rootCnaInfo.organizationName;
      } else {
        rootInfo = CNA_DETAIL.rootCnaInfo.shortName;
      }
      rootCnaElement.textContent = rootInfo;
      if (rootCnaDiv) rootCnaDiv.style.display = '';
    } else {
      // Hide the root CNA div if not provided
      if (rootCnaDiv) rootCnaDiv.style.display = 'none';
    }

    if (rootCnaElement && CNA_DETAIL.rootCnaInfo && CNA_DETAIL.rootCnaInfo.organizationName) {
      rootCnaElement.textContent = `${CNA_DETAIL.rootCnaInfo.organizationName} (${CNA_DETAIL.rootCnaInfo.shortName || 'N/A'})`;
    } else if (rootCnaElement) {
      rootCnaElement.textContent = 'Not Provided';
    }
    
    // Render trend badge using real trend analysis data
    renderTrendBadge(CNA_DETAIL.trend_direction, CNA_DETAIL.trend_description);

    // Render recent CVE cards below main info
    renderRecentCveCards(CNA_DETAIL.recentCves);
    
    // Update enhanced metadata fields with proper null checks
    const scopeEl = document.getElementById('cnaScope');
    const idEl = document.getElementById('cnaOfficialId'); // Fixed ID to match HTML
    const emailEl = document.getElementById('cnaEmail');
    const advisoriesEl = document.getElementById('cnaAdvisories');
    
    if (scopeEl) scopeEl.textContent = CNA_DETAIL.scope || 'Not Provided';
    if (idEl) idEl.textContent = CNA_DETAIL.officialCnaID || 'Not Provided';
    
    // Handle action buttons in the centered section - no headings, just buttons
    // Variables already declared above
    
    // Handle email contacts - styled as button in action section
    if (emailEl && CNA_DETAIL.email && Array.isArray(CNA_DETAIL.email) && CNA_DETAIL.email.length > 0) {
      const emailLinks = CNA_DETAIL.email.map(email => {
        if (typeof email === 'object' && email.emailAddr) {
          return `<a href="mailto:${email.emailAddr}" class="cna-action-button contact-button">Contact</a>`;
        } else if (typeof email === 'string') {
          return `<a href="mailto:${email}" class="cna-action-button contact-button">Contact</a>`;
        }
        return null;
      }).filter(link => link !== null);
      
      if (emailLinks.length > 0) {
        emailEl.innerHTML = emailLinks.join(' ');
        emailEl.style.display = 'inline-block';
        hasActionButtons = true;
      } else {
        emailEl.style.display = 'none';
      }
    } else {
      emailEl.style.display = 'none';
    }
    
    // Handle advisories - styled as button in action section
    if (advisoriesEl && CNA_DETAIL.advisories && Array.isArray(CNA_DETAIL.advisories) && CNA_DETAIL.advisories.length > 0) {
      const advisoryLinks = CNA_DETAIL.advisories.map(advisory => {
        if (typeof advisory === 'object' && advisory.url && advisory.label) {
          return `<a href="${advisory.url}" target="_blank" class="cna-action-button advisory-button">${advisory.label}</a>`;
        } else if (typeof advisory === 'string' && advisory.startsWith('http')) {
          return `<a href="${advisory}" target="_blank" class="cna-action-button advisory-button">Advisories</a>`;
        }
        return null;
      }).filter(link => link !== null);
      
      if (advisoryLinks.length > 0) {
        advisoriesEl.innerHTML = advisoryLinks.join(' ');
        advisoriesEl.style.display = 'inline-block';
        hasActionButtons = true;
      } else {
        advisoriesEl.style.display = 'none';
      }
    } else {
      advisoriesEl.style.display = 'none';
    }
    
    // Hide the entire action buttons container if no buttons are present
    if (actionButtonsContainer) {
      actionButtonsContainer.style.display = hasActionButtons ? 'flex' : 'none';
    }

    // ================================
    // RENDER PAGE SECTIONS
    // ================================
    
    console.log('Rendering page sections...');
    
    // Render metric cards
    renderMetricCards(CNA_DETAIL.metrics);
    
    // Render category breakdown
    renderCategoryBreakdown(CNA_DETAIL.categories);
    
    // Render actionable insights

    
    // ================================
    // SETUP CLICKABLE BENCHMARK SCORE PILL
    // ================================
    
    // Replace score pill with clickable benchmark comparison
    try {
      await setupClickableBenchmarkScorePill(CNA_DETAIL);
    } catch (error) {
      console.error('Error setting up clickable benchmark score pill:', error);
    }
    
    // Note: All benchmark dropdown logic removed - functionality integrated into clickable score pill
    
    console.log('Page initialization completed successfully');
    
  } catch (error) {
    console.error('Error initializing page:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    
    // Display error message to user
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = 'background: #f8d7da; color: #721c24; padding: 1rem; margin: 1rem; border: 1px solid #f5c6cb; border-radius: 4px;';
    errorDiv.innerHTML = `
      <h3>Error Loading CNA Data</h3>
      <p>There was an error loading the CNA detail page: ${error.message}</p>
      <p>Please try refreshing the page or selecting a different CNA.</p>
    `;
    document.body.appendChild(errorDiv);
  }
}

// ================================
// CLICKABLE BENCHMARK SCORE PILL SETUP
// ================================

// Replace score pill with clickable benchmark comparison pill
async function setupClickableBenchmarkScorePill(currentCnaData) {
  try {
    console.log('Setting up clickable benchmark score pill...');
    console.log('Current CNA data:', currentCnaData);
    
    // Check if score pill element exists
    const scorePill = document.getElementById('cnaScore');
    if (!scorePill) {
      console.error('Score pill element not found in DOM');
      return;
    }
    
    // Load CNA summary data to calculate peer averages
    const response = await fetch('../data/cna_summary.json');
    if (!response.ok) {
      throw new Error(`Failed to load CNA summary data: ${response.status}`);
    }
    
    const cnaSummaryData = await response.json();
    console.log(`Loaded ${cnaSummaryData.length} CNAs for benchmark comparison`);
    
    // Get current CNA's types for filtering
    let currentCnaTypes = [];
    if (currentCnaData && currentCnaData.cnaTypes) {
      currentCnaTypes = Array.isArray(currentCnaData.cnaTypes) ? currentCnaData.cnaTypes : [currentCnaData.cnaTypes];
    } else if (currentCnaData && currentCnaData.type) {
      currentCnaTypes = [currentCnaData.type];
    }
    
    // Prefer metrics[1].value if present and numeric (removes %), else fallback
    let currentScore = 0;
    if (currentCnaData.metrics && Array.isArray(currentCnaData.metrics) && currentCnaData.metrics.length > 1) {
      // Remove any trailing %
      const val = currentCnaData.metrics[1].value;
      if (typeof val === 'string' && val.endsWith('%')) {
        currentScore = parseFloat(val.replace('%',''));
      } else if (!isNaN(val)) {
        currentScore = Number(val);
      }
    } else if (typeof currentCnaData.score !== 'undefined') {
      currentScore = currentCnaData.score;
    }
    console.log('Current CNA types:', currentCnaTypes);
    console.log('Current CNA score:', currentScore);
    
    // Create comparison types array (All CNAs + specific types)
    const comparisonTypes = ['all', ...currentCnaTypes];
    let currentComparisonIndex = 0;
    
    // Function to calculate peer average for a specific type (matches working benchmark comparison)
    function calculatePeerAverageForType(filterType) {
      let filteredCnas;
      
      if (filterType === 'all') {
        filteredCnas = cnaSummaryData;
      } else {
        // Match the exact logic from the working benchmark comparison
        filteredCnas = cnaSummaryData.filter(cna => cna.type === filterType);
      }
      
      // Exclude current CNA from peer calculation
      const currentCnaName = currentCnaData.name || currentCnaData.cna;
      filteredCnas = filteredCnas.filter(cna => cna.name !== currentCnaName);
      
      if (filteredCnas.length === 0) {
        return { average: 0, count: 0 };
      }
      
      // Use overallScore from cna_summary.json for comparison
      const totalScore = filteredCnas.reduce((sum, cna) => sum + (cna.overallScore || 0), 0);
      const average = Math.round(totalScore / filteredCnas.length);
      
      console.log(`Peer calculation for ${filterType}:`, {
        filteredCount: filteredCnas.length,
        totalScore,
        average,
        sampleCnas: filteredCnas.slice(0, 3).map(cna => ({ name: cna.name, score: cna.overall_average_score }))
      });
      
      return { average, count: filteredCnas.length };
    }
    
    // Function to update the pill display
    function updatePillDisplay() {
      const currentType = comparisonTypes[currentComparisonIndex];
      const peerData = calculatePeerAverageForType(currentType);
      
      if (peerData.count === 0) {
        scorePill.innerHTML = `${currentScore}%`;
        scorePill.className = 'uniform-pill';
        return;
      }
      
      const difference = currentScore - peerData.average;
      const sign = difference > 0 ? '+' : '';
      const cnaName = currentCnaData.name || currentCnaData.cna || 'This CNA';
      
      // Determine type label and styling
      let typeLabel, pillClass, differenceClass;
      if (currentType === 'all') {
        typeLabel = 'CNA';
        pillClass = 'uniform-pill benchmark-pill-all';
      } else {
        typeLabel = currentType;
        pillClass = 'uniform-pill';
      }
      
      // Determine difference class
      if (difference > 0) {
        differenceClass = 'positive';
        if (currentType !== 'all') pillClass = 'uniform-pill benchmark-pill-positive';
      } else if (difference < 0) {
        differenceClass = 'negative';
        if (currentType !== 'all') pillClass = 'uniform-pill benchmark-pill-negative';
      } else {
        differenceClass = 'neutral';
        if (currentType !== 'all') pillClass = 'uniform-pill benchmark-pill-neutral';
      }
      
      // Create the exact same HTML structure as benchmarkComparison
      const benchmarkHtml = `
        <span class="benchmark-cna-score">${cnaName}: <strong>${currentScore}</strong></span>
        <span class="benchmark-separator">•</span>
        <span class="benchmark-peer-avg">${typeLabel} Avg: <strong>${peerData.average}</strong></span>
        <span class="benchmark-separator">•</span>
        <span class="benchmark-difference ${differenceClass}">${sign}${difference}</span>
      `;
      
      scorePill.innerHTML = benchmarkHtml;
      scorePill.className = pillClass;
      scorePill.title = `Click to cycle comparison types. Current comparison: ${typeLabel}`;
      scorePill.style.background = '#ffffff';
      scorePill.style.color = '#333333';
    }
    
    // Add click event listener to cycle through comparison types
    scorePill.addEventListener('click', () => {
      currentComparisonIndex = (currentComparisonIndex + 1) % comparisonTypes.length;
      updatePillDisplay();
      console.log(`Switched to comparison type: ${comparisonTypes[currentComparisonIndex]}`);
    });
    
    // Make pill look clickable
    scorePill.style.cursor = 'pointer';
    scorePill.style.transition = 'all 0.2s ease';
    
    // Initial display
    updatePillDisplay();
    
    console.log('Clickable benchmark score pill setup completed');
    console.log('Available comparison types:', comparisonTypes);
    
  } catch (error) {
    console.error('Error setting up clickable benchmark score pill:', error);
  }
}



// ================================
// INITIALIZE WHEN DOM IS READY
// ================================

// Note: forcePopulateBenchmarkDropdown function removed - benchmark functionality now integrated into clickable score pill

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  // Then run normal initialization
  initializePage();
});

console.log('CNA Detail JavaScript loaded successfully');
