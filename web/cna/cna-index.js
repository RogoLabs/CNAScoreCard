/**
 * CNA Index Page - Main JavaScript
 * Modern implementation with clear separation of concerns
 * Supports chunked loading for faster initial page loads
 */

// Configuration
const CONFIG = {
  dataUrl: '../data/cna_combined.json',
  itemsPerPage: 25,
  defaultSort: 'rank',
  useChunkedLoading: true  // Enable chunked loading when available
};

// State management
const STATE = {
  data: [],
  filteredData: [],
  currentPage: 1,
  sortField: CONFIG.defaultSort,
  sortDirection: 'asc',
  showingDetails: false,
  searchTerm: '',
  isChunkedMode: false,
  dataFullyLoaded: false
};

// DOM Elements
const DOM = {
  table: document.getElementById('cnaTable'),
  tableBody: document.querySelector('#cnaTable tbody'),
  tableHeaders: document.querySelectorAll('.sortable'),
  searchInput: document.getElementById('searchInput'),
  toggleDetailsBtn: document.getElementById('toggleDetailsBtn'),
  startIndex: document.getElementById('startIndex'),
  endIndex: document.getElementById('endIndex'),
  totalItems: document.getElementById('totalItems'),
  prevPageBtn: document.getElementById('prevPageBtn'),
  nextPageBtn: document.getElementById('nextPageBtn'),
  paginationPages: document.getElementById('paginationPages'),
  exportCsvBtn: document.getElementById('exportCsvBtn'),
  exportJsonBtn: document.getElementById('exportJsonBtn'),
};

/**
 * Initialize the application
 */
async function init() {
  try {
    // Try chunked loading first if enabled and ChunkLoader is available
    if (CONFIG.useChunkedLoading && typeof ChunkLoader !== 'undefined') {
      await initWithChunks();
    } else {
      await initWithFallback();
    }
    
    // Set up event listeners
    setupEventListeners();
    
    // Set initial header text based on details view state
    updateScoreCardHeaderText();
    
    // Apply filters (this will hide inactive CNAs by default and set STATE.filteredData)
    applyFilters();
    
  } catch (error) {
    console.error('Failed to initialize CNA Index:', error);
    showErrorMessage('Failed to load CNA data. Please try refreshing the page.');
  }
}

/**
 * Initialize with chunked loading
 */
async function initWithChunks() {
  const result = await ChunkLoader.init();
  
  if (result.mode === 'chunked') {
    STATE.isChunkedMode = true;
    // Load all data from chunks - we need all data for proper filtering/sorting
    STATE.data = await ChunkLoader.loadAll();
    STATE.dataFullyLoaded = true;
  } else {
    // Fall back to regular loading
    await initWithFallback();
  }
}

/**
 * Initialize with fallback (load full file)
 */
async function initWithFallback() {
  STATE.data = await fetchData(CONFIG.dataUrl);
  STATE.dataFullyLoaded = true;
  STATE.isChunkedMode = false;
}

/**
 * Fetch data from the server
 * @param {string} url - URL to fetch data from
 * @returns {Promise<Array>} - Parsed JSON data
 */
async function fetchData(url) {
  const response = await fetch(url);
  
  if (!response.ok) {
    throw new Error(`Failed to fetch data: ${response.status} ${response.statusText}`);
  }
  
  return await response.json();
}

/**
 * Set up all event listeners
 */
function setupEventListeners() {
  // Search input
  DOM.searchInput?.addEventListener('input', debounce(handleSearch, 300));
  
  // Sortable headers - get fresh list each time to include dynamically added headers
  const sortableHeaders = document.querySelectorAll('.sortable');
  sortableHeaders.forEach(header => {
    header.addEventListener('click', () => handleHeaderClick(header));
  });
  
  // Toggle details button
  DOM.toggleDetailsBtn?.addEventListener('click', handleToggleDetails);
  
  // Pagination buttons
  DOM.prevPageBtn?.addEventListener('click', handlePrevPage);
  DOM.nextPageBtn?.addEventListener('click', handleNextPage);
  
  // Export buttons
  DOM.exportCsvBtn?.addEventListener('click', handleExportCsv);
  DOM.exportJsonBtn?.addEventListener('click', handleExportJson);
}

/**
 * Handle search input
 */
function handleSearch() {
  STATE.searchTerm = DOM.searchInput.value.toLowerCase().trim();
  STATE.currentPage = 1; // Reset to first page
  applyFilters();
}

/**
 * Handle sortable header click
 * @param {HTMLElement} header - The clicked header element
 */
function handleHeaderClick(header) {
  const sortField = header.dataset.sort;
  
  // Toggle sort direction if clicking the same field
  if (STATE.sortField === sortField) {
    STATE.sortDirection = STATE.sortDirection === 'asc' ? 'desc' : 'asc';
  } else {
    // New field, start with ascending
    STATE.sortField = sortField;
    STATE.sortDirection = 'asc';
  }
  
  // Update header visual indicators
  updateSortIndicators(header, STATE.sortDirection);
  
  // Sort and render
  sortData(STATE.sortField, STATE.sortDirection);
  renderTable();
  renderPagination();
}

/**
 * Update visual sort indicators on table headers
 * @param {HTMLElement} activeHeader - The currently active header
 * @param {string} direction - Sort direction ('asc' or 'desc')
 */
function updateSortIndicators(activeHeader, direction) {
  // Remove sort classes from all sortable headers
  const sortableHeaders = document.querySelectorAll('.sortable');
  sortableHeaders.forEach(header => {
    header.classList.remove('sort-asc', 'sort-desc');
  });
  
  // Add appropriate class to active header
  activeHeader.classList.add(`sort-${direction}`);
}

/**
 * Handle toggle details button click
 */
function handleToggleDetails() {
  STATE.showingDetails = !STATE.showingDetails;
  
  // Update button text
  DOM.toggleDetailsBtn.textContent = STATE.showingDetails ? 'Hide Details' : 'Show Details';
  DOM.toggleDetailsBtn.setAttribute('data-showing', STATE.showingDetails.toString());
  
  // Toggle class on table
  DOM.table.classList.toggle('show-details', STATE.showingDetails);
  
  // Update CNA ScoreCard Rating header text based on view state
  updateScoreCardHeaderText();
}

/**
 * Update the CNA ScoreCard Rating header text based on details view state
 */
function updateScoreCardHeaderText() {
  const scoreHeader = document.querySelector('th[data-sort="score"]');
  if (scoreHeader) {
    const headerText = STATE.showingDetails ? 'Average' : 'CNA ScoreCard Rating';
    // Update the text content while preserving the sort indicator
    const sortIndicator = scoreHeader.querySelector('.sort-indicator');
    scoreHeader.innerHTML = `${headerText} <span class="sort-indicator">${sortIndicator ? sortIndicator.innerHTML : ''}</span>`;
  }
}

/**
 * Handle previous page button click
 */
function handlePrevPage() {
  if (STATE.currentPage > 1) {
    STATE.currentPage--;
    renderTable();
    renderPagination();
    scrollToTop();
  }
}

/**
 * Handle next page button click
 */
function handleNextPage() {
  const totalPages = Math.ceil(STATE.filteredData.length / CONFIG.itemsPerPage);
  
  if (STATE.currentPage < totalPages) {
    STATE.currentPage++;
    renderTable();
    renderPagination();
    scrollToTop();
  }
}

/**
 * Apply all filters to the data
 */
function applyFilters() {
  // Start with all data
  let filtered = [...STATE.data];
  
  // Apply search filter
  if (STATE.searchTerm) {
    const searchLower = STATE.searchTerm.toLowerCase();
    filtered = filtered.filter(cna => {
      // Search in CNA names
      const nameMatch = (cna.shortName && cna.shortName.toLowerCase().includes(searchLower)) ||
                       (cna.organizationName && cna.organizationName.toLowerCase().includes(searchLower));
      
      // Search in CNA types
      const typeMatch = (cna.cnaType && cna.cnaType.toLowerCase().includes(searchLower)) ||
                       (cna.cnaTypes && Array.isArray(cna.cnaTypes) && 
                        cna.cnaTypes.some(type => type && type.toLowerCase().includes(searchLower)));
      
      return nameMatch || typeMatch;
    });
  } else {
    // When no search term, show only active CNAs by default
    filtered = filtered.filter(cna => cna.is_active === true);
  }
  

  
  // Update filtered data and render
  STATE.filteredData = filtered;
  sortData(STATE.sortField, STATE.sortDirection);
  STATE.currentPage = 1; // Reset to first page
  renderTable();
  renderPagination();
  updateCountDisplay();
}

/**
 * Sort the filtered data
 * @param {string} field - Field to sort by
 * @param {string} direction - Sort direction ('asc' or 'desc')
 */
function sortData(field, direction) {
  STATE.filteredData.sort((a, b) => {
    let aVal, bVal;
    
    switch (field) {
      case 'rank':
        aVal = a.rank || 0;
        bVal = b.rank || 0;
        break;
      case 'name':
        aVal = (a.shortName || '').toLowerCase();
        bVal = (b.shortName || '').toLowerCase();
        break;
      case 'type':
        aVal = (a.cnaType || '').toLowerCase();
        bVal = (b.cnaType || '').toLowerCase();
        break;
      case 'cveCount':
        aVal = a.total_cves || 0;
        bVal = b.total_cves || 0;
        break;
      case 'score':
        aVal = a.scores?.overall_average_score || 0;
        bVal = b.scores?.overall_average_score || 0;
        break;
      case 'foundational':
        aVal = a.scores?.foundational_completeness || 0;
        bVal = b.scores?.foundational_completeness || 0;
        break;
      case 'rootcause':
        aVal = a.scores?.root_cause_analysis || 0;
        bVal = b.scores?.root_cause_analysis || 0;
        break;
      case 'software':
        aVal = a.scores?.software_identification || 0;
        bVal = b.scores?.software_identification || 0;
        break;
      case 'severity':
        aVal = a.scores?.severity_and_impact || 0;
        bVal = b.scores?.severity_and_impact || 0;
        break;
      case 'patch':
        aVal = a.scores?.patchinfo || 0;
        bVal = b.scores?.patchinfo || 0;
        break;
      default:
        aVal = 0;
        bVal = 0;
    }
    
    // Handle string vs number comparison
    if (typeof aVal === 'string' && typeof bVal === 'string') {
      return direction === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    } else {
      return direction === 'asc' ? aVal - bVal : bVal - aVal;
    }
  });
}

/**
 * Render the table with current data and pagination
 */
function renderTable() {
  if (!DOM.tableBody) return;
  
  // Clear current table
  DOM.tableBody.innerHTML = '';
  
  // Calculate start and end indices
  const startIndex = (STATE.currentPage - 1) * CONFIG.itemsPerPage;
  const endIndex = Math.min(startIndex + CONFIG.itemsPerPage, STATE.filteredData.length);
  
  // Get current page data
  const pageData = STATE.filteredData.slice(startIndex, endIndex);
  
  // Create table rows
  pageData.forEach(cna => {
    const row = document.createElement('tr');
    
    // Add visual styling for inactive CNAs
    if (!cna.is_active) {
      row.classList.add('inactive-cna');
    }
    
    // Format and create cells - show rank only for active CNAs
    const rankDisplay = cna.is_active ? cna.rank : '-';
    
    // Determine medal-style CSS class based on rank value
    let rankClass = '';
    if (cna.is_active && cna.rank) {
      if (cna.rank === 1) {
        rankClass = 'rank-gold';
      } else if (cna.rank === 2) {
        rankClass = 'rank-silver';
      } else if (cna.rank === 3) {
        rankClass = 'rank-bronze';
      }
    }

    const detailFileParam = cna.detailFile ? `&detailFile=${encodeURIComponent(cna.detailFile)}` : '';
    const detailHref = `cna-detail.html?shortName=${encodeURIComponent(cna.shortName || '')}${detailFileParam}`;
    
    row.innerHTML = `
      <td class="col-rank ${rankClass}" data-label="Rank">${rankDisplay}</td>
      <td class="col-name" data-label="CNA">
        <div class="cna-name-cell">
          <a href="${detailHref}" class="cna-name-link">${cna.shortName}</a>
          <div class="cna-details">
            <div class="org-name">${truncateWithTooltip(cna.organizationName || cna.shortName, 45)}</div>
          </div>
        </div>
      </td>
      <td class="col-type" data-label="Type">${formatCnaTypes(cna.cnaTypes, cna.cnaType, cna.shortName)}</td>
      <td class="col-count" data-label="CVE Count">${cna.total_cves || 0}</td>
      <td class="col-score" data-label="Score">${formatScoreWithBar(cna.scores?.overall_average_score || 0, true)}</td>
      <td class="col-detail" data-column="foundational" data-label="Foundational">${formatScoreWithBar(cna.scores?.foundational_completeness || 0, true)}</td>
      <td class="col-detail" data-column="rootcause" data-label="Root Cause">${formatScoreWithBar(cna.scores?.root_cause_analysis || 0, true)}</td>
      <td class="col-detail" data-column="software" data-label="Software ID">${formatScoreWithBar(cna.scores?.software_identification || 0, true)}</td>
      <td class="col-detail" data-column="severity" data-label="Severity">${formatScoreWithBar(cna.scores?.severity_and_impact || 0, true)}</td>
      <td class="col-detail" data-column="patch" data-label="Patch Info">${formatScoreWithBar(cna.scores?.patchinfo || 0, true)}</td>
    `;
    
    DOM.tableBody.appendChild(row);
  });
  
  // Update count display
  updateCountDisplay();
}

/**
 * Format a score with a visual bar
 * @param {number} score - The score value
 * @param {boolean} isPercentage - Whether this score is a percentage
 * @returns {string} - HTML string for the score display
 */
function formatScoreWithBar(score, isPercentage = false) {
  const value = score || 0;
  const percentage = isPercentage ? value : Math.min(100, (value / 100) * 100);
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
      <div class="score-value">${displayValue}</div>
      <div class="score-bar">
        <div class="score-fill ${colorClass}" style="width: ${percentage}%"></div>
      </div>
    </div>
  `;
}

/**
 * Format CNA types for display
 * @param {Array} types - Array of CNA types
 * @param {string} fallbackType - Fallback single type string
 * @param {string} cnaShortName - CNA short name for special case handling
 * @returns {string} - HTML string for CNA types
 */
function formatCnaTypes(types, fallbackType, cnaShortName) {
  // Special case for MITRE - always show "CNA Of Last Resort"
  if (cnaShortName && cnaShortName.toLowerCase() === 'mitre') {
    return '<span class="cna-type-badge cna-type-cert">CNA Of Last Resort</span>';
  }
  
  // Handle cases where types is not an array or is empty
  if (!Array.isArray(types) || types.length === 0) {
    return fallbackType || 'Unknown';
  }
  
  // Filter out N/A values
  const validTypes = types.filter(type => type && type !== 'N/A' && type !== 'Unknown');
  
  // If no valid types after filtering, return fallback
  if (validTypes.length === 0) {
    return fallbackType || 'Unknown';
  }
  
  // Always use badges, even for single type
  const badges = validTypes.map(type => {
    // Create class name based on type
    let typeClass = '';
    if (type === 'Vendor') {
      typeClass = 'cna-type-vendor';
    } else if (type === 'Open Source') {
      typeClass = 'cna-type-opensource';
    } else if (type === 'CERT') {
      typeClass = 'cna-type-cert';
    } else if (type.includes('Bug Bounty')) {
      typeClass = 'cna-type-bounty';
    } else if (type === 'Consortium') {
      typeClass = 'cna-type-consortium';
    } else if (type === 'Researcher') {
      typeClass = 'cna-type-researcher';
    }
    
    return `<span class="cna-type-badge ${typeClass}">${type}</span>`;
  }).join(' ');
  
  return badges;
}

/**
 * Format trend data
 * @param {Object} trend - Trend data
 * @returns {string} - HTML string for the trend display
 */
function formatTrend(trend) {
  if (!trend) return '';
  
  let icon = '➡️'; // default
  
  if (trend.direction === 'improving') {
    icon = '↗️';
  } else if (trend.direction === 'declining') {
    icon = '↘️';
  }
  
  return `
    <div class="trend-container">
      <span class="trend-indicator" title="${trend.description || ''}">${icon}</span>
    </div>
  `;
}

/**
 * Render pagination controls
 */
function renderPagination() {
  if (!DOM.paginationPages) return;
  
  // Clear current pagination
  DOM.paginationPages.innerHTML = '';
  
  const totalPages = Math.ceil(STATE.filteredData.length / CONFIG.itemsPerPage);
  
  // Update prev/next buttons
  if (DOM.prevPageBtn) {
    DOM.prevPageBtn.disabled = STATE.currentPage === 1;
  }
  
  if (DOM.nextPageBtn) {
    DOM.nextPageBtn.disabled = STATE.currentPage >= totalPages;
  }
  
  // Hide pagination if only one page
  const paginationContainer = document.getElementById('paginationControls');
  if (paginationContainer) {
    paginationContainer.style.display = totalPages <= 1 ? 'none' : 'flex';
  }
  
  if (totalPages <= 1) return;
  
  // Generate page numbers with ellipsis for large ranges
  const pagesToShow = new Set();
  pagesToShow.add(1); // Always show first page
  if (totalPages > 1) pagesToShow.add(totalPages); // Always show last page
  
  // Show current page and some around it
  for (let i = Math.max(1, STATE.currentPage - 1); i <= Math.min(totalPages, STATE.currentPage + 1); i++) {
    pagesToShow.add(i);
  }
  
  // Convert to sorted array
  const sortedPages = Array.from(pagesToShow).sort((a, b) => a - b);
  
  // Render page numbers with ellipses
  let lastRenderedPage = 0;
  sortedPages.forEach(page => {
    if (lastRenderedPage > 0 && page > lastRenderedPage + 1) {
      // Add ellipsis
      const ellipsis = document.createElement('div');
      ellipsis.className = 'page-ellipsis';
      ellipsis.textContent = '…';
      ellipsis.setAttribute('aria-hidden', 'true');
      DOM.paginationPages.appendChild(ellipsis);
    }
    
    // Add page number
    const pageElement = document.createElement('div');
    pageElement.className = 'page-number' + (page === STATE.currentPage ? ' active' : '');
    pageElement.textContent = page;
    pageElement.setAttribute('role', 'button');
    pageElement.setAttribute('aria-label', `Page ${page}${page === STATE.currentPage ? ' (current)' : ''}`);
    pageElement.setAttribute('tabindex', '0');
    pageElement.addEventListener('click', () => goToPage(page));
    DOM.paginationPages.appendChild(pageElement);
    
    lastRenderedPage = page;
  });
}

/**
 * Go to a specific page
 * @param {number} page - Page number
 */
function goToPage(page) {
  if (page === STATE.currentPage) return;
  
  STATE.currentPage = page;
  renderTable();
  renderPagination();
  scrollToTop();
}

/**
 * Update the count display with current pagination info
 */
function updateCountDisplay() {
  if (!DOM.startIndex || !DOM.endIndex || !DOM.totalItems) return;
  
  const startIndex = (STATE.currentPage - 1) * CONFIG.itemsPerPage + 1;
  const endIndex = Math.min(startIndex + CONFIG.itemsPerPage - 1, STATE.filteredData.length);
  const totalItems = STATE.filteredData.length;
  
  DOM.startIndex.textContent = totalItems === 0 ? 0 : startIndex;
  DOM.endIndex.textContent = endIndex;
  DOM.totalItems.textContent = totalItems;
}

/**
 * Show an error message to the user
 * @param {string} message - Error message to display
 */
function showErrorMessage(message) {
  const tableBody = DOM.tableBody;
  
  if (tableBody) {
    tableBody.innerHTML = `<tr><td colspan="11" class="error-message">${message}</td></tr>`;
  }
}

/**
 * Helper function to scroll to top of table
 */
function scrollToTop() {
  DOM.table?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Truncate long text with tooltip support
 * @param {string} text - Text to truncate
 * @param {number} maxLength - Maximum length before truncation
 * @returns {string} - HTML string with truncated text and tooltip
 */
function truncateWithTooltip(text, maxLength = 40) {
  if (!text || text.length <= maxLength) {
    return text || '';
  }
  
  const truncated = text.substring(0, maxLength - 3) + '...';
  return `<span class="truncated-text" title="${text}">${truncated}</span>`;
}

/**
 * Debounce function to limit how often a function is called
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, wait) {
  let timeout;
  return function(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}

/**
 * Handle CSV export - exports current filtered view
 */
function handleExportCsv() {
  const dataToExport = STATE.filteredData;
  
  if (dataToExport.length === 0) {
    alert('No data to export');
    return;
  }
  
  // CSV headers
  const headers = [
    'Rank',
    'Short Name',
    'Organization Name',
    'CNA Type',
    'CVE Count',
    'Overall Score',
    'Foundational Completeness',
    'Root Cause Analysis',
    'Software Identification',
    'Severity & Impact',
    'Patch Info',
    'Status'
  ];
  
  // Convert data to CSV rows
  const rows = dataToExport.map(cna => [
    cna.is_active ? cna.rank : 'N/A',
    escapeCSVField(cna.shortName || ''),
    escapeCSVField(cna.organizationName || cna.shortName || ''),
    escapeCSVField(Array.isArray(cna.cnaTypes) ? cna.cnaTypes.join(', ') : (cna.cnaType || '')),
    cna.total_cves || 0,
    (cna.scores?.overall_average_score || 0).toFixed(2),
    (cna.scores?.foundational_completeness || 0).toFixed(2),
    (cna.scores?.root_cause_analysis || 0).toFixed(2),
    (cna.scores?.software_identification || 0).toFixed(2),
    (cna.scores?.severity_and_impact || 0).toFixed(2),
    (cna.scores?.patchinfo || 0).toFixed(2),
    cna.is_active ? 'Active' : 'Inactive'
  ]);
  
  // Build CSV content
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ].join('\n');
  
  // Download the file
  downloadFile(csvContent, 'cna-rankings.csv', 'text/csv;charset=utf-8;');
}

/**
 * Handle JSON export - exports current filtered view
 */
function handleExportJson() {
  const dataToExport = STATE.filteredData;
  
  if (dataToExport.length === 0) {
    alert('No data to export');
    return;
  }
  
  // Create a clean export format
  const exportData = {
    exportDate: new Date().toISOString(),
    totalCNAs: dataToExport.length,
    filterApplied: STATE.searchTerm ? `Search: "${STATE.searchTerm}"` : 'Active CNAs only',
    sortedBy: STATE.sortField,
    sortDirection: STATE.sortDirection,
    cnas: dataToExport.map(cna => ({
      rank: cna.is_active ? cna.rank : null,
      shortName: cna.shortName,
      organizationName: cna.organizationName || cna.shortName,
      cnaTypes: cna.cnaTypes || [cna.cnaType].filter(Boolean),
      cveCount: cna.total_cves || 0,
      scores: {
        overall: cna.scores?.overall_average_score || 0,
        foundational: cna.scores?.foundational_completeness || 0,
        rootCause: cna.scores?.root_cause_analysis || 0,
        softwareId: cna.scores?.software_identification || 0,
        severity: cna.scores?.severity_and_impact || 0,
        patchInfo: cna.scores?.patchinfo || 0
      },
      isActive: cna.is_active
    }))
  };
  
  // Download the file
  const jsonContent = JSON.stringify(exportData, null, 2);
  downloadFile(jsonContent, 'cna-rankings.json', 'application/json');
}

/**
 * Escape a field for CSV format
 * @param {string} field - Field value to escape
 * @returns {string} - Escaped field
 */
function escapeCSVField(field) {
  if (field === null || field === undefined) return '';
  const stringField = String(field);
  // If field contains comma, newline, or quote, wrap in quotes and escape existing quotes
  if (stringField.includes(',') || stringField.includes('\n') || stringField.includes('"')) {
    return `"${stringField.replace(/"/g, '""')}"`;
  }
  return stringField;
}

/**
 * Download a file with the given content
 * @param {string} content - File content
 * @param {string} filename - Name of the file
 * @param {string} mimeType - MIME type of the file
 */
function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', init);
