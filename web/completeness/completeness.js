// Completeness Page - Complete Refactored Implementation
// Clean, simple approach with reliable CNA ScoreCard field prioritization

// Import chart functions from shared module
import { renderSparkline, renderBarChart, createHorizontalBarChart } from '../shared/charts.js';

console.log('Loading Completeness Page JavaScript...');

// ================================
// GLOBAL STATE
// ================================
let allFieldsData = [];
let filteredFieldsData = [];
let currentSortColumn = 'cna_scorecard';
let currentSortDirection = 'desc';
let selectedCNA = null;

// ================================
// UTILITY FUNCTIONS
// ================================

// Get CNA ScoreCard CSS class based on category
function getCNAScoreCardClass(category) {
  if (!category) return '';
  
  const categoryMap = {
    'foundationalCompleteness': 'cna-scorecard-foundational',
    'rootCauseAnalysis': 'cna-scorecard-root-cause',
    'severityAndImpactContext': 'cna-scorecard-severity',
    'softwareIdentification': 'cna-scorecard-software-id',
    'patchinfo': 'cna-scorecard-patchinfo'
  };
  
  return categoryMap[category] || '';
}

// Render importance badge (matches CNA type badge pattern)
function renderImportanceBadge(importance) {
  if (!importance) {
    return '<span class="importance-badge importance-medium">Medium</span>';
  }
  
  // Create class name based on importance level (matching CNA type logic)
  let importanceClass = '';
  if (importance === 'High') {
    importanceClass = 'importance-high';
  } else if (importance === 'Medium') {
    importanceClass = 'importance-medium';
  } else if (importance === 'Low') {
    importanceClass = 'importance-low';
  }
  
  return `<span class="importance-badge ${importanceClass}">${importance}</span>`;
}

// Render schema field link
function renderSchemaFieldLink(fieldName) {
  const baseUrl = 'https://cveproject.github.io/cve-schema/schema/docs/';
  const fieldPath = fieldName.replace(/\./g, '_');
  const url = `${baseUrl}#oneOf_i0_${fieldPath}`;
  return `<a href="${url}" target="_blank" rel="noopener" class="schema-link">${fieldName}</a>`;
}

// ================================
// SORTING FUNCTIONS
// ================================

// Simple, reliable sorting function
function sortFields(fields, column, direction) {
  return [...fields].sort((a, b) => {
    // Only prioritize CNA ScoreCard measured fields for the default 'cna_scorecard' sort
    // For manual column sorting, perform straight sorts without starred field bias
    if (column === 'cna_scorecard') {
      const aIsMeasured = !!a.cna_scorecard_category;
      const bIsMeasured = !!b.cna_scorecard_category;
      
      if (aIsMeasured !== bIsMeasured) {
        return aIsMeasured ? -1 : 1; // Measured fields first (negative = higher priority)
      }
    }
    
    // Sort by the selected column
    let aVal, bVal;
    
    switch(column) {
      case 'field':
        aVal = a.field || '';
        bVal = b.field || '';
        break;
      case 'percent':
        aVal = parseFloat(a.percent || 0);
        bVal = parseFloat(b.percent || 0);
        break;
      case 'unique_cnas':
        aVal = parseInt(a.unique_cnas || 0);
        bVal = parseInt(b.unique_cnas || 0);
        break;
      case 'importance':
        const importanceOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
        aVal = importanceOrder[a.importance] || 2;
        bVal = importanceOrder[b.importance] || 2;
        break;
      case 'cna_scorecard':
      default:
        // Default: sort by completion percentage
        aVal = parseFloat(a.percent || 0);
        bVal = parseFloat(b.percent || 0);
        break;
    }
    
    // Apply sort direction
    if (direction === 'asc') {
      if (typeof aVal === 'string') return aVal.localeCompare(bVal);
      return aVal - bVal;
    } else {
      if (typeof aVal === 'string') return bVal.localeCompare(aVal);
      return bVal - aVal;
    }
  });
}

// ================================
// RENDERING FUNCTIONS
// ================================

// Render the completeness table
function renderTable(fields) {
  // Hide "CNAs Populating" column when viewing individual CNA data
  const isIndividualCNA = selectedCNA !== null;
  
  const tableHtml = `
    <table class="completeness-table">
      <thead>
        <tr>
          <th class="sortable" data-column="field">
            Field ${getSortIcon('field')}
          </th>
          <th class="sortable" data-column="percent">
            Completeness ${getSortIcon('percent')}
          </th>
          ${!isIndividualCNA ? `
          <th class="sortable" data-column="unique_cnas" style="white-space: nowrap;">
            CNAs Populating ${getSortIcon('unique_cnas')}
          </th>
          ` : ''}
          <th class="sortable" data-column="importance">
            Importance ${getSortIcon('importance')}
          </th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        ${fields.map(field => {
          const cnaScoreCardClass = getCNAScoreCardClass(field.cna_scorecard_category);
          // Debug logging for CSS class application
          if (field.cna_scorecard_category) {
            console.log(`Field ${field.field}: category=${field.cna_scorecard_category}, class=${cnaScoreCardClass}`);
          }
          return `
            <tr class="${cnaScoreCardClass}">
              <td>
                ${field.cna_scorecard_category ? `<span class="star-indicator" title="CNA ScoreCard Measured Field">★</span> ` : ''}
                ${renderSchemaFieldLink(field.field)}
              </td>
              <td class="percent-cell">${field.percent}%</td>
              ${!isIndividualCNA ? `<td class="count-cell">${field.unique_cnas}</td>` : ''}
              <td>${renderImportanceBadge(field.importance)}</td>
              <td class="description-cell">${field.description || ''}</td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
  
  return tableHtml;
}

// Get sort icon for column headers
function getSortIcon(column) {
  if (currentSortColumn !== column) {
    return '<span class="sort-icon">↕</span>';
  }
  
  return currentSortDirection === 'asc' 
    ? '<span class="sort-icon active">↑</span>'
    : '<span class="sort-icon active">↓</span>';
}

// ================================
// EVENT HANDLERS
// ================================

// Add sort event listeners to table headers
function addSortEventListeners() {
  document.querySelectorAll('.sortable').forEach(header => {
    header.addEventListener('click', () => {
      const column = header.dataset.column;
      
      // Toggle direction if same column, otherwise default to desc
      if (currentSortColumn === column) {
        currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
      } else {
        currentSortColumn = column;
        currentSortDirection = 'desc';
      }
      
      // Re-render with new sort
      renderCompleteness();
    });
  });
}

// ================================
// MAIN RENDERING FUNCTION
// ================================

// Main function to render the completeness data
function renderCompleteness() {
  console.log('renderCompleteness called with:', {
    dataLength: filteredFieldsData.length,
    currentSortColumn,
    currentSortDirection
  });
  
  const sortedFields = sortFields(filteredFieldsData, currentSortColumn, currentSortDirection);
  
  console.log('After sorting:');
  console.log('First 5 fields:', sortedFields.slice(0, 5).map(f => ({
    field: f.field,
    category: f.cna_scorecard_category,
    isMeasured: !!f.cna_scorecard_category
  })));
  
  const tableHtml = renderTable(sortedFields);
  
  const overview = document.getElementById('completenessOverview');
  if (overview) {
    overview.innerHTML = tableHtml;
    addSortEventListeners();
    console.log('Table rendered successfully');
  } else {
    console.error('completenessOverview element not found!');
  }
}

// ================================
// DATA LOADING AND INITIALIZATION
// ================================

// Load field utilization data
async function loadFieldData() {
  try {
    console.log('Loading field utilization data...');
    const response = await fetch('../data/field_utilization.json');
    
    if (!response.ok) {
      throw new Error(`Failed to load field data: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('Field data loaded successfully:', data.length, 'fields');
    
    return data;
  } catch (error) {
    console.error('Error loading field data:', error);
    return [];
  }
}

// Load CNA data for search functionality
async function loadCNAData() {
  try {
    console.log('Loading CNA data...');
    // Load the combined data which has correct CVE counts
    const combinedData = await fetch('../data/cna_combined.json').then(resp => resp.json());
    
    console.log('CNA data loaded successfully:', combinedData.length, 'CNAs from combined data');
    // Use combinedData for both search list and scorecards since it has correct CVE counts
    return { cnaList: combinedData, scorecards: combinedData };
  } catch (error) {
    console.error('Error loading CNA data:', error);
    console.error('Make sure cna_combined.json exists in ../data/');
    return { cnaList: [], scorecards: {} };
  }
}

// Setup CNA search functionality
function setupCNASearch(cnaList, scorecards) {
  const searchInput = document.getElementById('cnaSearchInput');
  const searchResults = document.getElementById('cnaSearchResults');
  
  if (!searchInput || !searchResults) {
    console.warn('CNA search elements not found');
    return;
  }
  
  // Sort CNAs by name with safe property access
  const sortedCNAs = cnaList.sort((a, b) => {
    const nameA = a.shortName || a.name || '';
    const nameB = b.shortName || b.name || '';
    return nameA.localeCompare(nameB);
  });
  
  // Track highlighted result index for keyboard navigation
  let highlightedIndex = -1;
  let currentResults = [];
  
  console.log('Setting up keyboard navigation for CNA search');
  
  // Search input handler
  searchInput.addEventListener('input', function(e) {
    const query = e.target.value.toLowerCase().trim();
    
    if (query === '') {
      searchResults.style.display = 'none';
      highlightedIndex = -1;
      currentResults = [];
      return;
    }
    
    // Filter CNAs with safe property access
    const filteredCNAs = sortedCNAs.filter(cna => {
      const shortName = cna.shortName || cna.name || '';
      const cnaId = cna.cnaId || cna.id || '';
      return shortName.toLowerCase().includes(query) || 
             cnaId.toLowerCase().includes(query);
    });
    
    // Show results
    currentResults = filteredCNAs.slice(0, 10);
    displaySearchResults(currentResults);
    
    // Highlight first result by default
    if (currentResults.length > 0) {
      highlightedIndex = 0;
      setTimeout(() => updateHighlight(), 10);
    } else {
      highlightedIndex = -1;
    }
  });
  
  // Keyboard navigation event handler
  searchInput.addEventListener('keydown', function(e) {
    console.log(`Key pressed: ${e.key}, Results visible: ${searchResults.style.display !== 'none'}, Results count: ${currentResults.length}`);
    
    if (searchResults.style.display === 'none' || currentResults.length === 0) {
      console.log('Exiting early - no results or hidden');
      return;
    }
    
    switch(e.key) {
      case 'ArrowDown':
        console.log('Processing ArrowDown');
        e.preventDefault();
        e.stopPropagation();
        highlightedIndex = Math.min(highlightedIndex + 1, currentResults.length - 1);
        console.log(`Arrow Down: highlighting index ${highlightedIndex}`);
        updateHighlight();
        break;
        
      case 'ArrowUp':
        console.log('Processing ArrowUp');
        e.preventDefault();
        e.stopPropagation();
        highlightedIndex = Math.max(highlightedIndex - 1, 0);
        console.log(`Arrow Up: highlighting index ${highlightedIndex}`);
        updateHighlight();
        break;
        
      case 'Enter':
        console.log('Processing Enter');
        e.preventDefault();
        e.stopPropagation();
        if (highlightedIndex >= 0 && highlightedIndex < currentResults.length) {
          const selectedCna = currentResults[highlightedIndex];
          const cnaShortName = selectedCna.shortName || selectedCna.name || '';
          console.log(`Selecting CNA: ${cnaShortName}`, selectedCna);
          selectCNA(cnaShortName, selectedCna, scorecards);
        }
        break;
        
      case 'Escape':
        console.log('Processing Escape');
        searchResults.style.display = 'none';
        highlightedIndex = -1;
        currentResults = [];
        break;
    }
  });
  
  // Function to update highlight styling
  function updateHighlight() {
    const items = searchResults.querySelectorAll('.search-result-item');
    
    if (items.length === 0) {
      console.log('No search result items found for highlighting');
      return;
    }
    
    console.log(`Highlighting index ${highlightedIndex} of ${items.length} items`);
    
    items.forEach((item, index) => {
      if (index === highlightedIndex) {
        item.style.backgroundColor = '#e3f2fd';
        item.style.borderLeft = '3px solid #2196f3';
        item.classList.add('highlighted');
      } else {
        item.style.backgroundColor = 'white';
        item.style.borderLeft = 'none';
        item.classList.remove('highlighted');
      }
    });
  }
  
  // Display search results
  function displaySearchResults(cnas) {
    const resultsHtml = cnas.map((cna, index) => `
      <div class="search-result-item" data-cna-short-name="${cna.shortName || cna.name || ''}" data-index="${index}"
           style="padding: 0.5rem; cursor: pointer; border-bottom: 1px solid #eee; transition: background-color 0.2s ease;"
           onmouseover="this.style.backgroundColor='#f5f5f5'; if (!this.classList.contains('highlighted')) this.style.borderLeft='none';"
           onmouseout="if (!this.classList.contains('highlighted')) { this.style.backgroundColor='white'; this.style.borderLeft='none'; }">
        <strong>${cna.shortName || cna.name || 'Unknown CNA'}</strong> (${cna.recent_cves || cna.total_cves || 0} CVEs)
      </div>
    `).join('');
    
    searchResults.innerHTML = resultsHtml;
    searchResults.style.display = 'block';
    
    // Add click handlers
    searchResults.querySelectorAll('.search-result-item').forEach((item, index) => {
      item.addEventListener('click', async () => {
        const cnaShortName = item.dataset.cnaShortName;
        const selectedCna = cnas.find(c => (c.shortName || c.name) === cnaShortName);
        console.log(`Click handler - CNA short name: ${cnaShortName}, Found CNA:`, selectedCna);
        await selectCNA(cnaShortName, selectedCna, scorecards);
      });
      
      // Update highlighted index on mouse enter for consistency
      item.addEventListener('mouseenter', function() {
        highlightedIndex = index;
        updateHighlight();
      });
    });
  }
  
  // Select a CNA
  async function selectCNA(cnaId, cnaData, scorecards) {
    if (cnaId === 'all' || !cnaId) {
      // Show all data
      selectedCNA = null;
      filteredFieldsData = allFieldsData;
      searchInput.value = '';
      searchInput.placeholder = 'All CNAs (Ecosystem) - Start typing to search...';
      searchResults.style.display = 'none';
      renderCompleteness();
    } else {
      // Show CNA-specific data
      selectedCNA = cnaId;
      searchInput.value = cnaData?.shortName || cnaId;
      searchInput.placeholder = `${cnaData?.shortName || cnaId} - Click to change`;
      searchResults.style.display = 'none';
      
      // Load individual CNA field utilization data
      try {
        console.log(`Loading field utilization data for CNA: ${cnaData?.shortName || cnaId}`);
        console.log('CNA Data:', cnaData);
        
        // Sanitize the shortName for filename (same logic as in the pipeline)
        const shortName = cnaData?.shortName || cnaId;
        const sanitizedName = shortName.replace(/[^a-zA-Z0-9_.-]/g, '_');
        const filename = `${sanitizedName}_completeness.json`;
        const fullUrl = `../data/completeness/${filename}`;
        
        console.log(`Attempting to load file: ${fullUrl}`);
        console.log(`Short name: "${shortName}", Sanitized: "${sanitizedName}", Filename: "${filename}"`);
        
        // First, let's test if we can fetch the aggregate file to verify our path is working
        console.log('Testing aggregate file access first...');
        try {
          const testResponse = await fetch('../data/field_utilization.json');
          console.log(`Aggregate file test - Status: ${testResponse.status}, OK: ${testResponse.ok}`);
        } catch (testError) {
          console.log('Aggregate file test failed:', testError);
        }
        
        const response = await fetch(fullUrl);
        
        console.log(`Response status: ${response.status}`);
        console.log(`Response ok: ${response.ok}`);
        console.log(`Response headers:`, [...response.headers.entries()]);
        
        if (!response.ok) {
          throw new Error(`Failed to load CNA field data: ${response.status} - ${response.statusText}`);
        }
        
        const cnaFieldData = await response.json();
        console.log(`Successfully loaded ${cnaFieldData.length} fields for ${shortName}`);
        console.log('Sample field data:', cnaFieldData.slice(0, 3));
        
        // For individual CNA views, show ALL fields including 0% ones
        // Users want to see the complete picture of what fields the CNA is/isn't populating
        console.log(`Showing all ${cnaFieldData.length} fields for individual CNA view (including 0% fields)`);
        
        filteredFieldsData = cnaFieldData;
        
        renderCompleteness();
        
      } catch (error) {
        console.error(`Error loading field data for CNA ${cnaData?.shortName || cnaId}:`, error);
        console.error('Full error details:', error);
        
        // Fallback to empty data with error message
        filteredFieldsData = [];
        renderCompleteness();
        
        // Show error message in the table area
        const overview = document.getElementById('completenessOverview');
        if (overview) {
          overview.innerHTML = `
            <div class="error-message">
              <h3>Error Loading CNA Data</h3>
              <p>Unable to load field utilization data for ${cnaData?.shortName || cnaId}. The CNA may not have recent CVE data or the file may not exist.</p>
              <p><a href="#" onclick="document.querySelector('#cnaSearchInput').click(); return false;">Click here to search for a different CNA</a></p>
            </div>
          `;
        }
      }
    }
  }
  
  // Click outside to close
  document.addEventListener('click', function(e) {
    if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
      searchResults.style.display = 'none';
    }
  });
  
  // Add "All CNAs" option when clicked
  searchInput.addEventListener('click', function() {
    if (selectedCNA !== null) {
      const allOption = `<div class="search-result-item" data-cna-id="all">All CNAs (Ecosystem)</div>`;
      searchResults.innerHTML = allOption + searchResults.innerHTML;
      searchResults.style.display = 'block';
      
      searchResults.querySelector('[data-cna-id="all"]').addEventListener('click', async () => {
        await selectCNA('all');
      });
    }
  });
}

// ================================
// MAIN INITIALIZATION
// ================================

// Initialize the page
async function initializePage() {
  try {
    console.log('Initializing completeness page...');
    
    // Load all data
    const [fieldData, cnaData] = await Promise.all([
      loadFieldData(),
      loadCNAData()
    ]);
    
    console.log('Field data loaded:', fieldData.length, 'fields');
    console.log('Sample field data:', fieldData.slice(0, 3));
    
    // Count measured vs non-measured fields
    const measuredFields = fieldData.filter(f => f.cna_scorecard_category);
    const nonMeasuredFields = fieldData.filter(f => !f.cna_scorecard_category);
    console.log('Measured fields:', measuredFields.length);
    console.log('Non-measured fields:', nonMeasuredFields.length);
    console.log('Sample measured fields:', measuredFields.slice(0, 3).map(f => ({field: f.field, category: f.cna_scorecard_category})));
    
    // Filter out fields with 0% completion for aggregate "All CNAs" view to keep table manageable
    // Individual CNA views will show all fields including 0% ones
    const fieldsWithData = fieldData.filter(field => field.percent > 0);
    console.log(`Filtered out ${fieldData.length - fieldsWithData.length} fields with 0% completion for aggregate view`);
    
    // Store data globally
    allFieldsData = fieldsWithData;
    filteredFieldsData = fieldsWithData;
    
    // Setup CNA search
    setupCNASearch(cnaData.cnaList, cnaData.scorecards);
    
    // Initial render with CNA ScoreCard fields at top
    console.log('About to render completeness with sorting...');
    renderCompleteness();
    
    console.log('Completeness page initialized successfully');
    
  } catch (error) {
    console.error('Error initializing completeness page:', error);
    
    // Show error message
    const overview = document.getElementById('completenessOverview');
    if (overview) {
      overview.innerHTML = `
        <div class="error-message">
          <h3>Error Loading Data</h3>
          <p>Unable to load completeness data. Please try refreshing the page.</p>
        </div>
      `;
    }
  }
}

// ================================
// INITIALIZE WHEN DOM IS READY
// ================================

document.addEventListener('DOMContentLoaded', function() {
  initializePage();
});

console.log('Completeness Page JavaScript loaded successfully');
