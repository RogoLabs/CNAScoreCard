// Completeness Dashboard Logic - Dynamic Rendering

// Comprehensive mapping from field name to schema anchor for CVE 5.1 Schema
const schemaAnchorMap = {
  // Core CVE metadata fields
  "dataVersion": "#oneOf_i0_dataVersion",
  "cveMetadata.serial": "#oneOf_i0_cveMetadata_serial",
  
  // CNA Container core fields
  "containers.cna.descriptions": "#oneOf_i0_containers_cna_descriptions",
  "containers.cna.affected": "#oneOf_i0_containers_cna_affected",
  "containers.cna.references": "#oneOf_i0_containers_cna_references",
  "containers.cna.title": "#oneOf_i0_containers_cna_title",
  "containers.cna.dateAssigned": "#oneOf_i0_containers_cna_dateAssigned",
  "containers.cna.datePublic": "#oneOf_i0_containers_cna_datePublic",
  "containers.cna.problemTypes": "#oneOf_i0_containers_cna_problemTypes",
  "containers.cna.metrics": "#oneOf_i0_containers_cna_metrics",
  "containers.cna.impacts": "#oneOf_i0_containers_cna_impacts",
  "containers.cna.configurations": "#oneOf_i0_containers_cna_configurations",
  "containers.cna.workarounds": "#oneOf_i0_containers_cna_workarounds",
  "containers.cna.solutions": "#oneOf_i0_containers_cna_solutions",
  "containers.cna.exploits": "#oneOf_i0_containers_cna_exploits",
  "containers.cna.timeline": "#oneOf_i0_containers_cna_timeline",
  "containers.cna.credits": "#oneOf_i0_containers_cna_credits",
  "containers.cna.source": "#oneOf_i0_containers_cna_source",
  "containers.cna.tags": "#oneOf_i0_containers_cna_tags",
  "containers.cna.taxonomyMappings": "#oneOf_i0_containers_cna_taxonomyMappings",
  "containers.cna.cpeApplicability": "#oneOf_i0_containers_cna_cpeApplicability",
  
  // ADP Container
  "containers.adp": "#oneOf_i0_containers_adp",
  
  // Descriptions analysis (custom checks)
  "descriptions.english": "#oneOf_i0_containers_cna_descriptions",
  "descriptions.multiple_languages": "#oneOf_i0_containers_cna_descriptions",
  "descriptions.supporting_media": "#oneOf_i0_containers_cna_descriptions",
  
  // Affected products analysis (custom checks)
  "affected.vendor": "#oneOf_i0_containers_cna_affected",
  "affected.product": "#oneOf_i0_containers_cna_affected",
  "affected.versions": "#oneOf_i0_containers_cna_affected",
  "affected.defaultStatus": "#oneOf_i0_containers_cna_affected",
  "affected.cpes": "#oneOf_i0_containers_cna_affected",
  "affected.modules": "#oneOf_i0_containers_cna_affected",
  "affected.programFiles": "#oneOf_i0_containers_cna_affected",
  "affected.programRoutines": "#oneOf_i0_containers_cna_affected",
  "affected.platforms": "#oneOf_i0_containers_cna_affected",
  "affected.repo": "#oneOf_i0_containers_cna_affected",
  
  // Problem Types analysis (custom checks)
  "problemTypes.cwe": "#oneOf_i0_containers_cna_problemTypes",
  "problemTypes.type": "#oneOf_i0_containers_cna_problemTypes",
  "problemTypes.references": "#oneOf_i0_containers_cna_problemTypes",
  
  // References analysis (custom checks)
  "references.advisory": "#oneOf_i0_containers_cna_references",
  "references.patch": "#oneOf_i0_containers_cna_references",
  "references.exploit": "#oneOf_i0_containers_cna_references",
  "references.technical": "#oneOf_i0_containers_cna_references",
  "references.vendor": "#oneOf_i0_containers_cna_references",
  "references.named": "#oneOf_i0_containers_cna_references",
  
  // Metrics analysis (custom checks)
  "metrics.cvssV4": "#oneOf_i0_containers_cna_metrics",
  "metrics.cvssV3_1": "#oneOf_i0_containers_cna_metrics",
  "metrics.cvssV3_0": "#oneOf_i0_containers_cna_metrics",
  "metrics.cvssV2": "#oneOf_i0_containers_cna_metrics",
  "metrics.other": "#oneOf_i0_containers_cna_metrics",
  "metrics.scenarios": "#oneOf_i0_containers_cna_metrics"
};

function renderSchemaFieldLink(field) {
  const anchor = schemaAnchorMap[field] || ("#oneOf_i0_" + field.replace(/\./g, '_'));
  const label = field.replace(/\./g, ' \u2192 ');
  return `<a href="https://cveproject.github.io/cve-schema/schema/docs/${anchor}" target="_blank" rel="noopener" class="schema-link">${label}</a>`;
}

document.addEventListener('DOMContentLoaded', function() {
  const overview = document.getElementById('completenessOverview');
  const cnaSearchInput = document.getElementById('cnaSearchInput');
  const cnaSearchResults = document.getElementById('cnaSearchResults');
  
  // Sorting state
  let currentSortColumn = 'cna_scorecard';
  let currentSortDirection = 'desc'; // Default to CNA ScoreCard fields first
  
  // Global data storage
  let allFields = [];
  let cnaData = [];
  let cnaScorecardsData = {};

  // Define canonical field order based on schema importance
  const canonicalFieldOrder = [
    "cveMetadata.serial",
    "containers.cna.descriptions",
    "containers.cna.affected",
    "containers.cna.references",
    "containers.cna.title",
    "containers.cna.dateAssigned",
    "containers.cna.datePublic",
    "containers.cna.problemTypes",
    "containers.cna.metrics",
    "containers.cna.impacts",
    "containers.cna.configurations",
    "containers.cna.workarounds",
    "containers.cna.solutions",
    "containers.cna.exploits",
    "containers.cna.timeline",
    "containers.cna.credits",
    "containers.cna.source",
    "containers.cna.tags",
    "containers.cna.taxonomyMappings",
    "containers.cna.cpeApplicability",
    "containers.adp",
    "descriptions.english",
    "descriptions.multiple_languages",
    "descriptions.supporting_media",
    "affected.vendor",
    "affected.product",
    "affected.versions",
    "affected.defaultStatus",
    "affected.cpes",
    "affected.modules",
    "affected.programFiles",
    "affected.programRoutines",
    "affected.platforms",
    "affected.repo",
    "problemTypes.cwe",
    "problemTypes.type"
  ];

  // Render importance badge based on field importance level
  function renderImportanceBadge(importance) {
    const badgeClass = importance === 'High' ? 'high' : importance === 'Medium' ? 'medium' : 'low';
    return `<span class="importance-badge ${badgeClass}">${importance}</span>`;
  }

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

  // Sort fields with CNA ScoreCard fields always at top
  function sortFields(fields, column, direction) {
    // Separate CNA ScoreCard measured fields from non-measured fields
    const measuredFields = fields.filter(field => field.cna_scorecard_category);
    const nonMeasuredFields = fields.filter(field => !field.cna_scorecard_category);
    
    // Sort each group separately
    const sortedMeasured = sortFieldGroup(measuredFields, column, direction);
    const sortedNonMeasured = sortFieldGroup(nonMeasuredFields, column, direction);
    
    // Always return measured fields first, then non-measured
    return [...sortedMeasured, ...sortedNonMeasured];
  }
  
  // Helper function to sort a group of fields by column
  function sortFieldGroup(fields, column, direction) {
    return fields.sort((a, b) => {
      let aVal, bVal;
      
      switch(column) {
        case 'field':
          aVal = a.field;
          bVal = b.field;
          break;
        case 'importance':
          const importanceOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
          aVal = importanceOrder[a.importance] || 0;
          bVal = importanceOrder[b.importance] || 0;
          break;
        case 'percent':
          aVal = parseFloat(a.percent ?? 0);
          bVal = parseFloat(b.percent ?? 0);
          break;
        case 'unique_cnas':
          aVal = parseInt(a.unique_cnas ?? 0);
          bVal = parseInt(b.unique_cnas ?? 0);
          break;
        case 'description':
          aVal = (a.description || '').toLowerCase();
          bVal = (b.description || '').toLowerCase();
          break;
        case 'cna_scorecard':
        default:
          // Default sort by completion percentage
          aVal = parseFloat(a.percent ?? 0);
          bVal = parseFloat(b.percent ?? 0);
          break;
      }
      
      if (direction === 'asc') {
        return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      } else {
        return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
      }
    });
  }

  // Render a single table with all fields
  function renderTable(fields) {
    const tableHtml = `
      <div class="completeness-table-container">
        <table class="completeness-table">
          <thead>
            <tr>
              <th class="sortable" data-column="field">Field ${getSortIcon('field')}</th>
              <th class="sortable" data-column="percent">Completeness ${getSortIcon('percent')}</th>
              <th class="sortable" data-column="unique_cnas">CNAs Populating ${getSortIcon('unique_cnas')}</th>
              <th class="sortable" data-column="importance">Importance ${getSortIcon('importance')}</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            ${fields.map(field => {
              const cnaScoreCardClass = getCNAScoreCardClass(field.cna_scorecard_category);
              return `
                <tr class="${cnaScoreCardClass}">
                  <td>${renderSchemaFieldLink(field.field)}</td>
                  <td class="percent-cell">${field.percent}%</td>
                  <td class="count-cell">${field.unique_cnas}</td>
                  <td>${renderImportanceBadge(field.importance)}</td>
                  <td class="description-cell">${field.description || ''}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
    return tableHtml;
  }

  // Get sort icon for column header
  function getSortIcon(column) {
    if (currentSortColumn !== column) {
      return '<span class="sort-icon">↕</span>';
    }
    return currentSortDirection === 'asc' ? 
      '<span class="sort-icon active">↑</span>' : 
      '<span class="sort-icon active">↓</span>';
  }
  
  // Load the completeness data
  fetch('../data/field_utilization.json')
    .then(response => response.json())
    .then(data => {
      allFields = data;
      // Display all fields from the data (already sorted by the pipeline)
      displayCompleteness(allFields);
    })
    .catch(error => {
      console.error('Error loading data:', error);
      overview.innerHTML = '<p>Error loading completeness data.</p>';
    });
    
  // Load CNA data
  Promise.all([
    fetch('../data/cna_summary.json').then(resp => resp.json()),
    fetch('../data/cna_combined.json').then(resp => resp.json())
  ])
    .then(([cnaList, combinedData]) => {
      console.log('CNA data loaded successfully:', cnaList.length, 'CNAs');
      cnaData = cnaList;
      allCNAScorecardsData = combinedData;
      
      // Setup CNA search functionality
      setupCNASearch(cnaList);
    })
    .catch(error => {
      console.error('Error loading CNA data:', error);
      console.error('Make sure cna_summary.json and cna_combined.json exist in ../data/');
    });
  
  // Function to setup CNA search functionality
  function setupCNASearch(cnaList) {
    // Sort CNAs by name for consistent display
    const sortedCNAs = cnaList.sort((a, b) => a.shortName.localeCompare(b.shortName));
    
    // Current selected CNA (null means "All CNAs")
    let selectedCNA = null;
    
    // Track highlighted result index for keyboard navigation
    let highlightedIndex = -1;
    let currentResults = [];
    
    // Search input event handler
    cnaSearchInput.addEventListener('input', function(e) {
      const query = e.target.value.toLowerCase().trim();
      
      if (query === '') {
        // Hide results when empty
        cnaSearchResults.style.display = 'none';
        highlightedIndex = -1;
        currentResults = [];
        return;
      }
      
      // Filter CNAs based on search query
      const filteredCNAs = sortedCNAs.filter(cna => 
        cna.shortName.toLowerCase().includes(query) || 
        cna.cnaId.toLowerCase().includes(query)
      );
      
      // Show search results
      currentResults = filteredCNAs.slice(0, 10); // Limit to 10 results
      displaySearchResults(currentResults);
      
      // Highlight first result by default after DOM is updated
      if (currentResults.length > 0) {
        highlightedIndex = 0;
        // Use setTimeout to ensure DOM is rendered before highlighting
        setTimeout(() => updateHighlight(), 10);
      } else {
        highlightedIndex = -1;
      }
    });
    
    // Add multiple event listeners to debug what's happening
    console.log('Setting up keyboard navigation for:', cnaSearchInput);
    
    // Test basic keydown capture
    cnaSearchInput.addEventListener('keydown', function(e) {
      console.log(`KEYDOWN EVENT FIRED: Key=${e.key}, Code=${e.code}, Target=${e.target.id}`);
    }, true); // Use capture phase
    
    // Test keyup as well
    cnaSearchInput.addEventListener('keyup', function(e) {
      console.log(`KEYUP EVENT FIRED: Key=${e.key}, Code=${e.code}`);
    });
    
    // Main keyboard navigation event handler
    cnaSearchInput.addEventListener('keydown', function(e) {
      console.log(`Main handler - Key pressed: ${e.key}, Results visible: ${cnaSearchResults.style.display !== 'none'}, Results count: ${currentResults.length}`);
      
      // Always log arrow keys, even if conditions aren't met
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter') {
        console.log(`Arrow/Enter key detected: ${e.key}`);
        console.log(`Search results display: ${cnaSearchResults.style.display}`);
        console.log(`Current results length: ${currentResults.length}`);
        console.log(`Highlighted index: ${highlightedIndex}`);
      }
      
      if (cnaSearchResults.style.display === 'none' || currentResults.length === 0) {
        console.log('Exiting early - no results or hidden');
        return;
      }
      
      switch(e.key) {
        case 'ArrowDown':
          console.log('Processing ArrowDown');
          e.preventDefault();
          e.stopPropagation();
          const newDownIndex = Math.min(highlightedIndex + 1, currentResults.length - 1);
          console.log(`Arrow Down: ${highlightedIndex} -> ${newDownIndex}`);
          highlightedIndex = newDownIndex;
          updateHighlight();
          break;
          
        case 'ArrowUp':
          console.log('Processing ArrowUp');
          e.preventDefault();
          e.stopPropagation();
          const newUpIndex = Math.max(highlightedIndex - 1, 0);
          console.log(`Arrow Up: ${highlightedIndex} -> ${newUpIndex}`);
          highlightedIndex = newUpIndex;
          updateHighlight();
          break;
          
        case 'Enter':
          console.log('Processing Enter');
          e.preventDefault();
          e.stopPropagation();
          console.log(`Enter pressed with highlighted index: ${highlightedIndex}`);
          if (highlightedIndex >= 0 && highlightedIndex < currentResults.length) {
            const selectedCna = currentResults[highlightedIndex];
            console.log(`Selecting CNA: ${selectedCna.shortName}`);
            selectCNA(selectedCna);
          }
          break;
          
        case 'Escape':
          console.log('Processing Escape');
          cnaSearchResults.style.display = 'none';
          highlightedIndex = -1;
          currentResults = [];
          break;
      }
    });
    
    // Handle clicks outside search box to close results
    document.addEventListener('click', function(e) {
      if (!cnaSearchInput.contains(e.target) && !cnaSearchResults.contains(e.target)) {
        cnaSearchResults.style.display = 'none';
        highlightedIndex = -1;
        currentResults = [];
      }
    });
    
    // Handle search input focus
    cnaSearchInput.addEventListener('focus', function() {
      if (this.value.trim() !== '') {
        const query = this.value.toLowerCase().trim();
        const filteredCNAs = sortedCNAs.filter(cna => 
          cna.shortName.toLowerCase().includes(query) || 
          cna.cnaId.toLowerCase().includes(query)
        );
        currentResults = filteredCNAs.slice(0, 10);
        displaySearchResults(currentResults);
        
        // Highlight first result by default after DOM is updated
        if (currentResults.length > 0) {
          highlightedIndex = 0;
          setTimeout(() => updateHighlight(), 10);
        } else {
          highlightedIndex = -1;
        }
      }
    });
    
    // Function to update highlight styling
    function updateHighlight() {
      const items = cnaSearchResults.querySelectorAll('.search-result-item');
      
      // Debug: Check if items exist
      if (items.length === 0) {
        console.log('No search result items found for highlighting');
        return;
      }
      
      // Debug: Log current state
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
    
    // Function to display search results
    function displaySearchResults(results) {
      if (results.length === 0) {
        cnaSearchResults.innerHTML = '<div style="padding: 0.5rem; color: #666;">No CNAs found</div>';
        cnaSearchResults.style.display = 'block';
        return;
      }
      
      const resultsHtml = results.map((cna, index) => `
        <div class="search-result-item" data-cna-id="${cna.cnaId}" data-index="${index}"
             style="padding: 0.5rem; cursor: pointer; border-bottom: 1px solid #eee; transition: background-color 0.2s ease;"
             onmouseover="this.style.backgroundColor='#f5f5f5'; if (!this.classList.contains('highlighted')) this.style.borderLeft='none';"
             onmouseout="if (!this.classList.contains('highlighted')) { this.style.backgroundColor='white'; this.style.borderLeft='none'; }">
          <strong>${cna.shortName}</strong> (${cna.cveCount} CVEs)
        </div>
      `).join('');
      
      cnaSearchResults.innerHTML = resultsHtml;
      cnaSearchResults.style.display = 'block';
      
      // Add click handlers to search results
      cnaSearchResults.querySelectorAll('.search-result-item').forEach((item, index) => {
        item.addEventListener('click', function() {
          const cnaId = this.getAttribute('data-cna-id');
          const cna = sortedCNAs.find(c => c.cnaId === cnaId);
          selectCNA(cna);
        });
        
        // Update highlighted index on mouse enter for consistency
        item.addEventListener('mouseenter', function() {
          highlightedIndex = index;
          updateHighlight();
        });
      });
    }
    
    // Function to select a CNA
    function selectCNA(cna) {
      selectedCNA = cna;
      if (cna) {
        cnaSearchInput.value = `${cna.shortName} (${cna.cveCount} CVEs)`;
        // Show CNA-specific data
        displayCNACompleteness(cna.cnaId);
      } else {
        cnaSearchInput.value = '';
        cnaSearchInput.placeholder = 'All CNAs (Ecosystem) - Start typing to search...';
        // Show all CNAs data
        displayCompleteness(allFields);
      }
      cnaSearchResults.style.display = 'none';
      highlightedIndex = -1;
      currentResults = [];
    }
    
    // Add "All CNAs" option when clicked
    cnaSearchInput.addEventListener('click', function() {
      if (selectedCNA !== null) {
        const allCNAsOption = `<div class="search-result-item" data-cna-id="all" 
             style="padding: 0.5rem; cursor: pointer; border-bottom: 1px solid #eee; font-weight: bold;"
             onmouseover="this.style.backgroundColor='#f5f5f5'"
             onmouseout="this.style.backgroundColor='white'">
          All CNAs (Ecosystem)
        </div>`;
        
        cnaSearchResults.innerHTML = allCNAsOption + cnaSearchResults.innerHTML;
        cnaSearchResults.style.display = 'block';
        
        // Add click handler for "All CNAs" option
        cnaSearchResults.querySelector('[data-cna-id="all"]').addEventListener('click', function() {
          selectCNA(null);
        });
      }
    });
    
    // Function to display CNA-specific completeness
    function displayCNACompleteness(cnaId) {
      if (cnaScorecardsData && cnaScorecardsData[cnaId]) {
        const cnaScorecard = cnaScorecardsData[cnaId];
        displayCompleteness(cnaScorecard.fields || []);
      }
    }
  }
  
  // Function to display completeness data
  function displayCompleteness(fields) {
    // Use the new sorting logic with default CNA ScoreCard priority
    const sortedFields = sortFields(fields, currentSortColumn, currentSortDirection);
    const html = renderTable(sortedFields);
    overview.innerHTML = html;
    addSortEventListeners();
  }
  
  // Handle CNA selection change
  cnaSelect.addEventListener('change', function() {
    const selectedCNAId = this.value;
    
    if (selectedCNAId === 'all') {
      // Show all CNAs data
      displayCompleteness(allFields);
    } else {
      // Show specific CNA data
      const selectedCNA = cnaData.find(cna => cna.cnaId === selectedCNAId);
      const cnaScorecard = cnaScorecardsData[selectedCNAId];
      
      if (selectedCNA && cnaScorecard) {
        displayCNASpecificData(selectedCNA, cnaScorecard);
      } else {
        console.error('CNA data not found for:', selectedCNAId);
        displayCompleteness(allFields);
      }
    }
  });
  
  // Function to display CNA-specific data
  function displayCNASpecificData(cna, scorecard) {
    // Convert CNA-specific field completeness to the same format as all-CNAs data
    const cnaFields = scorecard.fieldCompleteness.map(field => ({
      field: field.field,
      percent: field.completionPercent,
      unique_cnas: 1, // Always 1 for individual CNA
      importance: field.importance,
      description: getFieldDescription(field.field)
    }));
    
    displayCompleteness(cnaFields);
    
    // Update page title to show selected CNA
    const titleElement = document.querySelector('.contextual-heading-title');
    if (titleElement) {
      titleElement.textContent = `${cna.shortName} - Field Completeness`;
    }
  }
  
  // Helper function to get field description
  function getFieldDescription(fieldName) {
    const field = allFields.find(f => f.field === fieldName);
    return field ? field.description : '';
  }
  
  // Function to add sort event listeners
  function addSortEventListeners() {
    document.querySelectorAll('.sortable').forEach(header => {
      header.addEventListener('click', () => {
        const column = header.dataset.column;
        
        // Toggle sort direction if same column, otherwise default to desc
        if (currentSortColumn === column) {
          currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
        } else {
          currentSortColumn = column;
          currentSortDirection = column === 'importance' ? 'desc' : 'asc';
        }
        
        // Re-render table with new sort
        const currentFields = getCurrentFields();
        const sortedFields = sortFields(currentFields, currentSortColumn, currentSortDirection);
        const tableHtml = renderTable(sortedFields);
        overview.innerHTML = tableHtml;
        addSortEventListeners();
      });
    });
  }
  
  // Helper function to get current fields being displayed
  function getCurrentFields() {
    const selectedCNAId = cnaSelect.value;
    
    if (selectedCNAId === 'all') {
      return allFields;
    } else {
      const selectedCNA = cnaData.find(cna => cna.cnaId === selectedCNAId);
      const cnaScorecard = cnaScorecardsData[selectedCNAId];
      
      if (selectedCNA && cnaScorecard) {
        return cnaScorecard.fieldCompleteness.map(field => ({
          field: field.field,
          percent: field.completionPercent,
          unique_cnas: 1,
          importance: field.importance,
          description: getFieldDescription(field.field)
        }));
      }
    }
    
    return allFields;
  }
});
