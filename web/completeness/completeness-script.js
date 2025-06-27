// CVE Data Completeness Analysis JavaScript

let completenessData = [];
let summaryData = {};
let missingCvesData = [];
let currentSort = 'completeness';
let currentView = 'table';

// DOM elements
const tableView = document.getElementById('table-view');
const chartView = document.getElementById('chart-view');
const tableViewBtn = document.getElementById('table-view-btn');
const chartViewBtn = document.getElementById('chart-view-btn');
const cnaSearch = document.getElementById('cna-search');
const sortSelect = document.getElementById('sort-select');
const completenessTableBody = document.getElementById('completeness-table-body');

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadCompletenessData();
    setupEventListeners();
    setupTabs();
});

// Load completeness data
async function loadCompletenessData() {
    try {
        // Load CNA completeness data
        const cnaResponse = await fetch('cna_completeness.json');
        completenessData = await cnaResponse.json();
        
        // Load summary data
        const summaryResponse = await fetch('completeness_summary.json');
        summaryData = await summaryResponse.json();
        
        // Extract missing CVEs data
        missingCvesData = summaryData.cves_missing_required_fields || [];
        
        // Initialize the interface
        updateOverviewStats();
        updateMissingCvesSection();
        renderTable();
        renderFieldAnalysis();
        updateLastUpdated();
        
    } catch (error) {
        console.error('Error loading completeness data:', error);
        showErrorMessage('Failed to load completeness data. Please try again later.');
    }
}

// Update overview statistics
function updateOverviewStats() {
    document.getElementById('overall-completeness').textContent = 
        `${summaryData.global_completeness?.overall_completeness?.toFixed(1) || '0.0'}%`;
    
    document.getElementById('required-completeness').textContent = 
        `${summaryData.global_completeness?.required_fields_completeness?.toFixed(1) || '0.0'}%`;
        
    document.getElementById('optional-completeness').textContent = 
        `${summaryData.global_completeness?.optional_fields_completeness?.toFixed(1) || '0.0'}%`;
        
    document.getElementById('total-cnas').textContent = 
        summaryData.total_cnas || '0';
}

// Setup event listeners
function setupEventListeners() {
    // View toggle buttons
    tableViewBtn.addEventListener('click', () => switchView('table'));
    chartViewBtn.addEventListener('click', () => switchView('chart'));
    
    // Search and sort
    cnaSearch.addEventListener('input', filterAndRenderTable);
    sortSelect.addEventListener('change', (e) => {
        currentSort = e.target.value;
        filterAndRenderTable();
    });
}

// Setup tab functionality
function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            
            // Update active tab button
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Update active tab content
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(`${tabId}-fields`).classList.add('active');
        });
    });
}

// Update missing CVEs section
function updateMissingCvesSection() {
    const missingCount = missingCvesData.length;
    const totalCves = summaryData.total_cves_analyzed || 1;
    const percentage = ((missingCount / totalCves) * 100).toFixed(2);
    
    // Update stats
    document.getElementById('missing-cves-count').textContent = missingCount;
    document.getElementById('missing-percentage').textContent = `${percentage}%`;
    
    // Render missing CVEs table
    renderMissingCvesTable();
    
    // Setup event listeners for missing CVEs section
    setupMissingCvesEventListeners();
}

// Setup event listeners for missing CVEs section
function setupMissingCvesEventListeners() {
    const searchInput = document.getElementById('missing-cves-search');
    const sortSelect = document.getElementById('missing-cves-sort');
    
    if (searchInput) {
        searchInput.addEventListener('input', renderMissingCvesTable);
    }
    
    if (sortSelect) {
        sortSelect.addEventListener('change', renderMissingCvesTable);
    }
}

// Render missing CVEs table
function renderMissingCvesTable() {
    const container = document.getElementById('missing-cves-table');
    if (!container) return;
    
    const searchTerm = document.getElementById('missing-cves-search')?.value.toLowerCase() || '';
    const sortBy = document.getElementById('missing-cves-sort')?.value || 'date';
    
    // Filter CVEs
    let filteredCves = missingCvesData.filter(cve => 
        cve.cveId.toLowerCase().includes(searchTerm) ||
        cve.assigningCna.toLowerCase().includes(searchTerm) ||
        cve.missingRequiredFields.some(field => field.toLowerCase().includes(searchTerm))
    );
    
    // Sort CVEs
    filteredCves.sort((a, b) => {
        switch (sortBy) {
            case 'date':
                return new Date(b.datePublished || 0) - new Date(a.datePublished || 0);
            case 'cve':
                return a.cveId.localeCompare(b.cveId);
            case 'cna':
                return a.assigningCna.localeCompare(b.assigningCna);
            case 'fields':
                return b.missingRequiredFields.length - a.missingRequiredFields.length;
            default:
                return 0;
        }
    });
    
    if (filteredCves.length === 0) {
        container.innerHTML = `
            <div class="empty-missing-fields">
                <div class="icon">✅</div>
                <h3>Excellent Schema Compliance!</h3>
                <p>All CVEs have required fields present, or no CVEs match your search criteria.</p>
            </div>
        `;
        return;
    }
    
    // Create table
    const tableHTML = `
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>CNA</th>
                    <th>Date Published</th>
                    <th>Missing Required Fields</th>
                </tr>
            </thead>
            <tbody>
                ${filteredCves.map(cve => `
                    <tr>
                        <td>
                            <a href="https://cve.org/CVERecord?id=${cve.cveId}" 
                               target="_blank" 
                               rel="noopener noreferrer" 
                               class="cve-link">
                                ${cve.cveId}
                            </a>
                        </td>
                        <td>
                            <span class="cna-badge">${escapeHtml(cve.assigningCna)}</span>
                        </td>
                        <td class="date-cell">
                            ${cve.datePublished ? new Date(cve.datePublished).toLocaleDateString() : 'Unknown'}
                        </td>
                        <td>
                            ${cve.missingRequiredFields.map(field => 
                                `<span class="missing-fields-badge">${escapeHtml(formatFieldName(field))}</span>`
                            ).join('')}
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
}

// Format field names for display
function formatFieldName(fieldName) {
    return fieldName
        .replace(/^containers\.cna\./, '')
        .replace(/^affected\./, 'affected: ')
        .replace(/^descriptions\./, 'descriptions: ')
        .replace(/([A-Z])/g, ' $1')
        .replace(/^\w/, c => c.toUpperCase());
}

// Switch between table and chart views
function switchView(view) {
    currentView = view;
    
    if (view === 'table') {
        tableView.style.display = 'block';
        chartView.style.display = 'none';
        tableViewBtn.classList.add('active');
        chartViewBtn.classList.remove('active');
    } else {
        tableView.style.display = 'none';
        chartView.style.display = 'block';
        tableViewBtn.classList.remove('active');
        chartViewBtn.classList.add('active');
        renderCharts();
    }
}

// Filter and render table based on search and sort
function filterAndRenderTable() {
    const searchTerm = cnaSearch.value.toLowerCase();
    let filteredData = completenessData.filter(cna => 
        cna.cna.toLowerCase().includes(searchTerm)
    );
    
    // Sort data
    filteredData.sort((a, b) => {
        switch (currentSort) {
            case 'name':
                return a.cna.localeCompare(b.cna);
            case 'cves':
                return b.total_cves - a.total_cves;
            case 'required':
                return b.required_fields_completeness - a.required_fields_completeness;
            case 'optional':
                return b.optional_fields_completeness - a.optional_fields_completeness;
            case 'completeness':
            default:
                return b.completeness_score - a.completeness_score;
        }
    });
    
    renderTable(filteredData);
}

// Render the completeness table
function renderTable(data = completenessData) {
    completenessTableBody.innerHTML = '';
    
    data.forEach((cna, index) => {
        const row = document.createElement('tr');
        
        // Determine percentile class for styling
        const percentileClass = getPercentileClass(cna.percentile);
        
        row.innerHTML = `
            <td class="rank-cell">${index + 1}</td>
            <td class="cna-cell">${escapeHtml(cna.cna)}</td>
            <td class="score-cell">
                <div class="score-bar">
                    <span class="score-value">${cna.completeness_score}%</span>
                    <div class="progress-bar">
                        <div class="progress-fill ${percentileClass}" style="width: ${cna.completeness_score}%"></div>
                    </div>
                </div>
            </td>
            <td>
                <div class="score-bar">
                    <span class="score-value">${cna.required_fields_completeness}%</span>
                    <div class="progress-bar">
                        <div class="progress-fill ${getScoreClass(cna.required_fields_completeness)}" 
                             style="width: ${cna.required_fields_completeness}%"></div>
                    </div>
                </div>
            </td>
            <td>
                <div class="score-bar">
                    <span class="score-value">${cna.optional_fields_completeness}%</span>
                    <div class="progress-bar">
                        <div class="progress-fill ${getScoreClass(cna.optional_fields_completeness)}" 
                             style="width: ${cna.optional_fields_completeness}%"></div>
                    </div>
                </div>
            </td>
            <td>${cna.total_cves.toLocaleString()}</td>
            <td>
                <span class="percentile-badge ${percentileClass}">${cna.percentile}%</span>
            </td>
            <td>
                <button class="details-btn" onclick="showCNADetails('${escapeHtml(cna.cna)}')">
                    View Details
                </button>
            </td>
        `;
        
        completenessTableBody.appendChild(row);
    });
}

// Render field analysis sections
function renderFieldAnalysis() {
    if (!summaryData.global_completeness) return;
    
    const requiredFields = summaryData.global_completeness.required_fields || [];
    const optionalFields = summaryData.global_completeness.optional_fields || [];
    
    // Create "most missing" by finding required fields with lowest completion rates
    const leastCompleteRequired = [...requiredFields]
        .sort((a, b) => a.percentage - b.percentage)
        .slice(0, 10); // Show top 10 least complete required fields
    
    const topPresent = summaryData.global_completeness.top_present_optional || [];
    
    // Render required fields
    renderFieldGrid('required-fields-grid', requiredFields, true);
    
    // Render optional fields
    renderFieldGrid('optional-fields-grid', optionalFields, false);
    
    // Render least complete required fields (instead of completely missing)
    renderFieldGrid('missing-fields-grid', leastCompleteRequired, true, true);
    
    // Render most utilized fields
    renderFieldGrid('utilized-fields-grid', topPresent, null, false);
}

// Render field grid
function renderFieldGrid(containerId, fields, isRequired = null, showMissing = false) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    container.innerHTML = '';
    
    // Handle empty arrays with informative messages
    if (fields.length === 0) {
        const emptyMessage = document.createElement('div');
        emptyMessage.className = 'empty-state';
        
        if (containerId === 'missing-fields-grid') {
            emptyMessage.innerHTML = `
                <div class="empty-state-content">
                    <div class="empty-state-icon">✅</div>
                    <h3>Excellent Schema Compliance!</h3>
                    <p>All CVE schema fields have high completion rates across CNAs. 
                       This indicates strong adherence to CVE schema requirements.</p>
                    <p><strong>Average completion rate:</strong> 
                       ${summaryData.global_completeness?.overall_completeness?.toFixed(1) || '0.0'}%</p>
                </div>
            `;
        } else {
            emptyMessage.innerHTML = `
                <div class="empty-state-content">
                    <div class="empty-state-icon">📊</div>
                    <h3>No Data Available</h3>
                    <p>No fields found for this category.</p>
                </div>
            `;
        }
        
        container.appendChild(emptyMessage);
        return;
    }
    
    fields.forEach(field => {
        const fieldCard = document.createElement('div');
        fieldCard.className = 'field-card';
        
        const percentage = field.percentage || 0;
        const progressClass = getScoreClass(percentage);
        
        // Get field description
        const description = getFieldDescription(field.field);
        
        fieldCard.innerHTML = `
            <div class="field-name">
                ${field.field}
                ${isRequired !== null ? 
                    `<span class="required-indicator ${isRequired ? 'required' : 'optional'}">
                        ${isRequired ? 'Required' : 'Optional'}
                    </span>` : 
                    ''
                }
            </div>
            <div class="field-description">${description}</div>
            <div class="field-stats">
                <span class="field-percentage">${percentage.toFixed(1)}%</span>
                <div class="field-progress">
                    <div class="field-progress-fill ${progressClass}" style="width: ${percentage}%"></div>
                </div>
                <span class="field-count">${field.present || 0}/${field.total || 0}</span>
            </div>
        `;
        
        container.appendChild(fieldCard);
    });
}

// Render charts (placeholder for now)
function renderCharts() {
    // This would integrate with a charting library like Chart.js or D3.js
    console.log('Charts would be rendered here');
    
    // For now, show placeholder text
    const chartContainers = document.querySelectorAll('.chart');
    chartContainers.forEach(container => {
        if (!container.innerHTML.trim()) {
            container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #6b7280; font-style: italic;">Chart visualization coming soon</div>';
        }
    });
}

// Show CNA details modal
function showCNADetails(cnaName) {
    const cna = completenessData.find(c => c.cna === cnaName);
    if (!cna) return;
    
    // Create modal HTML
    const modalHtml = `
        <div id="cna-modal" class="modal" style="display: block;">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>${escapeHtml(cna.cna)} - Completeness Details</h2>
                    <span class="close" onclick="closeCNAModal()">&times;</span>
                </div>
                <div class="modal-body">
                    <div class="metric-grid">
                        <div class="metric-item">
                            <div class="metric-value">${cna.completeness_score}%</div>
                            <div class="metric-label">Overall Score</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.required_fields_completeness}%</div>
                            <div class="metric-label">Required Fields</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.optional_fields_completeness}%</div>
                            <div class="metric-label">Optional Fields</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.total_cves}</div>
                            <div class="metric-label">Total CVEs</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.percentile}%</div>
                            <div class="metric-label">Percentile Rank</div>
                        </div>
                    </div>
                    
                    <h3>Key Metrics Breakdown</h3>
                    <div class="field-grid">
                        ${Object.entries(cna.key_metrics || {}).map(([key, value]) => `
                            <div class="field-card">
                                <div class="field-name">${formatMetricName(key)}</div>
                                <div class="field-stats">
                                    <span class="field-percentage">${value.toFixed(1)}%</span>
                                    <div class="field-progress">
                                        <div class="field-progress-fill ${getScoreClass(value)}" 
                                             style="width: ${value}%"></div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    
    // Close modal when clicking outside
    document.getElementById('cna-modal').addEventListener('click', (e) => {
        if (e.target.id === 'cna-modal') {
            closeCNAModal();
        }
    });
}

// Close CNA details modal
function closeCNAModal() {
    const modal = document.getElementById('cna-modal');
    if (modal) {
        modal.remove();
    }
}

// Helper functions
function getScoreClass(score) {
    if (score >= 80) return 'excellent';
    if (score >= 60) return 'good';
    if (score >= 40) return 'fair';
    return 'poor';
}

function getPercentileClass(percentile) {
    if (percentile >= 75) return 'percentile-top';      // Top 25%
    if (percentile >= 50) return 'percentile-upper';    // Upper middle 25%
    if (percentile >= 25) return 'percentile-lower';    // Lower middle 25%
    return 'percentile-bottom';                          // Bottom 25%
}

function getFieldDescription(fieldName) {
    const descriptions = {
        'dataType': 'Indicates the type of information (CVE_RECORD)',
        'dataVersion': 'Version of the CVE schema used',
        'cveMetadata.cveId': 'The CVE identifier',
        'cveMetadata.assignerOrgId': 'UUID of the assigning organization',
        'cveMetadata.assignerShortName': 'Short name of the assigning organization',
        'cveMetadata.state': 'State of the CVE (PUBLISHED/REJECTED)',
        'containers.cna.descriptions': 'Vulnerability descriptions',
        'containers.cna.affected': 'Affected products and versions',
        'containers.cna.references': 'Reference URLs and documentation',
        'containers.cna.problemTypes': 'Problem type information (CWE, etc.)',
        'containers.cna.metrics': 'Impact metrics (CVSS scores)',
        'containers.cna.solutions': 'Solutions and remediations',
        'descriptions.english': 'At least one English description',
        'affected.vendor': 'Vendor information in affected products',
        'affected.product': 'Product information in affected products',
        'affected.cpes': 'Common Platform Enumeration identifiers',
        'problemTypes.cwe': 'Common Weakness Enumeration identifiers',
        'references.advisory': 'Advisory references',
        'references.patch': 'Patch references',
        'metrics.cvssV3_1': 'CVSS v3.1 metrics',
        'metrics.cvssV4': 'CVSS v4.0 metrics'
    };
    
    return descriptions[fieldName] || `Schema field: ${fieldName}`;
}

function formatMetricName(key) {
    return key.replace(/_/g, ' ')
             .replace(/\b\w/g, l => l.toUpperCase())
             .replace('Has ', '');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showErrorMessage(message) {
    const errorDiv = document.createElement('div');
    errorDiv.style.cssText = `
        background: #fee2e2;
        color: #dc2626;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        text-align: center;
        border: 1px solid #fecaca;
    `;
    errorDiv.textContent = message;
    
    const container = document.querySelector('.container');
    container.insertBefore(errorDiv, container.firstChild);
}

function updateLastUpdated() {
    const lastUpdatedElement = document.getElementById('last-updated');
    if (summaryData.generated_at) {
        const date = new Date(summaryData.generated_at);
        lastUpdatedElement.textContent = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    } else {
        lastUpdatedElement.textContent = 'Unknown';
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeCNAModal();
    }
});
