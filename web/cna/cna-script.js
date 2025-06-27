// CNA Index Page Script - Lists all CNAs with EAS scores
let cnaListData = [];
let currentSort = 'score';
let currentView = 'table';

// DOM elements
const tableView = document.getElementById('table-view');
const cardView = document.getElementById('card-view');
const tableViewBtn = document.getElementById('table-view-btn');
const cardViewBtn = document.getElementById('card-view-btn');
const cnaSearch = document.getElementById('cna-search');
const sortSelect = document.getElementById('sort-select');
const cnaTableBody = document.getElementById('cna-table-body');

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadCNAListData();
    setupEventListeners();
});

// Load CNA list data from consolidated data file
async function loadCNAListData() {
    try {
        // Load the consolidated CNA data from the parent data directory
        const response = await fetch('../data/cnas.json');
        const cnaData = await response.json();
        
        // Transform the data to match the expected format
        cnaListData = cnaData
            .filter(cna => cna.total_cves > 0) // Only include CNAs with CVEs
            .map(cna => {
                // Format the display name to be more readable
                let displayName = cna.cna;
                if (displayName.includes('_')) {
                    displayName = displayName.replace(/_/g, ' ');
                }
                
                return {
                    name: cna.cna,
                    displayName: displayName,
                    easScore: cna.average_eas_score || 0,
                    cveCount: cna.total_cves || 0,
                    rank: cna.rank || 0,
                    percentile: cna.percentile || 0,
                    activeCnaCount: cna.active_cna_count || 298,
                    breakdown: {
                        foundational: cna.average_foundational_completeness || 0,
                        rootCause: cna.average_root_cause_analysis || 0,
                        softwareIdentification: cna.average_software_identification || 0,
                        security: cna.average_severity_context || 0,
                        actionable: cna.average_actionable_intelligence || 0,
                        dataFormat: cna.average_data_format_precision || 0
                    },
                    filename: `${cna.cna}.json`
                };
            });
        
        // Initialize the interface
        updateOverviewStats();
        filterAndRenderTable();
        updateLastUpdated();
        
        // Hide loading indicator
        document.getElementById('loading').style.display = 'none';
        
    } catch (error) {
        console.error('Error loading CNA data:', error);
        showErrorMessage('Failed to load CNA data. Please try again later.');
    }
}

// Update overview statistics
function updateOverviewStats() {
    if (cnaListData.length === 0) return;
    
    const totalCves = cnaListData.reduce((sum, cna) => sum + cna.cveCount, 0);
    const averageScore = cnaListData.reduce((sum, cna) => sum + cna.easScore, 0) / cnaListData.length;
    const topPerformer = cnaListData.reduce((top, cna) => 
        cna.easScore > top.easScore ? cna : top, cnaListData[0]);
    
    document.getElementById('average-score').textContent = averageScore.toFixed(1);
    document.getElementById('total-cnas').textContent = cnaListData.length.toLocaleString();
    document.getElementById('total-cves').textContent = totalCves.toLocaleString();
    document.getElementById('top-performer').textContent = topPerformer.displayName;
}

// Setup event listeners
function setupEventListeners() {
    // View toggle buttons
    tableViewBtn?.addEventListener('click', () => switchView('table'));
    cardViewBtn?.addEventListener('click', () => switchView('card'));
    
    // Search and sort
    cnaSearch?.addEventListener('input', filterAndRenderTable);
    sortSelect?.addEventListener('change', (e) => {
        currentSort = e.target.value;
        filterAndRenderTable();
    });
}

// Switch between table and card views
function switchView(view) {
    currentView = view;
    
    if (view === 'table') {
        tableView.style.display = 'block';
        cardView.style.display = 'none';
        tableViewBtn.classList.add('active');
        cardViewBtn.classList.remove('active');
    } else {
        tableView.style.display = 'none';
        cardView.style.display = 'block';
        tableViewBtn.classList.remove('active');
        cardViewBtn.classList.add('active');
        renderCardView();
    }
}

// Filter and render table based on search and sort
function filterAndRenderTable() {
    const searchTerm = cnaSearch?.value.toLowerCase() || '';
    let filteredData = cnaListData.filter(cna => 
        cna.name.toLowerCase().includes(searchTerm) ||
        cna.displayName.toLowerCase().includes(searchTerm)
    );
    
    // Sort data
    filteredData.sort((a, b) => {
        switch (currentSort) {
            case 'name':
                return a.displayName.localeCompare(b.displayName);
            case 'cves':
                return b.cveCount - a.cveCount;
            case 'rank':
                return a.rank - b.rank;
            case 'score':
            default:
                return b.easScore - a.easScore;
        }
    });
    
    renderTable(filteredData);
}

// Render the CNA table
function renderTable(data = cnaListData) {
    if (!cnaTableBody) return;
    
    cnaTableBody.innerHTML = '';
    
    data.forEach((cna, index) => {
        const row = document.createElement('tr');
        
        // Determine percentile class for styling
        const percentileClass = getPercentileClass(cna.percentile);
        
        row.innerHTML = `
            <td class="rank-cell">${cna.rank || (index + 1)}</td>
            <td class="cna-cell">
                <a href="cna-detail.html?cna=${encodeURIComponent(cna.name)}" 
                   title="${escapeHtml(cna.displayName)}">
                    ${escapeHtml(cna.displayName)}
                </a>
            </td>
            <td class="score-cell">
                <div class="score-bar">
                    <span class="score-value">${formatNumber(cna.easScore)}/100</span>
                    <div class="progress-bar">
                        <div class="progress-fill ${percentileClass}" style="width: ${cna.easScore}%"></div>
                    </div>
                </div>
            </td>
            <td>${cna.cveCount.toLocaleString()}</td>
            <td>
                <span class="percentile-badge ${percentileClass}">${formatNumber(cna.percentile)}%</span>
            </td>
            <td>
                <a href="cna-detail.html?cna=${encodeURIComponent(cna.name)}" 
                   class="details-btn">
                    View Details
                </a>
            </td>
        `;
        
        cnaTableBody.appendChild(row);
    });
}

// Render card view (fallback to existing card implementation)
function renderCardView() {
    if (!cardView) return;
    
    const searchTerm = cnaSearch?.value.toLowerCase() || '';
    let filteredData = cnaListData.filter(cna => 
        cna.name.toLowerCase().includes(searchTerm) ||
        cna.displayName.toLowerCase().includes(searchTerm)
    );
    
    // Sort data
    filteredData.sort((a, b) => {
        switch (currentSort) {
            case 'name':
                return a.displayName.localeCompare(b.displayName);
            case 'cves':
                return b.cveCount - a.cveCount;
            case 'rank':
                return a.rank - b.rank;
            case 'score':
            default:
                return b.easScore - a.easScore;
        }
    });
    
    cardView.innerHTML = filteredData.map(cna => `
        <div class="cna-card">
            <div class="cna-header">
                <h3 class="cna-name" title="${escapeHtml(cna.displayName)}">
                    <a href="cna-detail.html?cna=${encodeURIComponent(cna.name)}">
                        ${escapeHtml(cna.displayName)}
                    </a>
                </h3>
                <div class="cna-score-container">
                    <div class="cna-score">${formatNumber(cna.easScore)}</div>
                </div>
            </div>
            <div class="cna-details">
                <div class="detail-item">
                    <span class="label">CVE Count (6mo):</span>
                    <span class="value">${cna.cveCount.toLocaleString()}</span>
                </div>
                <div class="detail-item">
                    <span class="label">Rank:</span>
                    <span class="value">${cna.rank || 'N/A'}${cna.activeCnaCount ? ` of ${cna.activeCnaCount}` : ''}</span>
                </div>
                <div class="detail-item">
                    <span class="label">Percentile:</span>
                    <span class="value">${formatNumber(cna.percentile)}%</span>
                </div>
            </div>
            <div class="cna-actions">
                <a href="cna-detail.html?cna=${encodeURIComponent(cna.name)}" class="view-details-btn">
                    View Details
                </a>
            </div>
        </div>
    `).join('');
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

function formatNumber(num) {
    if (typeof num === 'string' && num.match(/^\d+\.0$/)) {
        return num.replace('.0', '');
    }
    if (typeof num === 'number') {
        return num % 1 === 0 ? num.toString() : num.toFixed(1);
    }
    return num;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showErrorMessage(message) {
    const loading = document.getElementById('loading');
    if (loading) {
        loading.innerHTML = `
            <div style="color: #e74c3c; padding: 20px;">
                <h3>⚠️ Error Loading Data</h3>
                <p>${message}</p>
            </div>
        `;
    }
}

function updateLastUpdated() {
    const lastUpdatedElement = document.getElementById('last-updated');
    if (lastUpdatedElement) {
        lastUpdatedElement.textContent = new Date().toLocaleDateString();
    }
}
