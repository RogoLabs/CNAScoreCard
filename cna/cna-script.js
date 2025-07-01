// CNA Index Page Script - Lists all CNAs with EAS scores
let cnaListData = [];
let currentSort = 'score';

// DOM elements
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
    // Search and sort
    cnaSearch?.addEventListener('input', filterAndRenderTable);
    sortSelect?.addEventListener('change', (e) => {
        currentSort = e.target.value;
        filterAndRenderTable();
    });
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
        if (currentSort === 'name') {
            return a.displayName.localeCompare(b.displayName);
        } else if (currentSort === 'cves') {
            return b.cveCount - a.cveCount;
        } else if (currentSort === 'rank') {
            return a.rank - b.rank;
        } else {
            return b.easScore - a.easScore;
        }
    });

    renderTable(filteredData);
}

// Render the CNA table
function renderTable(data = cnaListData) {
    if (!cnaTableBody)
        return;

    cnaTableBody.innerHTML = '';

    data.forEach((cna, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="rank-cell">${index + 1}</td>
            <td class="cna-cell">
                <a href="cna-detail.html?shortName=${cna.name}">${escapeHtml(cna.displayName)}</a>
            </td>
            <td class="score-cell">
                <div class="score-bar">
                    <div class="progress-bar">
                        <div class="progress-fill ${getPercentileClass(cna.percentile)}" style="width: ${cna.easScore.toFixed(1)}%;"></div>
                    </div>
                    <span class="score-value">${cna.easScore.toFixed(1)}</span>
                </div>
            </td>
            <td>${formatNumber(cna.cveCount)}</td>
            <td>
                <a href="cna-detail.html?shortName=${cna.name}" class="details-btn">Details</a>
            </td>
        `;
        cnaTableBody.appendChild(row);
    });
}

// Helper functions
function getScoreClass(score) {
    if (score >= 7.5) return 'score-excellent';
    if (score >= 5) return 'score-good';
    if (score >= 2.5) return 'score-fair';
    return 'score-poor';
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
