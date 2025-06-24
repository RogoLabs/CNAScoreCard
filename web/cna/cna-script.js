// CNA-specific page functionality
let cnaData = null;
let filteredCves = [];

document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on an individual CNA page or the CNA index page
    if (typeof CNA_NAME !== 'undefined' && typeof SAFE_FILENAME !== 'undefined') {
        // Individual CNA page
        loadIndividualCNAData();
    } else {
        // CNA index page
        loadCNAIndexData();
    }
});

// Load data for individual CNA page
function loadIndividualCNAData() {
    const loading = document.getElementById('loading');
    const cveCards = document.getElementById('cveCards');
    const cnaHeader = document.getElementById('cnaHeader');
    const cnaTitle = document.getElementById('cnaTitle');
    const cnaStats = document.getElementById('cnaStats');
    
    // Load CNA-specific data
    fetch(`./data/${SAFE_FILENAME}.json`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            cnaData = data;
            loading.style.display = 'none';
            
            // Update header with CNA info
            displayCNAHeader(data.cna_info, data.recent_cves);
            
            // Display CVEs
            filteredCves = data.recent_cves || [];
            displayCVEs(filteredCves);
            
            // Setup search and sort
            setupCVEFilters();
        })
        .catch(error => {
            console.error('Error loading CNA data:', error);
            loading.innerHTML = `
                <div style="color: #e74c3c; text-align: center;">
                    <h3>Error loading CNA data</h3>
                    <p>Could not load data for ${CNA_NAME}</p>
                </div>
            `;
        });
}

// Load data for CNA index page
function loadCNAIndexData() {
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    const cnaList = document.getElementById('cnaList');
    const loading = document.getElementById('loading');

    let allCnas = [];

    // Load CNA data
    fetch('../data/cnas.json')
        .then(response => response.json())
        .then(data => {
            // Filter CNAs that have recent CVEs (active CNAs)
            allCnas = data.filter(cna => cna.total_cves_scored > 0);
            loading.style.display = 'none';
            displayCnas(allCnas);
        })
        .catch(error => {
            console.error('Error loading CNA data:', error);
            loading.textContent = 'Error loading CNA data';
        });

    function displayCnas(cnas) {
        if (cnas.length === 0) {
            cnaList.innerHTML = '<p class="no-results">No CNAs found matching your search.</p>';
            return;
        }

        cnaList.innerHTML = cnas.map(cna => {
            const safeFilename = cna.cna.replace(/[^a-zA-Z0-9\s\-_]/g, '').trim().replace(/\s+/g, '_');
            return `
                <div class="cna-card">
                    <h3><a href="${safeFilename}.html">${cna.cna}</a></h3>
                    <div class="cna-score grade-${getGradeFromScore(cna.average_eas_score).toLowerCase()}">${cna.average_eas_score.toFixed(1)}</div>
                    <div class="cna-grade">${getGradeFromScore(cna.average_eas_score)}</div>
                    <div class="cna-stats">
                        <span class="cve-count">${cna.total_cves_scored} CVEs</span>
                        <span class="percentile">${cna.percentile ? cna.percentile.toFixed(1) : '0'}%</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    function sortCnas(cnas, sortBy) {
        const sorted = [...cnas];
        switch (sortBy) {
            case 'name':
                return sorted.sort((a, b) => a.cna.localeCompare(b.cna));
            case 'score':
                return sorted.sort((a, b) => b.average_eas_score - a.average_eas_score);
            case 'cveCount':
                return sorted.sort((a, b) => b.total_cves_scored - a.total_cves_scored);
            default:
                return sorted;
        }
    }

    function filterAndSort() {
        const searchTerm = searchInput.value.toLowerCase();
        const sortBy = sortSelect.value;

        let filtered = allCnas;
        if (searchTerm) {
            filtered = allCnas.filter(cna => 
                cna.cna.toLowerCase().includes(searchTerm)
            );
        }

        const sorted = sortCnas(filtered, sortBy);
        displayCnas(sorted);
    }

    if (searchInput) searchInput.addEventListener('input', filterAndSort);
    if (sortSelect) sortSelect.addEventListener('change', filterAndSort);
}

// Display CNA header information
function displayCNAHeader(cnaInfo, recentCves) {
    const cnaStats = document.getElementById('cnaStats');
    if (!cnaStats || !cnaInfo) return;
    
    const totalCves = cnaInfo.total_cves_scored || 0;
    const avgScore = cnaInfo.average_eas_score || 0;
    const percentile = cnaInfo.percentile || 0;
    
    cnaStats.innerHTML = `
        <div class="cna-summary ${getPercentileClass(percentile)}">
            <div class="summary-main">
                <div class="summary-score">
                    <div class="score-value">${avgScore.toFixed(1)}</div>
                    <div class="score-percentile">${percentile.toFixed(1)}th percentile</div>
                </div>
                <div class="summary-details">
                    <div class="detail-item">
                        <span class="label">Total CVEs:</span>
                        <span class="value">${totalCves}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Recent CVEs shown:</span>
                        <span class="value">${recentCves ? recentCves.length : 0}</span>
                    </div>
                </div>
            </div>
            <div class="summary-breakdown">
                <h3>Average Scores by Category</h3>
                <div class="breakdown-grid">
                    <div class="breakdown-item">
                        <span class="breakdown-label">Foundational Completeness</span>
                        <span class="breakdown-value">${(cnaInfo.average_foundational_completeness || 0).toFixed(1)}/30</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Root Cause Analysis</span>
                        <span class="breakdown-value">${(cnaInfo.average_root_cause_analysis || 0).toFixed(1)}/20</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Severity Context</span>
                        <span class="breakdown-value">${(cnaInfo.average_severity_context || 0).toFixed(1)}/25</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Actionable Intelligence</span>
                        <span class="breakdown-value">${(cnaInfo.average_actionable_intelligence || 0).toFixed(1)}/20</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Data Format Precision</span>
                        <span class="breakdown-value">${(cnaInfo.average_data_format_precision || 0).toFixed(1)}/5</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Display CVE cards
function displayCVEs(cves) {
    const cveCards = document.getElementById('cveCards');
    if (!cveCards) return;
    
    if (!cves || cves.length === 0) {
        cveCards.innerHTML = '<p>No CVEs found.</p>';
        return;
    }
    
    cveCards.innerHTML = cves.map(cve => createCVECard(cve)).join('');
}

// Create individual CVE card
function createCVECard(cve) {
    const cveId = cve.cveId || cve.cve_id || 'Unknown';
    const totalScore = cve.totalEasScore || 0;
    const scoreClass = getScoreClass(totalScore);
    
    return `
        <div class="cve-card ${scoreClass}">
            <div class="cve-header">
                <h4 class="cve-id">
                    <a href="https://www.cve.org/CVERecord?id=${cveId}" target="_blank">${cveId}</a>
                </h4>
                <div class="cve-score">${totalScore.toFixed(1)}</div>
            </div>
            <div class="cve-details">
                <div class="score-breakdown">
                    <div class="breakdown-item">
                        <span class="label">Foundational Completeness</span>
                        <span class="value">${(cve.foundationalCompletenesScore || 0).toFixed(1)}/30</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${Math.min(100, (cve.foundationalCompletenesScore || 0) / 30 * 100)}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Root Cause Analysis</span>
                        <span class="value">${(cve.rootCauseAnalysisScore || 0).toFixed(1)}/20</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${Math.min(100, (cve.rootCauseAnalysisScore || 0) / 20 * 100)}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Severity Context</span>
                        <span class="value">${(cve.severityContextScore || 0).toFixed(1)}/25</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${Math.min(100, (cve.severityContextScore || 0) / 25 * 100)}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Actionable Intelligence</span>
                        <span class="value">${(cve.actionableIntelligenceScore || 0).toFixed(1)}/20</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${Math.min(100, (cve.actionableIntelligenceScore || 0) / 20 * 100)}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Data Format Precision</span>
                        <span class="value">${(cve.dataFormatPrecisionScore || 0).toFixed(1)}/5</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${Math.min(100, (cve.dataFormatPrecisionScore || 0) / 5 * 100)}%"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Setup CVE filters
function setupCVEFilters() {
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    
    if (searchInput) {
        searchInput.addEventListener('input', filterCVEs);
    }
    
    if (sortSelect) {
        sortSelect.addEventListener('change', filterCVEs);
    }
}

// Filter CVEs based on search and sort
function filterCVEs() {
    if (!cnaData || !cnaData.recent_cves) return;
    
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const sortBy = document.getElementById('sortSelect').value;
    
    let filtered = cnaData.recent_cves;
    
    if (searchTerm) {
        filtered = filtered.filter(cve => {
            const cveId = (cve.cveId || cve.cve_id || '').toLowerCase();
            return cveId.includes(searchTerm);
        });
    }
    
    // Sort CVEs
    filtered.sort((a, b) => {
        switch (sortBy) {
            case 'cveId':
                const idA = a.cveId || a.cve_id || '';
                const idB = b.cveId || b.cve_id || '';
                return idA.localeCompare(idB);
            case 'date':
                const dateA = a.publishedDate || a.published_date || '';
                const dateB = b.publishedDate || b.published_date || '';
                return dateB.localeCompare(dateA);
            case 'score':
            default:
                return (b.totalEasScore || 0) - (a.totalEasScore || 0);
        }
    });
    
    filteredCves = filtered;
    displayCVEs(filteredCves);
}

// Utility functions
function getPercentileClass(percentile) {
    if (percentile >= 75) return 'percentile-top';
    if (percentile >= 50) return 'percentile-upper';
    if (percentile >= 25) return 'percentile-lower';
    return 'percentile-bottom';
}

function getScoreClass(score) {
    if (score >= 80) return 'score-excellent';
    if (score >= 60) return 'score-good';
    if (score >= 40) return 'score-fair';
    return 'score-poor';
}

function getGradeFromScore(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
}