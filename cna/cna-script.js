// filepath: /Users/gamblin/Code/CNAScoreCard/web/cna/cna-script.js
// Global variables
let cnaData = null;
let filteredCVEs = [];

// Load and display CNA-specific data
async function loadCNAData() {
    try {
        const response = await fetch(`./data/${SAFE_FILENAME}.json`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        cnaData = await response.json();
        
        console.log('Loaded CNA data:', cnaData);
        document.getElementById('loading').style.display = 'none';
        
        // Update header with CNA stats
        displayCNAHeader(cnaData.cna_info);
        
        // Display CVEs
        filteredCVEs = [...cnaData.recent_cves];
        displayCVEs(filteredCVEs);
        setupEventListeners();
    } catch (error) {
        console.error('Error loading CNA data:', error);
        document.getElementById('loading').innerHTML = `
            <div style="color: #e74c3c; text-align: center;">
                <h3>Error loading data</h3>
                <p>Could not load data for ${CNA_NAME}.</p>
                <p>Please try refreshing the page or go back to the main page.</p>
            </div>
        `;
    }
}

// Display CNA header information
function displayCNAHeader(cnaInfo) {
    const headerElement = document.getElementById('cnaStats');
    const score = safeGet(cnaInfo, 'average_eas_score', 0);
    const percentile = safeGet(cnaInfo, 'percentile', 0);
    const totalCVEs = safeGet(cnaInfo, 'total_cves_scored', 0);
    const avgFoundational = safeGet(cnaInfo, 'average_foundational_completeness', 0);
    const avgRootCause = safeGet(cnaInfo, 'average_root_cause_analysis', 0);
    const avgSeverity = safeGet(cnaInfo, 'average_severity_context', 0);
    const avgActionable = safeGet(cnaInfo, 'average_actionable_intelligence', 0);
    const avgFormat = safeGet(cnaInfo, 'average_data_format_precision', 0);
    
    const percentileClass = getPercentileClass(percentile);
    const percentileText = totalCVEs > 0 ? `${percentile.toFixed(1)}th percentile` : 'N/A';
    
    headerElement.innerHTML = `
        <div class="cna-summary ${percentileClass}">
            <div class="summary-main">
                <div class="summary-score">
                    <div class="score-value">${score.toFixed(1)}/100</div>
                    <div class="score-percentile">${percentileText}</div>
                </div>
                <div class="summary-details">
                    <div class="detail-item">
                        <span class="label">Total CVEs (6 months):</span>
                        <span class="value">${totalCVEs}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Showing Latest:</span>
                        <span class="value">${Math.min(totalCVEs, 100)} CVEs</span>
                    </div>
                </div>
            </div>
            <div class="summary-breakdown">
                <h3>Average Score Breakdown</h3>
                <div class="breakdown-grid">
                    <div class="breakdown-item">
                        <span class="breakdown-label">Foundational Completeness:</span>
                        <span class="breakdown-value">${avgFoundational.toFixed(1)}/30</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Root Cause Analysis:</span>
                        <span class="breakdown-value">${avgRootCause.toFixed(1)}/20</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Severity Context:</span>
                        <span class="breakdown-value">${avgSeverity.toFixed(1)}/25</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Actionable Intelligence:</span>
                        <span class="breakdown-value">${avgActionable.toFixed(1)}/20</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Data Format Precision:</span>
                        <span class="breakdown-value">${avgFormat.toFixed(1)}/5</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Display CVEs as cards
function displayCVEs(cves) {
    const container = document.getElementById('cveCards');
    
    if (cves.length === 0) {
        container.innerHTML = '<p>No CVEs found matching your criteria.</p>';
        return;
    }
    
    const cardsHTML = cves.map(cve => createCVECard(cve)).join('');
    container.innerHTML = cardsHTML;
}

// Create individual CVE card
function createCVECard(cve) {
    const cveId = safeGet(cve, 'cveId', 'N/A');
    const totalScore = safeGet(cve, 'totalEasScore', 0);
    const breakdown = safeGet(cve, 'scoreBreakdown', {});
    
    const foundational = safeGet(breakdown, 'foundationalCompleteness', 0);
    const rootCause = safeGet(breakdown, 'rootCauseAnalysis', 0);
    const severity = safeGet(breakdown, 'severityAndImpactContext', 0);
    const actionable = safeGet(breakdown, 'actionableIntelligence', 0);
    const format = safeGet(breakdown, 'dataFormatAndPrecision', 0);
    
    const scoreClass = getScoreClass(totalScore);
    
    return `
        <div class="cve-card ${scoreClass}">
            <div class="cve-header">
                <h3 class="cve-id">${escapeHtml(cveId)}</h3>
                <div class="cve-score">${totalScore}/100</div>
            </div>
            <div class="cve-details">
                <div class="score-breakdown">
                    <div class="breakdown-item">
                        <span class="label">Foundational:</span>
                        <span class="value">${foundational}/30</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${(foundational/30)*100}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Root Cause:</span>
                        <span class="value">${rootCause}/20</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${(rootCause/20)*100}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Severity Context:</span>
                        <span class="value">${severity}/25</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${(severity/25)*100}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Actionable Intel:</span>
                        <span class="value">${actionable}/20</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${(actionable/20)*100}%"></div>
                        </div>
                    </div>
                    <div class="breakdown-item">
                        <span class="label">Data Format:</span>
                        <span class="value">${format}/5</span>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${(format/5)*100}%"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Get CSS class based on score
function getScoreClass(score) {
    if (score >= 80) return 'score-excellent';
    if (score >= 60) return 'score-good';
    if (score >= 40) return 'score-fair';
    return 'score-poor';
}

// Get CSS class based on percentile
function getPercentileClass(percentile) {
    if (percentile >= 75) return 'percentile-top';
    if (percentile >= 50) return 'percentile-upper';
    if (percentile >= 25) return 'percentile-lower';
    return 'percentile-bottom';
}

// Escape HTML to prevent XSS
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) {
        return '';
    }
    return unsafe
        .toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('searchInput');
    searchInput.addEventListener('input', handleSearch);
    
    // Sort functionality
    const sortSelect = document.getElementById('sortSelect');
    sortSelect.addEventListener('change', handleSort);
}

// Handle search
function handleSearch(event) {
    const searchTerm = event.target.value.toLowerCase();
    filteredCVEs = cnaData.recent_cves.filter(cve => {
        const cveId = safeGet(cve, 'cveId', '').toLowerCase();
        return cveId.includes(searchTerm);
    });
    displayCVEs(filteredCVEs);
}

// Handle sorting
function handleSort(event) {
    const sortBy = event.target.value;
    
    filteredCVEs.sort((a, b) => {
        switch (sortBy) {
            case 'cveId':
                const idA = safeGet(a, 'cveId', '');
                const idB = safeGet(b, 'cveId', '');
                return idA.localeCompare(idB);
            case 'date':
                // Since we don't have date in the score data, sort by CVE ID which includes year
                const dateA = safeGet(a, 'cveId', '');
                const dateB = safeGet(b, 'cveId', '');
                return dateB.localeCompare(dateA); // Newer first
            case 'score':
            default:
                const scoreA = safeGet(a, 'totalEasScore', 0);
                const scoreB = safeGet(b, 'totalEasScore', 0);
                return scoreB - scoreA; // Higher score first
        }
    });
    
    displayCVEs(filteredCVEs);
}

// Safe property access helper
function safeGet(obj, property, defaultValue = 0) {
    return obj && obj[property] !== undefined ? obj[property] : defaultValue;
}

// Initialize the application
document.addEventListener('DOMContentLoaded', loadCNAData);