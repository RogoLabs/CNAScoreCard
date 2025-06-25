// CNA Detail Page Script - Minimal version (EAS scoring handled in backend)
let cnaData = {};
let cveScores = [];

// Function to load CNA data
async function loadCNAData() {
    try {
        const response = await fetch(`data/${SAFE_FILENAME}.json`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        const cnaInfo = data.cna_info || {};
        const recentCVEs = data.recent_cves || [];
        const totalCVEs = data.total_cves || cnaInfo.total_cves_scored || recentCVEs.length;
        cnaData.ranking = (typeof cnaInfo.rank !== 'undefined' && typeof cnaInfo.active_cna_count !== 'undefined') ? `Rank: ${cnaInfo.rank} of ${cnaInfo.active_cna_count}` : 'N/A';
        const overallScore = cnaInfo.average_eas_score || 0;
        const percentile = cnaInfo.percentile || 0;
        const breakdown = {
            foundational: (cnaInfo.average_foundational_completeness || 0),
            rootCause: (cnaInfo.average_root_cause_analysis || 0),
            softwareIdentification: (cnaInfo.average_software_identification || 0),
            security: (cnaInfo.average_severity_context || 0),
            actionable: (cnaInfo.average_actionable_intelligence || 0),
            dataFormat: (cnaInfo.average_data_format_precision || 0)
        };
        cveScores = recentCVEs.map(cve => {
            return {
                cveId: cve.cveId,
                overallScore: cve.totalEasScore || 0,
                percentile: cve.percentile || 0,
                foundationalCompleteness: cve.scoreBreakdown?.foundationalCompleteness || 0,
                rootCauseAnalysis: cve.scoreBreakdown?.rootCauseAnalysis || 0,
                softwareIdentification: cve.scoreBreakdown?.softwareIdentification || 0,
                securityContext: cve.scoreBreakdown?.severityAndImpactContext || 0,
                actionableIntelligence: cve.scoreBreakdown?.actionableIntelligence || 0,
                dataFormatPrecision: cve.scoreBreakdown?.dataFormatAndPrecision || 0,
            };
        });
        displayCNAHeader(overallScore, percentile, totalCVEs, breakdown, cnaData.ranking);
        displayCVECards(cveScores);
    } catch (error) {
        console.error('Error loading CNA data:', error);
        document.getElementById('loading').innerHTML = `
            <div style="text-align: center; padding: 2rem; color: #dc3545;">
                <h3>Error Loading Data</h3>
                <p>Could not load data for ${CNA_NAME}. Please check if the CNA name is correct.</p>
                <p><small>Error: ${error.message}</small></p>
            </div>
        `;
    }
}

// Helper to format numbers (hide .0 if integer, even if string)
function formatNumber(num) {
    if (typeof num === 'string' && num.match(/^[0-9]+\.0$/)) return num.replace('.0', '');
    if (typeof num === 'number') {
        if (num % 1 === 0) return num.toString();
        return parseFloat(num.toFixed(1)).toString();
    }
    return num;
}

// Function to get percentile class for styling
function getPercentileClass(percentile) {
    if (percentile >= 80) return 'percentile-top';
    if (percentile >= 60) return 'percentile-upper';
    if (percentile >= 40) return 'percentile-lower';
    return 'percentile-bottom';
}

// Function to display CNA header
function displayCNAHeader(overallScore, percentile, totalCVEs, breakdown, ranking) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('cnaHeader').style.display = 'block';
    document.getElementById('cveSection').style.display = 'block';

    // Professional CNA header card matching site style
    document.getElementById('cnaHeader').innerHTML = `
        <div class="cna-detail-card">
            <div class="cna-title-section">
                <h1 class="cna-title">${CNA_NAME.toUpperCase()}</h1>
            </div>
            
            <div class="cna-metrics-section">
                <div class="metric-item main-metric">
                    <div class="metric-value">${formatNumber(overallScore)}<span class="metric-unit">/100</span></div>
                    <div class="metric-label">EAS Score</div>
                </div>
                
                <div class="metric-item">
                    <div class="metric-value">${formatNumber(totalCVEs)}</div>
                    <div class="metric-label">CVEs Published (6mo)</div>
                </div>
                
                <div class="metric-item">
                    <div class="metric-value">${formatNumber(ranking || 'N/A')}</div>
                    <div class="metric-label">Ranking</div>
                </div>
            </div>
            
            <div class="cna-breakdown-section">
                <div class="breakdown-grid">
                    <div class="breakdown-item">
                        <span class="breakdown-label">Foundational Completeness:</span>
                        <span class="breakdown-value">${formatNumber(breakdown.foundational)}/30</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Root Cause Analysis:</span>
                        <span class="breakdown-value">${formatNumber(breakdown.rootCause)}/10</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Software Identification:</span>
                        <span class="breakdown-value">${formatNumber(breakdown.softwareIdentification)}/10</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Severity Context:</span>
                        <span class="breakdown-value">${formatNumber(breakdown.security)}/25</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Actionable Intelligence:</span>
                        <span class="breakdown-value">${formatNumber(breakdown.actionable)}/20</span>
                    </div>
                    <div class="breakdown-item">
                        <span class="breakdown-label">Data Format Precision:</span>
                        <span class="breakdown-value">${formatNumber(breakdown.dataFormat)}/5</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Function to display CVE cards
function displayCVECards(scores) {
    const container = document.getElementById('cveCards');
    if (scores.length === 0) {
        container.innerHTML = '<p>No CVEs found for this CNA.</p>';
        return;
    }
    // Sort scores by overall score (descending)
    const sortedScores = [...scores].sort((a, b) => b.overallScore - a.overallScore);
    container.innerHTML = sortedScores.map(score => {
        const scoreClass = getPercentileClass(score.percentile);
        return `
            <div class="cna-card ${scoreClass}">
                <div class="cna-header">
                    <h3 class="cna-name">
                        <a href="https://cve.org/CVERecord?id=${score.cveId}" target="_blank">${score.cveId}</a>
                    </h3>
                    <div class="cna-score-container">
                        <div class="cna-score">${formatNumber(score.overallScore)}/100</div>
                    </div>
                </div>
                <div class="cna-details">
                    <div class="detail-item">
                        <span class="label">Foundational Completeness:</span>
                        <span class="value">${formatNumber(score.foundationalCompleteness)}/30</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Root Cause Analysis:</span>
                        <span class="value">${formatNumber(score.rootCauseAnalysis)}/10</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Software Identification:</span>
                        <span class="value">${formatNumber(score.softwareIdentification)}/10</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Severity Context:</span>
                        <span class="value">${formatNumber(score.securityContext)}/25</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Actionable Intelligence:</span>
                        <span class="value">${formatNumber(score.actionableIntelligence)}/20</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Data Format Precision:</span>
                        <span class="value">${formatNumber(score.dataFormatPrecision)}/5</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Function to filter and sort CVEs
function filterAndSortCVEs() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const sortBy = document.getElementById('sortSelect').value;
    
    let filteredScores = cveScores.filter(score => 
        score.cveId.toLowerCase().includes(searchTerm)
    );
    
    if (sortBy === 'score') {
        filteredScores.sort((a, b) => b.overallScore - a.overallScore);
    } else if (sortBy === 'cveId') {
        filteredScores.sort((a, b) => a.cveId.localeCompare(b.cveId));
    }
    
    displayCVECards(filteredScores);
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    loadCNAData();
    
    document.getElementById('searchInput').addEventListener('input', filterAndSortCVEs);
    document.getElementById('sortSelect').addEventListener('change', filterAndSortCVEs);
});