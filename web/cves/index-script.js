// CVE Index Page Script - displays top 10 and bottom 10 CVEs

let topCveData = [];
let bottomCveData = [];

// Function to load both top and bottom CVE data
async function loadCVEData() {
    try {
        // Load both datasets in parallel
        const [topResponse, bottomResponse] = await Promise.all([
            fetch('../data/top100_cves.json'),
            fetch('../data/bottom100_cves.json')
        ]);
        
        if (!topResponse.ok || !bottomResponse.ok) {
            throw new Error('Failed to load CVE data');
        }
        
        const topData = await topResponse.json();
        const bottomData = await bottomResponse.json();
        
        if (!Array.isArray(topData) || !Array.isArray(bottomData)) {
            throw new Error('Invalid data format - expected arrays');
        }
        
        // Take top 10 from each dataset
        topCveData = topData.slice(0, 10);
        bottomCveData = bottomData.slice(0, 10);
        
        displayCVEPreviews();
        
    } catch (error) {
        console.error('Error loading CVE data:', error);
        document.getElementById('loading').innerHTML = `
            <div class="error-message">
                <h3>Error Loading Data</h3>
                <p>Could not load CVE data. Please try refreshing the page.</p>
                <p><small>Error: ${error.message}</small></p>
            </div>
        `;
    }
}

// Function to display CVE previews
function displayCVEPreviews() {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('cvePreview').style.display = 'block';
    
    displayCVECards(topCveData, 'topCveCards');
    displayCVECards(bottomCveData, 'bottomCveCards');
}

// Helper to format numbers (hide .0 if integer, even if string)
function formatNumber(num) {
    if (typeof num === 'string' && num.match(/^\d+\.0$/)) return num.replace('.0', '');
    if (typeof num === 'number') {
        if (num % 1 === 0) return num.toString();
        return parseFloat(num.toFixed(1)).toString();
    }
    return num;
}

// Function to get score class for styling (backward compatibility)
function getScoreClass(score) {
    if (score >= 80) return 'score-excellent';
    if (score >= 60) return 'score-good';
    if (score >= 40) return 'score-fair';
    return 'score-poor';
}

// Function to get percentile class for styling (preferred method)
function getPercentileClass(percentile) {
    if (percentile >= 75) return 'percentile-top';      // Top 25%
    if (percentile >= 50) return 'percentile-upper';    // Upper middle 25%
    if (percentile >= 25) return 'percentile-lower';    // Lower middle 25%
    return 'percentile-bottom';                          // Bottom 25%
}

// Function to format date
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'short', 
            day: 'numeric' 
        });
    } catch (e) {
        return dateString;
    }
}

// Helper to get stoplight class for breakdown values
function getBreakdownClass(value, max) {
    const pct = (value / max) * 100;
    if (pct >= 80) return 'breakdown-good';
    if (pct >= 50) return 'breakdown-ok';
    return 'breakdown-bad';
}

// Function to display CVE cards
function displayCVECards(cves, containerId) {
    const container = document.getElementById(containerId);
    
    if (cves.length === 0) {
        container.innerHTML = '<div class="no-results">No CVEs found.</div>';
        return;
    }
    
    container.innerHTML = cves.map(cve => {
        const score = cve.totalEasScore || 0;
        const percentile = cve.percentile;
        
        // Use percentile-based classification if percentile data exists,
        // otherwise determine based on context (top vs bottom preview)
        let scoreClass;
        if (percentile !== undefined && percentile !== null) {
            scoreClass = getPercentileClass(percentile);
        } else if (containerId === 'topCveCards') {
            // Top CVEs should be green (top performers)
            scoreClass = 'percentile-top';
        } else if (containerId === 'bottomCveCards') {
            // Bottom CVEs should be red (bottom performers)
            scoreClass = 'percentile-bottom';
        } else {
            // Fallback to score-based classification
            scoreClass = getScoreClass(score);
        }
        
        const breakdown = cve.scoreBreakdown || {};
        // EAS max values for each dimension
        const maxVals = {
            foundationalCompleteness: 32,
            rootCauseAnalysis: 12,
            softwareIdentification: 12,
            severityAndImpactContext: 27,
            actionableIntelligence: 20
        };
        return `
            <div class="cve-card ${scoreClass}">
                <div class="cve-header">
                    <div class="cve-id">
                        <a href="https://cve.org/CVERecord?id=${cve.cveId}" target="_blank">${cve.cveId}</a>
                    </div>
                    <div class="cve-meta">
                        <div class="cve-score-main"><span class="score-number">${formatNumber(score)}</span><span class="score-denom">/100</span></div>
                        <div class="cve-cna">${cve.assigningCna || 'Unknown CNA'}</div>
                        <div class="cve-date">${formatDate(cve.datePublished)}</div>
                    </div>
                </div>
                <div class="cve-breakdown-grid">
                    <div class="breakdown-item"><span class="label">Foundational</span><span class="value ${getBreakdownClass(breakdown.foundationalCompleteness || 0, maxVals.foundationalCompleteness)}">${formatNumber(breakdown.foundationalCompleteness || 0)}/32</span></div>
                    <div class="breakdown-item"><span class="label">Root Cause</span><span class="value ${getBreakdownClass(breakdown.rootCauseAnalysis || 0, maxVals.rootCauseAnalysis)}">${formatNumber(breakdown.rootCauseAnalysis || 0)}/12</span></div>
                    <div class="breakdown-item"><span class="label">Software ID</span><span class="value ${getBreakdownClass(breakdown.softwareIdentification || 0, maxVals.softwareIdentification)}">${formatNumber(breakdown.softwareIdentification || 0)}/12</span></div>
                    <div class="breakdown-item"><span class="label">Severity & Impact</span><span class="value ${getBreakdownClass(breakdown.severityAndImpactContext || 0, maxVals.severityAndImpactContext)}">${formatNumber(breakdown.severityAndImpactContext || 0)}/27</span></div>
                    <div class="breakdown-item"><span class="label">Actionable</span><span class="value ${getBreakdownClass(breakdown.actionableIntelligence || 0, maxVals.actionableIntelligence)}">${formatNumber(breakdown.actionableIntelligence || 0)}/20</span></div>
                </div>
            </div>
        `;
    }).join('');
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    loadCVEData();
});
