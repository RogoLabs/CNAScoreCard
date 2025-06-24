// Main script file for CNA ScoreCard - fixing score calculation
// Enhanced Aggregate Scoring (EAS) Implementation

// Function to calculate Enhanced Aggregate Scoring (EAS)
function calculateEAS(cveData) {
    if (!cveData) return null;
    
    const cveId = cveData.CVE_data_meta?.ID || 'Unknown';
    
    // Scoring components (each out of 20 points for total of 100)
    let foundationalCompleteness = 0;
    let rootCauseAnalysis = 0;
    let securityContext = 0;
    let actionableIntelligence = 0;
    let dataFormatPrecision = 0;
    
    // 1. Foundational Completeness (20 points)
    if (cveData.description?.description_data?.[0]?.value) {
        const desc = cveData.description.description_data[0].value;
        if (desc.length > 50) foundationalCompleteness += 5;
        if (desc.length > 100) foundationalCompleteness += 5;
        if (desc.includes('vulnerability') || desc.includes('exploit')) foundationalCompleteness += 5;
        if (desc.length > 200) foundationalCompleteness += 5;
    }
    
    // 2. Root Cause Analysis (20 points)
    if (cveData.problemtype?.problemtype_data?.[0]?.description?.[0]?.value) {
        const problemType = cveData.problemtype.problemtype_data[0].description[0].value;
        if (problemType && problemType !== 'NVD-CWE-Other') rootCauseAnalysis += 10;
        if (problemType.includes('CWE-')) rootCauseAnalysis += 10;
    }
    
    // 3. Security Context (20 points)
    if (cveData.impact?.cvss?.vector_string) {
        securityContext += 10;
        const cvss = cveData.impact.cvss.vector_string;
        if (cvss.includes('CVSS:3') || cvss.includes('CVSS:4')) securityContext += 5;
        if (cveData.impact.cvss.base_score && cveData.impact.cvss.base_score > 0) securityContext += 5;
    }
    
    // 4. Actionable Intelligence (20 points)
    if (cveData.references?.reference_data?.length > 0) {
        actionableIntelligence += 5;
        if (cveData.references.reference_data.length > 2) actionableIntelligence += 5;
        
        const hasVendorAdvisory = cveData.references.reference_data.some(ref => 
            ref.tags?.includes('Vendor Advisory') || 
            ref.url?.includes('advisory') ||
            ref.url?.includes('security')
        );
        if (hasVendorAdvisory) actionableIntelligence += 10;
    }
    
    // 5. Data Format Precision (20 points)
    if (cveData.data_format === 'MITRE') dataFormatPrecision += 5;
    if (cveData.data_version) dataFormatPrecision += 5;
    if (cveData.CVE_data_meta?.STATE === 'PUBLIC') dataFormatPrecision += 5;
    if (cveData.CVE_data_meta?.ASSIGNER) dataFormatPrecision += 5;
    
    // Calculate overall score (sum of all components for total out of 100)
    const overallScore = (foundationalCompleteness + rootCauseAnalysis + securityContext + actionableIntelligence + dataFormatPrecision);
    
    return {
        overallScore: parseFloat(overallScore.toFixed(1)),
        foundationalCompleteness,
        rootCauseAnalysis,
        securityContext,
        actionableIntelligence,
        dataFormatPrecision
    };
}

// Global variables
let allCNAs = [];
let filteredCNAs = [];

// Load and display CNA data
async function loadCNAData() {
    try {
        const response = await fetch('./data/cnas.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        // Handle different possible data structures
        let cnaArray;
        if (Array.isArray(data)) {
            cnaArray = data;
        } else if (data.cnas && Array.isArray(data.cnas)) {
            cnaArray = data.cnas;
        } else if (typeof data === 'object' && data !== null) {
            // If it's an object, convert to array
            cnaArray = Object.values(data);
        } else {
            throw new Error('Invalid data format received');
        }
        
        allCNAs = cnaArray;
        filteredCNAs = [...allCNAs];
        
        console.log('Loaded CNA data:', allCNAs.length, 'CNAs');
        document.getElementById('loading').style.display = 'none';
        displayCNAs(filteredCNAs);
        setupEventListeners();
    } catch (error) {
        console.error('Error loading CNA data:', error);
        document.getElementById('loading').innerHTML = `
            <div style="color: #e74c3c; text-align: center;">
                <h3>Error loading data</h3>
                <p>Could not load CNA data. This might be because:</p>
                <ul style="text-align: left; display: inline-block;">
                    <li>The data hasn't been generated yet</li>
                    <li>The GitHub Action is still running</li>
                    <li>There's a network issue</li>
                </ul>
                <p>Please try refreshing the page in a few minutes.</p>
            </div>
        `;
    }
}

// Display CNAs as cards
function displayCNAs(cnas) {
    const container = document.getElementById('cnaCards');
    
    if (cnas.length === 0) {
        container.innerHTML = '<p>No CNAs found matching your criteria.</p>';
        return;
    }
    
    // Separate active and inactive CNAs
    const activeCNAs = cnas.filter(cna => {
        const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
        return totalCVEs > 0 && cna.message !== "No CVEs published in the last 6 months";
    });
    
    const inactiveCNAs = cnas.filter(cna => {
        const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
        return totalCVEs === 0 || cna.message === "No CVEs published in the last 6 months";
    });
    
    // Create cards for active CNAs first, then inactive ones
    const activeCardsHTML = activeCNAs.map(cna => createCNACard(cna)).join('');
    const inactiveCardsHTML = inactiveCNAs.map(cna => createCNACard(cna)).join('');
    
    container.innerHTML = activeCardsHTML + inactiveCardsHTML;
}

// Helper to format numbers: show as integer if .0, else one decimal
function formatScore(num) {
    if (typeof num !== 'number') return num;
    return num % 1 === 0 ? num.toString() : num.toFixed(1);
}

// Create individual CNA card
function createCNACard(cna) {
    const score = safeGet(cna, 'average_eas_score', 0);
    const percentile = safeGet(cna, 'percentile', 0);
    const scoreClass = getPercentileClass(percentile);
    const cnaName = safeGet(cna, 'cna', 'Unknown CNA');
    const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
    const avgFoundational = safeGet(cna, 'average_foundational_completeness', 0);
    const avgRootCause = safeGet(cna, 'average_root_cause_analysis', 0);
    const avgSeverity = safeGet(cna, 'average_severity_context', 0);
    const avgActionable = safeGet(cna, 'average_actionable_intelligence', 0);
    const avgFormat = safeGet(cna, 'average_data_format_precision', 0);
    
    // Check if CNA is inactive (no recent CVEs)
    const isInactive = totalCVEs === 0 || cna.message === "No CVEs published in the last 6 months";
    const inactiveClass = isInactive ? 'cna-inactive' : '';
    
    // Format percentile display
    const percentileText = isInactive ? 'N/A' : `${formatScore(percentile)}th percentile`;
    
    // Create safe filename for CNA page link
    const safeFilename = cnaName.replace(/[^a-zA-Z0-9\s\-_]/g, '').trim().replace(/\s+/g, '_');
    const cnaPageLink = isInactive ? '#' : `./cna/cna-detail.html?cna=${encodeURIComponent(cnaName)}`;
    
    return `
        <div class="cna-card ${scoreClass} ${inactiveClass}">
            <div class="cna-header">
                <h3 class="cna-name" title="${escapeHtml(cnaName)}">
                    ${isInactive ? escapeHtml(cnaName) : `<a href="${cnaPageLink}" class="cna-link">${escapeHtml(cnaName)}</a>`}
                </h3>
                <div class="cna-score-container">
                    <div class="cna-score">${formatScore(score)}/100</div>
                    <div class="cna-percentile">${percentileText}</div>
                </div>
            </div>
            <div class="cna-details">
                <div class="detail-item">
                    <span class="label">CVE Count:</span>
                    <span class="value">${formatScore(totalCVEs)}</span>
                </div>
                <div class="detail-item">
                    <span class="label">Foundational Completeness:</span>
                    <span class="value">${formatScore(avgFoundational)}/30</span>
                </div>
                <div class="detail-item">
                    <span class="label">Root Cause Analysis:</span>
                    <span class="value">${formatScore(avgRootCause)}/20</span>
                </div>
                <div class="detail-item">
                    <span class="label">Severity Context:</span>
                    <span class="value">${formatScore(avgSeverity)}/25</span>
                </div>
                <div class="detail-item">
                    <span class="label">Actionable Intelligence:</span>
                    <span class="value">${formatScore(avgActionable)}/20</span>
                </div>
                <div class="detail-item">
                    <span class="label">Data Format Precision:</span>
                    <span class="value">${formatScore(avgFormat)}/5</span>
                </div>
                ${cna.message ? `<div class="detail-item"><span class="label">Status:</span><span class="value">${escapeHtml(cna.message)}</span></div>` : ''}
                ${!isInactive ? `<div class="detail-item cna-view-details"><a href="${cnaPageLink}" class="view-details-link">View Individual CVEs →</a></div>` : ''}
            </div>
        </div>
    `;
}

// Get CSS class based on percentile (relative ranking)
function getPercentileClass(percentile) {
    if (percentile >= 75) return 'percentile-top';      // Top 25%
    if (percentile >= 50) return 'percentile-upper';    // Upper middle 25%
    if (percentile >= 25) return 'percentile-lower';    // Lower middle 25%
    return 'percentile-bottom';                          // Bottom 25%
}

// Get CSS class based on absolute score (kept for backward compatibility)
function getScoreClass(score) {
    if (score >= 80) return 'score-excellent';
    if (score >= 60) return 'score-good';
    if (score >= 40) return 'score-fair';
    return 'score-poor';
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
    filteredCNAs = allCNAs.filter(cna => {
        const cnaName = safeGet(cna, 'cna', '').toLowerCase();
        return cnaName.includes(searchTerm);
    });
    displayCNAs(filteredCNAs);
}

// Handle sorting
function handleSort(event) {
    const sortBy = event.target.value;
    
    // Separate active and inactive CNAs for sorting
    const activeCNAs = filteredCNAs.filter(cna => {
        const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
        return totalCVEs > 0 && cna.message !== "No CVEs published in the last 6 months";
    });
    
    const inactiveCNAs = filteredCNAs.filter(cna => {
        const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
        return totalCVEs === 0 || cna.message === "No CVEs published in the last 6 months";
    });
    
    // Sort only the active CNAs
    activeCNAs.sort((a, b) => {
        switch (sortBy) {
            case 'name':
                const nameA = safeGet(a, 'cna', '');
                const nameB = safeGet(b, 'cna', '');
                return nameA.localeCompare(nameB);
            case 'cveCount':
                const countA = safeGet(a, 'total_cves_scored', 0);
                const countB = safeGet(b, 'total_cves_scored', 0);
                return countB - countA;
            case 'score':
            default:
                const scoreA = safeGet(a, 'average_eas_score', 0);
                const scoreB = safeGet(b, 'average_eas_score', 0);
                return scoreB - scoreA;
        }
    });
    
    // Keep inactive CNAs in alphabetical order
    inactiveCNAs.sort((a, b) => {
        const nameA = safeGet(a, 'cna', '');
        const nameB = safeGet(b, 'cna', '');
        return nameA.localeCompare(nameB);
    });
    
    // Combine active CNAs first, then inactive CNAs
    filteredCNAs = [...activeCNAs, ...inactiveCNAs];
    
    displayCNAs(filteredCNAs);
}

// Safe property access helper
function safeGet(obj, property, defaultValue = 0) {
    return obj && obj[property] !== undefined ? obj[property] : defaultValue;
}

// Safe percentage formatting
function formatPercentage(value) {
    return typeof value === 'number' ? value.toFixed(1) : '0.0';
}

// Initialize the application
document.addEventListener('DOMContentLoaded', loadCNAData);