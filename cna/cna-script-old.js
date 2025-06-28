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

// CNA data from CVE Project
let CNA_LIST_DATA = null;

// Fetch CNA list data
async function fetchCNAListData() {
    const remoteUrl = 'https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json';
    const fallbackPath = 'data/CNAsList.json';
    
    // Try remote URL first
    try {
        const response = await fetch(remoteUrl);
        if (response.ok) {
            CNA_LIST_DATA = await response.json();
            return;
        }
    } catch (error) {
        console.log('Error fetching from remote URL:', remoteUrl, error);
    }
    
    // Fallback to local copy
    try {
        const response = await fetch(fallbackPath);
        if (response.ok) {
            CNA_LIST_DATA = await response.json();
            return;
        }
    } catch (error) {
        console.log('Error fetching from fallback:', fallbackPath, error);
    }
    
    console.warn('Could not fetch CNA list data from remote or local sources');
}

// Find CNA details by name
function findCNADetails(cnaName) {
    if (!CNA_LIST_DATA || !Array.isArray(CNA_LIST_DATA)) {
        return null;
    }
    
    // Try exact matches first
    let match = CNA_LIST_DATA.find(cna => 
        cna.shortName === cnaName || 
        cna.organizationName === cnaName
    );
    
    if (match) {
        return match;
    }
    
    // Try case-insensitive matches
    const lowerCnaName = cnaName.toLowerCase();
    match = CNA_LIST_DATA.find(cna => 
        cna.shortName?.toLowerCase() === lowerCnaName ||
        cna.organizationName?.toLowerCase() === lowerCnaName
    );
    
    if (match) {
        return match;
    }
    
    // Try partial matches for common variations
    match = CNA_LIST_DATA.find(cna => {
        const shortName = cna.shortName?.toLowerCase() || '';
        const orgName = cna.organizationName?.toLowerCase() || '';
        
        // Check if any part matches
        return shortName.includes(lowerCnaName) || 
               lowerCnaName.includes(shortName) ||
               orgName.includes(lowerCnaName) ||
               lowerCnaName.includes(orgName);
    });
    
    if (match) {
        return match;
    }
    
    return null;
}

// Initialize CNA data fetch
fetchCNAListData();

// Function to calculate percentile based on score
function calculatePercentile(score) {
    if (score >= 80) return 90;
    if (score >= 60) return 70;
    if (score >= 40) return 50;
    if (score >= 20) return 30;
    return 10;
}

// Function to get percentile class for styling
function getPercentileClass(percentile) {
    if (percentile >= 75) return 'percentile-top';
    if (percentile >= 50) return 'percentile-upper';
    if (percentile >= 25) return 'percentile-lower';
    return 'percentile-bottom';
}

// Function to load CNA data
async function loadCNAData() {
    try {
        // Ensure CNA list data is loaded first
        if (!CNA_LIST_DATA) {
            await fetchCNAListData();
        }
        // Only look in the new location for CNA data files
        const dataPath = `data/${window.SAFE_FILENAME}.json`;
        let response = null;
        let data = null;
        try {
            response = await fetch(dataPath);
            if (response.ok) {
                data = await response.json();
            }
        } catch (err) {
            console.log('Error fetching CNA data from:', dataPath, err);
        }
        if (!data) {
            throw new Error(`Could not load CNA data for ${window.SAFE_FILENAME}`);
        }
        // Use the EAS data structure directly
        const cnaInfo = data.cna_info || {};
        const recentCVEs = data.recent_cves || [];
        // Use the correct total CVE count for the CNA
        const totalCVEs = data.total_cves || cnaInfo.total_cves_scored || recentCVEs.length;

        // Extract ranking and active CNA count if available
        cnaData.ranking = (typeof cnaInfo.rank !== 'undefined' && typeof cnaInfo.active_cna_count !== 'undefined') ? `Rank: ${cnaInfo.rank} of ${cnaInfo.active_cna_count}` : 'N/A';

        // Get additional CNA details from CVE Project data - try multiple variations
        let cnaDetails = findCNADetails(window.CNA_NAME);
        if (!cnaDetails) {
            // Try with underscores replaced with spaces
            const nameWithSpaces = window.CNA_NAME.replace(/_/g, ' ');
            cnaDetails = findCNADetails(nameWithSpaces);
        }
        if (!cnaDetails) {
            // Try original filename format (from JSON)
            const originalName = cnaInfo.cna;
            if (originalName) {
                cnaDetails = findCNADetails(originalName);
            }
        }
        if (!cnaDetails) {
            // Try with different case variations and common name mappings
            const variations = [
                window.CNA_NAME.toLowerCase(),
                window.CNA_NAME.toUpperCase(),
                window.CNA_NAME.replace(/_/g, ''),
                window.CNA_NAME.replace(/_/g, '-'),
            ];
            
            // Special case mappings for known CNAs
            const specialMappings = {
                'palo_alto': ['palo_alto', 'Palo Alto Networks, Inc.', 'palo alto networks', 'Palo Alto', 'paloalto'],
                'google_android': ['google_android', 'Android (associated with Google Inc. or Open Handset Alliance)', 'Android', 'Google Android'],
                'github_m': ['GitHub_M', 'GitHub, Inc.'],
                'github_p': ['GitHub_P', 'GitHub, Inc. (Products Only)'],
                'meta': ['Meta', 'Meta Platforms, Inc.', 'Facebook'],
                'microsoft': ['microsoft', 'Microsoft Corporation'],
                'apple': ['apple', 'Apple Inc.'],
                'oracle': ['oracle', 'Oracle Corporation'],
                'adobe': ['adobe', 'Adobe Systems Incorporated'],
                'canonical': ['canonical', 'Canonical Ltd.'],
                'redhat': ['redhat', 'Red Hat, Inc.'],
                'debian': ['debian', 'Debian GNU/Linux'],
            };
            
            if (specialMappings[window.CNA_NAME.toLowerCase()]) {
                variations.push(...specialMappings[window.CNA_NAME.toLowerCase()]);
            }
            
            for (const variation of variations) {
                cnaDetails = findCNADetails(variation);
                if (cnaDetails) {
                    break;
                }
            }
        }
        cnaData.details = cnaDetails;
        
        // Use the pre-calculated scores from the EAS system
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
        
        // Convert CVE data to display format
        cveScores = recentCVEs.map(cve => {
            return {
                cveId: cve.cveId,
                overallScore: cve.totalEasScore || 0,
                percentile: calculatePercentile(cve.totalEasScore || 0),
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
                <p>Could not load data for ${window.CNA_NAME}. Please check if the CNA name is correct.</p>
                <p><small>Error: ${error.message}</small></p>
            </div>
        `;
    }
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

// Function to display CNA header
function displayCNAHeader(overallScore, percentile, totalCVEs, breakdown, ranking) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('cnaHeader').style.display = 'block';
    document.getElementById('cveSection').style.display = 'block';

    const cnaDetails = cnaData.details;
    
    // Extract CNA details for header integration
    let longName = '';
    let scope = '';
    let dateBecameCNA = '';
    let advisoryUrl = null;
    let disclosurePolicyUrl = null;
    
    if (cnaDetails) {
        longName = cnaDetails.organizationName !== window.CNA_NAME ? cnaDetails.organizationName : '';
        // Fix: Always handle scope as array or string, fallback to empty string
        if (Array.isArray(cnaDetails.scope)) {
            scope = cnaDetails.scope.filter(Boolean).join(', ');
        } else if (typeof cnaDetails.scope === 'string') {
            scope = cnaDetails.scope.trim();
        } else {
            scope = '';
        }
        dateBecameCNA = cnaDetails.dateBecameCNA || '';
        // Defensive check for advisory URL
        if (cnaDetails.securityAdvisories && Array.isArray(cnaDetails.securityAdvisories.advisories)) {
            const advisory = cnaDetails.securityAdvisories.advisories.find(a => a && typeof a.url === 'string' && a.url.trim());
            if (advisory) {
                advisoryUrl = advisory.url.trim();
            }
        }
        // Fix: Properly extract disclosurePolicy from array (CNAsList.json)
        if (Array.isArray(cnaDetails.disclosurePolicy)) {
            // Support array of objects with url property (new format)
            const dpObj = cnaDetails.disclosurePolicy.find(x => x && typeof x === 'object' && x.url && typeof x.url === 'string' && x.url.trim());
            if (dpObj) disclosurePolicyUrl = dpObj.url.trim();
            // Fallback: array of strings (legacy)
            if (!disclosurePolicyUrl) {
                const dpStr = cnaDetails.disclosurePolicy.find(x => typeof x === 'string' && x.trim().startsWith('http'));
                if (dpStr) disclosurePolicyUrl = dpStr.trim();
            }
        } else if (typeof cnaDetails.disclosurePolicy === 'string' && cnaDetails.disclosurePolicy.trim().startsWith('http')) {
            disclosurePolicyUrl = cnaDetails.disclosurePolicy.trim();
        }
    }

    // Modern, clean CNA header card with integrated CNA details
    document.getElementById('cnaHeader').innerHTML = `
        <div class="cna-header-container">
            <div class="cna-detail-card">
                <div class="cna-title-section">
                    <div class="cna-title-content">
                        <h1 class="cna-title">${window.CNA_NAME.toUpperCase()}</h1>
                        ${longName ? `<div class="cna-org-name">${longName}</div>` : ''}
                        ${(scope || advisoryUrl || disclosurePolicyUrl) ? `
                            <div class="cna-scope-box">
                                ${scope ? `<div><span class='scope-label'>Scope:</span> <span class='scope-value'>${scope}</span></div>` : ''}
                                ${(advisoryUrl || disclosurePolicyUrl) ? `<div style='border-top:1px solid #dee2e6; margin: 12px 0 0 0;'></div>` : ''}
                                <div class='cna-links-centered'>
                                    ${advisoryUrl ? `<a href='${advisoryUrl}' target='_blank' rel='noopener noreferrer'>Security Advisories</a>` : ''}
                                    ${disclosurePolicyUrl ? `<a href='${disclosurePolicyUrl}' target='_blank' rel='noopener noreferrer'>Disclosure Policy</a>` : ''}
                                </div>
                            </div>
                        ` : ''}
                    </div>
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
                        <div class="metric-value">${ranking || 'N/A'}</div>
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
                        <a href="https://www.cve.org/CVERecord?id=${score.cveId}" target="_blank">${score.cveId}</a>
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