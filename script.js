// Main script file for CNA ScoreCard - fixing score calculation
// Enhanced Aggregate Scoring (EAS) Implementation
// Accessibility and modularity improvements

// Function to escape HTML for XSS prevention
function escapeHtml(unsafe) {
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

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
    
    // 1. Foundational Completeness (30 points: 15 for description + 10 for products + 5 for versions)
    if (cveData.description?.description_data?.[0]?.value) {
        const desc = cveData.description.description_data[0].value;
        const descLower = desc.toLowerCase();
        let descriptionQuality = 0;
        
        // Basic length and structure (3 points max)
        if (desc.length >= 50) descriptionQuality += 1;
        if (desc.length >= 100) descriptionQuality += 1;
        if (desc.length >= 200) descriptionQuality += 1;
        
        // Technical vulnerability types (4 points max)
        const vulnTypes = [
            'file inclusion', 'sql injection', 'access control', 'local file inclusion',
            'remote file inclusion', 'cross-site scripting', 'command injection', 
            'buffer overflow', 'sanitization', 'authentication bypass',
            'null pointer dereference', 'path traversal', 'improper validation',
            'xss', 'denial of service', 'out-of-bounds', 'code injection',
            'privilege escalation', 'xml external entity', 'double free',
            'use after free', 'race condition', 'integer overflow', 'format string',
            'heap overflow', 'stack overflow', 'type confusion', 'memory corruption',
            'deserialization', 'directory traversal', 'xxe', 'server-side request forgery',
            'ssrf', 'csrf', 'cross-site request forgery', 'remote code execution',
            'arbitrary code execution', 'prototype pollution', 'insecure deserialization',
            'ldap injection', 'xpath injection', 'template injection', 'header injection',
            'clickjacking', 'certificate validation', 'weak encryption', 'cryptographic',
            'resource exhaustion', 'infinite loop', 'zip slip', 'business logic',
            'improper input validation', 'missing authentication', 'weak authentication',
            'logic error'
        ];
        
        if (vulnTypes.some(type => descLower.includes(type))) {
            descriptionQuality += 2;
        }
        
        // Additional technical terms for more granular scoring
        const techTerms2 = [
            'vulnerability', 'exploit', 'attack', 'malicious', 'crafted',
            'arbitrary code', 'remote', 'local', 'authenticated', 'unauthenticated'
        ];
        const techMatches2 = techTerms2.filter(term => descLower.includes(term)).length;
        if (techMatches2 >= 2) descriptionQuality += 1;
        if (techMatches2 >= 4) descriptionQuality += 1;
        
        // Impact/exploitation context (4 points max)
        const impactTerms = [
            'leads to', 'disclose', 'execute arbitrary', 'arbitrary code execution', 
            'remote attackers', 'authenticated attackers', 'allows', 'bypass',
            'can be exploited', 'remote code execution', 'unauthenticated attackers',
            'attackers can', 'results in', 'manipulate', 'obtain', 'compromise',
            'gain access', 'unauthorized access', 'enables', 'permits', 'facilitates',
            'triggers', 'may allow', 'could allow', 'escalate privileges', 'circumvent',
            'retrieve', 'expose', 'information disclosure', 'data exposure',
            'sensitive information', 'leak', 'reveal', 'crash', 'hang', 'freeze',
            'terminate', 'local attackers', 'malicious users', 'crafted',
            'specially crafted', 'malicious', 'attacker', 'exploitation',
            'exploitable', 'when processing', 'during processing', 'via the'
        ];
        const impactMatches = impactTerms.filter(term => descLower.includes(term)).length;
        if (impactMatches >= 1) descriptionQuality += 1;
        if (impactMatches >= 2) descriptionQuality += 1;
        if (impactMatches >= 3) descriptionQuality += 2;
        
        // Technical specificity (4 points max)
        const techTerms = [
            'argument', 'component', 'class', 'parameter', 'function', 'field',
            'via the', 'within the', 'plugin', 'in the', 'api', 'service',
            'endpoint', 'interface', 'handler', 'through the', 'buffer',
            'library', 'method', 'variable', 'property', 'object', 'instance',
            'request', 'response', 'header', 'cookie', 'session', 'module',
            'framework', 'driver', 'daemon', 'process', 'thread', 'parser',
            'processor', 'validator', 'serializer', 'deserializer', 'encoder',
            'decoder', 'protocol', 'socket', 'connection', 'channel', 'stream',
            'queue', 'when processing', 'during processing', 'while handling',
            'when parsing', 'during parsing', 'application', 'implementation',
            'configuration', 'initialization', 'authentication mechanism',
            'authorization mechanism', 'validation routine', 'sanitization'
        ];
        const techMatches = techTerms.filter(term => descLower.includes(term)).length;
        if (techMatches >= 1) descriptionQuality += 1;
        if (techMatches >= 3) descriptionQuality += 1;
        if (techMatches >= 5) descriptionQuality += 2;
        
        // Generic content penalty (max -2 points)
        const genericPhrases = [
            'vulnerability exists', 'security issue', 'security vulnerability',
            'issue has been identified', 'problem has been found', 'flaw exists',
            'weakness in', 'issue in', 'vulnerability in the', 'security flaw',
            'security weakness', 'may allow', 'could allow', 'might allow',
            'potential vulnerability', 'security problem', 'possible to',
            'it is possible', 'there is a vulnerability', 'vulnerability was found',
            'vulnerability was discovered', 'security bug'
        ];
        const genericCount = genericPhrases.filter(phrase => descLower.includes(phrase)).length;
        if (desc.length < 100 && genericCount >= 2) {
            descriptionQuality -= 2;
        }
        
        foundationalCompleteness += Math.max(0, Math.min(15, descriptionQuality));
    }
    
    // Check for affected products (10 points)
    if (cveData.affects?.vendor?.vendor_data && cveData.affects.vendor.vendor_data.length > 0) {
        foundationalCompleteness += 10;
        
        // Check for version information (5 points)
        const hasVersionInfo = cveData.affects.vendor.vendor_data.some(vendor =>
            vendor.product?.product_data?.some(product =>
                product.version?.version_data?.some(version =>
                    version.version_value && version.version_value !== 'n/a'
                )
            )
        );
        if (hasVersionInfo) {
            foundationalCompleteness += 5;
        }
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
    
    // 5. Data Format Precision (5 points total - all or nothing)
    let formatChecks = [];
    
    // Check 1: CPE format
    let hasValidCpe = false;
    if (cveData.affects?.vendor?.vendor_data) {
        for (const vendor of cveData.affects.vendor.vendor_data) {
            if (vendor.product?.product_data) {
                for (const product of vendor.product.product_data) {
                    if (product.version?.version_data) {
                        for (const version of product.version.version_data) {
                            if (version.platform && Array.isArray(version.platform)) {
                                if (version.platform.some(p => p && p.startsWith('cpe:'))) {
                                    hasValidCpe = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (hasValidCpe) break;
                }
            }
            if (hasValidCpe) break;
        }
    }
    formatChecks.push(hasValidCpe);
    
    // Check 2: CVSS format
    let hasValidCvss = false;
    if (cveData.impact?.cvss?.vector_string && cveData.impact?.cvss?.base_score) {
        const cvss = cveData.impact.cvss.vector_string;
        if (cvss.includes('CVSS:3') || cvss.includes('CVSS:4')) {
            hasValidCvss = true;
        }
    }
    formatChecks.push(hasValidCvss);
    
    // Check 3: CWE format
    let hasValidCwe = false;
    if (cveData.problemtype?.problemtype_data) {
        for (const pt of cveData.problemtype.problemtype_data) {
            if (pt.description) {
                for (const desc of pt.description) {
                    if (desc.value && desc.value.startsWith('CWE-') && 
                        desc.value.substring(4).match(/^\d+$/)) {
                        hasValidCwe = true;
                        break;
                    }
                }
            }
            if (hasValidCwe) break;
        }
    }
    formatChecks.push(hasValidCwe);
    
    // Only award points if ALL format checks pass
    if (formatChecks.every(check => check)) {
        dataFormatPrecision = 5;
    }
    
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

// Modernized sorting logic
const sortOptions = {
    score: (a, b) => safeGet(b, 'average_eas_score', 0) - safeGet(a, 'average_eas_score', 0),
    name: (a, b) => safeGet(a, 'cna', '').localeCompare(safeGet(b, 'cna', '')),
    cveCount: (a, b) => safeGet(b, 'total_cves_scored', 0) - safeGet(a, 'total_cves_scored', 0)
};

function getSortedCNAs(cnas, sortBy = 'score') {
    // Separate active and inactive CNAs
    const activeCNAs = cnas.filter(cna => {
        const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
        return totalCVEs > 0 && cna.message !== "No CVEs published in the last 6 months";
    });
    const inactiveCNAs = cnas.filter(cna => {
        const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
        return totalCVEs === 0 || cna.message === "No CVEs published in the last 6 months";
    });
    // Sort active CNAs by selected sort
    activeCNAs.sort(sortOptions[sortBy]);
    // Always sort inactive CNAs by name
    inactiveCNAs.sort(sortOptions['name']);
    return [...activeCNAs, ...inactiveCNAs];
}

// Display CNAs as cards
function displayCNAs(cnas, sortBy = 'score') {
    const container = document.getElementById('cnaCards');
    if (cnas.length === 0) {
        container.innerHTML = '<p>No CNAs found matching your criteria.</p>';
        return;
    }
    const sortedCNAs = getSortedCNAs(cnas, sortBy);
    container.innerHTML = sortedCNAs.map(cna => createCNACard(cna)).join('');
}

// Helper to format numbers: show as integer if .0, else one decimal (handles string '100.0' too)
function formatScore(num) {
    // Convert to number if possible
    const n = (typeof num === 'string') ? Number(num) : num;
    if (typeof n === 'number' && !isNaN(n)) {
        return n % 1 === 0 ? n.toString() : n.toFixed(1);
    }
    return num;
}

// Create individual CNA card
function createCNACard(cna) {
    const score = Number(safeGet(cna, 'average_eas_score', 0));
    const rank = safeGet(cna, 'rank', null);
    const activeCount = safeGet(cna, 'active_cna_count', null);
    const percentile = safeGet(cna, 'percentile', 0);
    const scoreClass = getPercentileClass(percentile);
    const cnaName = safeGet(cna, 'cna', 'Unknown');
    const totalCVEs = Number(safeGet(cna, 'total_cves_scored', 0));
    const avgFoundational = Number(safeGet(cna, 'average_foundational_completeness', 0));
    const avgRootCause = Number(safeGet(cna, 'average_root_cause_analysis', 0));
    const avgSoftwareId = Number(safeGet(cna, 'average_software_identification', 0));
    const avgSeverity = Number(safeGet(cna, 'average_severity_context', 0));
    const avgActionable = Number(safeGet(cna, 'average_actionable_intelligence', 0));
    const avgFormat = Number(safeGet(cna, 'average_data_format_precision', 0));
    
    // Check if CNA is inactive (no recent CVEs)
    const isInactive = totalCVEs === 0 || cna.message === "No CVEs published in the last 6 months";
    const inactiveClass = isInactive ? 'cna-inactive' : '';
    
    // Format rank display
    let rankText = 'N/A';
    if (!isInactive && rank && activeCount) {
        rankText = `Rank: ${rank} of ${activeCount}`;
    }
    
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
                    <div class="cna-percentile">${rankText}</div>
                </div>
            </div>
            <div class="cna-details">
                <div class="detail-item">
                    <span class="label">CVE Count:</span>
                    <span class="value">${formatScore(totalCVEs)}</span>
                </div>
                <div class="detail-item">
                    <span class="label">Foundational Completeness:</span>
                    <span class="value">${formatScore(avgFoundational)}/32</span>
                </div>
                <div class="detail-item">
                    <span class="label">Root Cause Analysis:</span>
                    <span class="value">${formatScore(avgRootCause)}/11</span>
                </div>
                <div class="detail-item">
                    <span class="label">Software Identification:</span>
                    <span class="value">${formatScore(avgSoftwareId)}/11</span>
                </div>
                <div class="detail-item">
                    <span class="label">Severity Context:</span>
                    <span class="value">${formatScore(avgSeverity)}/26</span>
                </div>
                <div class="detail-item">
                    <span class="label">Actionable Intelligence:</span>
                    <span class="value">${formatScore(avgActionable)}/20</span>
                </div>
                ${cna.message ? `<div class="detail-item"><span class="label">Status:</span><span class="value">${escapeHtml(cna.message)}</span></div>` : ''}
                ${!isInactive ? `<div class="detail-item cna-view_details"><a href="${cnaPageLink}" class="view-details-link">View Individual CVEs →</a></div>` : ''}
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

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('searchInput');
    searchInput.addEventListener('input', handleSearch);
    
    // Sort functionality
    const sortSelect = document.getElementById('sortSelect');
    sortSelect.addEventListener('change', handleSort);
    
    // Hide inactive toggle functionality
    const hideInactiveToggle = document.getElementById('hideInactiveToggle');
    hideInactiveToggle.addEventListener('click', handleFilter);
}

// Handle search
function handleSearch(event) {
    applyFilters();
}

// Handle sorting
function handleSort(event) {
    const sortBy = event.target.value;
    displayCNAs(filteredCNAs, sortBy);
}

// Handle filter toggle
function handleFilter() {
    const button = document.getElementById('hideInactiveToggle');
    const isActive = button.getAttribute('data-active') === 'true';
    // Toggle the state
    const newState = !isActive;
    button.setAttribute('data-active', newState.toString());
    // Update button appearance
    if (newState) {
        button.classList.add('active');
        button.textContent = 'Show CNAs with 0 CVEs';
    } else {
        button.classList.remove('active');
        button.textContent = 'Hide CNAs with 0 CVEs';
    }
    applyFilters();
}

// Apply all filters (search + hide inactive toggle)
function applyFilters() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const hideInactive = document.getElementById('hideInactiveToggle').getAttribute('data-active') === 'true';
    
    filteredCNAs = allCNAs.filter(cna => {
        // Apply search filter
        const cnaName = safeGet(cna, 'cna', '').toLowerCase();
        const matchesSearch = cnaName.includes(searchTerm);
        // Apply inactive filter
        const totalCVEs = safeGet(cna, 'total_cves_scored', 0);
        const isInactive = totalCVEs === 0 || cna.message === "No CVEs published in the last 6 months";
        const showInactive = !hideInactive || !isInactive;
        return matchesSearch && showInactive;
    });
    const sortBy = document.getElementById('sortSelect').value;
    displayCNAs(filteredCNAs, sortBy);
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
document.addEventListener('DOMContentLoaded', () => {
    const sortSelect = document.getElementById('sortSelect');
    sortSelect.value = 'score';
    // Set initial state: hide inactive CNAs
    const hideInactiveToggle = document.getElementById('hideInactiveToggle');
    hideInactiveToggle.setAttribute('data-active', 'true');
    hideInactiveToggle.classList.add('active');
    hideInactiveToggle.textContent = 'Show CNAs with 0 CVEs';
    loadCNAData();
});