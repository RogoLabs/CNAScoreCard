// CNA Detail Page Script - Enhanced Aggregate Scoring (EAS) Implementation
let cnaData = {};
let cveScores = [];
let allCVEs = [];

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
            'buffer overflow', 'sql injection', 'xss', 'cross-site scripting',
            'privilege escalation', 'code injection', 'path traversal',
            'denial of service', 'memory corruption', 'use after free',
            'race condition', 'authentication bypass', 'authorization',
            'deserialization', 'command injection', 'file inclusion',
            'directory traversal', 'format string', 'integer overflow',
            'xml external entity', 'xxe', 'server-side request forgery', 'ssrf',
            'csrf', 'cross-site request forgery', 'heap overflow', 'stack overflow',
            'double free', 'out-of-bounds', 'type confusion', 'logic error',
            'access control', 'improper validation', 'improper input validation',
            'missing authentication', 'weak encryption', 'cryptographic',
            'certificate validation', 'tls', 'ssl'
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
            'allows', 'enables', 'leads to', 'results in', 'can be exploited',
            'may allow', 'could allow', 'permits', 'expose', 'disclose',
            'execute arbitrary', 'gain access', 'bypass', 'escalate',
            'compromise', 'unauthorized', 'malicious', 'attacker'
        ];
        const impactMatches = impactTerms.filter(term => descLower.includes(term)).length;
        if (impactMatches >= 1) descriptionQuality += 1;
        if (impactMatches >= 2) descriptionQuality += 1;
        if (impactMatches >= 3) descriptionQuality += 2;
        
        // Technical specificity (4 points max)
        const techTerms = [
            'function', 'method', 'parameter', 'header', 'field', 'variable',
            'endpoint', 'api', 'request', 'response', 'cookie', 'session',
            'component', 'module', 'library', 'framework', 'protocol',
            'when processing', 'during', 'while handling', 'in the', 'via the'
        ];
        const techMatches = techTerms.filter(term => descLower.includes(term)).length;
        if (techMatches >= 1) descriptionQuality += 1;
        if (techMatches >= 3) descriptionQuality += 1;
        if (techMatches >= 5) descriptionQuality += 2;
        
        // Generic content penalty (max -2 points)
        const genericPhrases = [
            'vulnerability exists', 'security issue', 'security vulnerability',
            'issue has been identified', 'problem has been found', 'flaw exists',
            'weakness in', 'issue in', 'vulnerability in the'
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
    
    // Calculate percentile based on score ranges
    const percentile = calculatePercentile(overallScore);
    
    return {
        cveId,
        overallScore: parseFloat(overallScore.toFixed(1)),
        percentile,
        foundationalCompleteness,
        rootCauseAnalysis,
        securityContext,
        actionableIntelligence,
        dataFormatPrecision
    };
}

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
    if (percentile >= 80) return 'percentile-top';
    if (percentile >= 60) return 'percentile-upper';
    if (percentile >= 40) return 'percentile-lower';
    return 'percentile-bottom';
}

// Function to load CNA data
async function loadCNAData() {
    try {
        const response = await fetch(`data/${SAFE_FILENAME}.json`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        // Use the EAS data structure directly
        const cnaInfo = data.cna_info || {};
        const recentCVEs = data.recent_cves || [];
        // Use the correct total CVE count for the CNA
        const totalCVEs = data.total_cves || cnaInfo.total_cves_scored || recentCVEs.length;

        // Extract ranking and active CNA count if available
        cnaData.ranking = (typeof cnaInfo.rank !== 'undefined' && typeof cnaInfo.active_cna_count !== 'undefined') ? `Rank: ${cnaInfo.rank} of ${cnaInfo.active_cna_count}` : 'N/A';

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
                <p>Could not load data for ${CNA_NAME}. Please check if the CNA name is correct.</p>
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
                        <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${score.cveId}" target="_blank">${score.cveId}</a>
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