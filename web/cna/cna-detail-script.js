document.addEventListener('DOMContentLoaded', function() {
    const urlParams = new URLSearchParams(window.location.search);
    const cnaName = urlParams.get('cna') || urlParams.get('shortName');

    if (cnaName) {
        loadCnaData(cnaName);
        setupEventListeners();
    } else {
        showError('CNA not specified.');
    }
});

let currentCveData = [];
let filteredCveData = [];

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

async function loadCnaData(cnaName) {
    try {
        // Ensure CNA list data is loaded first
        if (!CNA_LIST_DATA) {
            await fetchCNAListData();
        }

        // Load both CNA data and details
        const [cnaResponse, detailsResponse] = await Promise.all([
            fetch(`data/${cnaName}.json`),
            fetch(`data/cna_details.json`)
        ]);
        
        if (!cnaResponse.ok) {
            throw new Error(`Data for ${cnaName} not found.`);
        }
        
        const cnaData = await cnaResponse.json();
        const cnaDetails = detailsResponse.ok ? await detailsResponse.json() : {};
        
        // Get additional CNA details from CVE Project data - try multiple variations
        let extendedCnaDetails = findCNADetails(cnaName);
        if (!extendedCnaDetails) {
            // Try with underscores replaced with spaces
            const nameWithSpaces = cnaName.replace(/_/g, ' ');
            extendedCnaDetails = findCNADetails(nameWithSpaces);
        }
        if (!extendedCnaDetails) {
            // Try original filename format (from JSON)
            const originalName = cnaData.cna_info?.cna;
            if (originalName) {
                extendedCnaDetails = findCNADetails(originalName);
            }
        }
        
        // Store CVE data globally for filtering/sorting
        currentCveData = cnaData.recent_cves || [];
        filteredCveData = [...currentCveData];
        
        // Combine the basic details with extended details
        const combinedDetails = {
            ...cnaDetails[cnaName],
            ...extendedCnaDetails
        };
        
        renderCnaHeader(cnaData.cna_info, combinedDetails);
        renderCveCards(filteredCveData);
        
        // Set initial count in section title
        const sectionTitle = document.querySelector('.section-title');
        if (sectionTitle && currentCveData.length > 0) {
            sectionTitle.textContent = `Recent CVE Scores (${currentCveData.length})`;
        }

        document.getElementById('loading').style.display = 'none';
        document.getElementById('cnaHeader').style.display = 'block';
        document.getElementById('cveSection').style.display = 'block';

    } catch (error) {
        showError(error.message);
    }
}

function renderCnaHeader(cnaInfo, cnaDetails) {
    if (!cnaInfo) return;
    
    // Get CNA name for comparison
    const cnaName = cnaInfo.cna;
    
    // Try to get additional CNA details from the CNA list data
    let additionalDetails = null;
    if (CNA_LIST_DATA) {
        additionalDetails = findCNADetails(cnaName);
    }
    
    // Prefer details from the additional data source, fallback to provided details
    const finalDetails = additionalDetails || cnaDetails || {};
    
    // Set title and organization name
    const title = finalDetails.shortName || cnaDetails?.shortName || capitalizeWords(cnaInfo.cna);
    document.getElementById('cnaTitle').textContent = title;
    
    // Display organization name if different from short name
    const orgNameElement = document.getElementById('cnaOrgName');
    const orgName = finalDetails.organizationName;
    if (orgName && orgName !== title) {
        orgNameElement.textContent = orgName;
        orgNameElement.style.display = 'block';
    } else if (finalDetails.country) {
        orgNameElement.textContent = `Based in ${finalDetails.country}`;
        orgNameElement.style.display = 'block';
    } else {
        orgNameElement.style.display = 'none';
    }
    
    // Extract scope, advisory URL, and disclosure policy URL
    let scope = '';
    let advisoryUrl = null;
    let disclosurePolicyUrl = null;
    
    // Handle scope (can be array or string)
    if (Array.isArray(finalDetails.scope)) {
        scope = finalDetails.scope.filter(Boolean).join(', ');
    } else if (typeof finalDetails.scope === 'string') {
        scope = finalDetails.scope.trim();
    }
    
    // Extract advisory URL
    if (finalDetails.securityAdvisories && Array.isArray(finalDetails.securityAdvisories.advisories)) {
        const advisory = finalDetails.securityAdvisories.advisories.find(a => a && typeof a.url === 'string' && a.url.trim());
        if (advisory) {
            advisoryUrl = advisory.url.trim();
        }
    }
    
    // Extract disclosure policy URL
    if (Array.isArray(finalDetails.disclosurePolicy)) {
        // Support array of objects with url property
        const dpObj = finalDetails.disclosurePolicy.find(x => x && typeof x === 'object' && x.url && typeof x.url === 'string' && x.url.trim());
        if (dpObj) {
            disclosurePolicyUrl = dpObj.url.trim();
        } else {
            // Fallback: array of strings
            const dpStr = finalDetails.disclosurePolicy.find(x => typeof x === 'string' && x.trim().startsWith('http'));
            if (dpStr) {
                disclosurePolicyUrl = dpStr.trim();
            }
        }
    } else if (typeof finalDetails.disclosurePolicy === 'string' && finalDetails.disclosurePolicy.trim().startsWith('http')) {
        disclosurePolicyUrl = finalDetails.disclosurePolicy.trim();
    }
    
    // Set scope information with links if available
    const scopeElement = document.getElementById('cnaScope');
    if (scope || advisoryUrl || disclosurePolicyUrl) {
        let scopeContent = '';
        
        if (scope) {
            scopeContent += `<div><strong>Scope:</strong> ${scope}</div>`;
        }
        
        if (advisoryUrl || disclosurePolicyUrl) {
            if (scope) {
                scopeContent += `<div style='border-top:1px solid #dee2e6; margin: 12px 0 8px 0;'></div>`;
            }
            scopeContent += `<div class='cna-links-centered'>`;
            if (advisoryUrl) {
                scopeContent += `<a href='${advisoryUrl}' target='_blank' rel='noopener noreferrer'>Security Advisories</a>`;
            }
            if (disclosurePolicyUrl) {
                scopeContent += `<a href='${disclosurePolicyUrl}' target='_blank' rel='noopener noreferrer'>Disclosure Policy</a>`;
            }
            scopeContent += `</div>`;
        }
        
        scopeElement.innerHTML = scopeContent;
        scopeElement.style.display = 'block';
    } else {
        scopeElement.style.display = 'none';
    }
    
    // Set main metrics
    document.querySelector('#cnaMainScore .metric-value').textContent = 
        cnaInfo.average_eas_score?.toFixed(1) || 'N/A';
    
    // Format rank display
    if (cnaInfo.rank && cnaInfo.active_cna_count) {
        document.querySelector('#cnaRank .metric-value').textContent = `#${cnaInfo.rank}`;
    } else {
        document.querySelector('#cnaRank .metric-value').textContent = 'N/A';
    }
    
    // Format percentile
    if (cnaInfo.percentile !== undefined) {
        const percentile = parseFloat(cnaInfo.percentile);
        document.querySelector('#cnaPercentile .metric-value').textContent = 
            `${percentile.toFixed(1)}th`;
    } else {
        document.querySelector('#cnaPercentile .metric-value').textContent = 'N/A';
    }
    
    document.querySelector('#cnaTotalCves .metric-value').textContent = 
        cnaInfo.total_cves_scored || cnaInfo.total_cves || 'N/A';
    
    // Set breakdown scores with maximum values
    document.getElementById('foundational').textContent = 
        `${cnaInfo.average_foundational_completeness?.toFixed(1) || 'N/A'}${cnaInfo.average_foundational_completeness ? '/30' : ''}`;
    document.getElementById('rootCause').textContent = 
        `${cnaInfo.average_root_cause_analysis?.toFixed(1) || 'N/A'}${cnaInfo.average_root_cause_analysis ? '/10' : ''}`;
    document.getElementById('softwareId').textContent = 
        `${cnaInfo.average_software_identification?.toFixed(1) || 'N/A'}${cnaInfo.average_software_identification ? '/10' : ''}`;
    document.getElementById('severityContext').textContent = 
        `${cnaInfo.average_severity_context?.toFixed(1) || 'N/A'}${cnaInfo.average_severity_context ? '/25' : ''}`;
    document.getElementById('actionableIntel').textContent = 
        `${cnaInfo.average_actionable_intelligence?.toFixed(1) || 'N/A'}${cnaInfo.average_actionable_intelligence ? '/20' : ''}`;
    document.getElementById('dataFormat').textContent = 
        `${cnaInfo.average_data_format_precision?.toFixed(1) || 'N/A'}${cnaInfo.average_data_format_precision ? '/5' : ''}`;
}

function renderCveCards(cves) {
    const container = document.getElementById('cveCards');
    if (!container) return;

    container.innerHTML = '';

    if (!cves || cves.length === 0) {
        container.innerHTML = '<div class="no-data">No CVEs found for this CNA.</div>';
        return;
    }

    cves.forEach(cve => {
        const card = createCveCard(cve);
        container.appendChild(card);
    });
}

function createCveCard(cve) {
    const card = document.createElement('div');
    card.className = `cve-card ${getScoreClass(cve.totalEasScore)}`;
    
    const publishedDate = new Date(cve.datePublished).toLocaleDateString();
    
    card.innerHTML = `
        <div class="cve-header">
            <h3 class="cve-id">
                <a href="../cves/cve-detail.html?id=${cve.cveId}" target="_blank">${cve.cveId}</a>
            </h3>
            <div class="cve-meta">
                <div class="cve-score">${cve.totalEasScore}</div>
                <div class="cve-date">${publishedDate}</div>
            </div>
        </div>
        <div class="cve-details">
            <div class="cve-detail-item">
                <span class="cve-detail-label">Foundational</span>
                <span class="cve-detail-value">${cve.scoreBreakdown?.foundationalCompleteness || 0}</span>
            </div>
            <div class="cve-detail-item">
                <span class="cve-detail-label">Root Cause</span>
                <span class="cve-detail-value">${cve.scoreBreakdown?.rootCauseAnalysis || 0}</span>
            </div>
            <div class="cve-detail-item">
                <span class="cve-detail-label">Software ID</span>
                <span class="cve-detail-value">${cve.scoreBreakdown?.softwareIdentification || 0}</span>
            </div>
            <div class="cve-detail-item">
                <span class="cve-detail-label">Severity</span>
                <span class="cve-detail-value">${cve.scoreBreakdown?.severityAndImpactContext || 0}</span>
            </div>
            <div class="cve-detail-item">
                <span class="cve-detail-label">Actionable</span>
                <span class="cve-detail-value">${cve.scoreBreakdown?.actionableIntelligence || 0}</span>
            </div>
            <div class="cve-detail-item">
                <span class="cve-detail-label">Data Format</span>
                <span class="cve-detail-value">${cve.scoreBreakdown?.dataFormatAndPrecision || 0}</span>
            </div>
        </div>
    `;
    
    return card;
}

function getScoreClass(score) {
    if (score >= 80) return 'percentile-excellent';
    if (score >= 60) return 'percentile-good';
    if (score >= 40) return 'percentile-medium';
    return 'percentile-low';
}

function setupEventListeners() {
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    const filterSelect = document.getElementById('filterSelect');
    
    if (searchInput) {
        searchInput.addEventListener('input', filterAndSort);
    }
    
    if (sortSelect) {
        sortSelect.addEventListener('change', filterAndSort);
    }
    
    if (filterSelect) {
        filterSelect.addEventListener('change', filterAndSort);
    }
}

function filterAndSort() {
    const searchTerm = document.getElementById('searchInput')?.value.toLowerCase() || '';
    const sortBy = document.getElementById('sortSelect')?.value || 'score';
    const filterBy = document.getElementById('filterSelect')?.value || 'all';
    
    // Filter by search term
    let filtered = currentCveData.filter(cve => 
        cve.cveId.toLowerCase().includes(searchTerm) ||
        cve.assigningCna.toLowerCase().includes(searchTerm)
    );
    
    // Filter by score range
    if (filterBy !== 'all') {
        filtered = filtered.filter(cve => {
            const score = cve.totalEasScore;
            switch (filterBy) {
                case 'high': return score >= 80;
                case 'medium': return score >= 60 && score < 80;
                case 'low': return score < 60;
                default: return true;
            }
        });
    }
    
    // Sort
    filtered.sort((a, b) => {
        switch (sortBy) {
            case 'score':
                return b.totalEasScore - a.totalEasScore;
            case 'date':
                return new Date(b.datePublished) - new Date(a.datePublished);
            case 'cveId':
                return a.cveId.localeCompare(b.cveId);
            default:
                return 0;
        }
    });
    
    filteredCveData = filtered;
    renderCveCards(filteredCveData);
    
    // Update section title with count
    const sectionTitle = document.querySelector('.section-title');
    if (sectionTitle) {
        const totalCount = currentCveData.length;
        const filteredCount = filtered.length;
        
        if (filteredCount !== totalCount) {
            sectionTitle.textContent = `Recent CVE Scores (${filteredCount} of ${totalCount})`;
        } else {
            sectionTitle.textContent = `Recent CVE Scores (${totalCount})`;
        }
    }
}

function capitalizeWords(str) {
    return str.replace(/\b\w+/g, word => 
        word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    ).replace(/_/g, ' ');
}

function showError(message) {
    document.getElementById('loading').innerHTML = `
        <div style="text-align: center; padding: 2rem; color: #dc3545;">
            <h3>⚠️ Error</h3>
            <p>${message}</p>
            <p><a href="index.html">← Back to CNA List</a></p>
        </div>
    `;
    document.getElementById('loading').style.display = 'block';
    document.getElementById('cnaHeader').style.display = 'none';
    document.getElementById('cveSection').style.display = 'none';
}
