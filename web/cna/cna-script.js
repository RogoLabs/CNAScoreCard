let allCNAs = [];

// Fetch CNA data and render cards
async function loadCNAData() {
    try {
        // Fetch both CNA scores and CNAs list data
        const [scoresResponse, cnasListResponse] = await Promise.all([
            fetch('../data/cna-scores.json'),
            fetch('https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json')
        ]);
        
        const scoresData = await scoresResponse.json();
        const cnasListData = await cnasListResponse.json();
        
        // Create a map of CNA details for quick lookup
        const cnaDetailsMap = new Map();
        
        // Handle different possible structures in the CNAs list data
        const cnasArray = cnasListData.CNAs || cnasListData.cnas || cnasListData.data || [];
        cnasArray.forEach(cna => {
            // Try different possible field names for shortname
            const shortname = cna.shortname || cna.short_name || cna.name;
            if (shortname) {
                cnaDetailsMap.set(shortname, cna);
                // Also map by lowercase for better matching
                cnaDetailsMap.set(shortname.toLowerCase(), cna);
            }
        });
        
        // Merge the data
        allCNAs = (scoresData.cnas || []).map(cna => {
            const details = cnaDetailsMap.get(cna.name) || cnaDetailsMap.get(cna.name.toLowerCase());
            return {
                ...cna,
                details: details || null
            };
        });
        
        renderCNAs(allCNAs);
        
        document.getElementById('loading').style.display = 'none';
    } catch (error) {
        console.error('Error loading CNA data:', error);
        document.getElementById('loading').innerHTML = 'Error loading CNA data';
    }
}

// Render CNA cards
function renderCNAs(cnas) {
    const container = document.getElementById('cnaList');
    container.innerHTML = '';
    
    cnas.forEach(cna => {
        const card = createCNACard(cna);
        container.appendChild(card);
    });
}

// Create individual CNA card
function createCNACard(cna) {
    const card = document.createElement('div');
    card.className = 'cna-card';
    
    const details = cna.details;
    const scoreClass = getScoreClass(cna.overallScore);
    
    card.innerHTML = `
        <div class="cna-header">
            <h3 class="cna-name">${cna.name}</h3>
            <div class="cna-score ${scoreClass}">${cna.overallScore?.toFixed(1) || 'N/A'}</div>
        </div>
        
        ${details?.name ? `<div class="cna-long-name">${details.name}</div>` : ''}
        
        <div class="cna-stats">
            <div class="stat">
                <span class="stat-label">CVEs:</span>
                <span class="stat-value">${cna.cveCount || 0}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Recent CVEs:</span>
                <span class="stat-value">${cna.recentCveCount || 0}</span>
            </div>
        </div>
        
        ${details?.scope ? `
            <div class="cna-scope">
                <span class="scope-label">Scope:</span>
                <span class="scope-value">${details.scope}</span>
            </div>
        ` : ''}
        
        ${details?.advisory_links && details.advisory_links.length > 0 ? `
            <div class="cna-advisories">
                <span class="advisories-label">Advisory Links:</span>
                <div class="advisory-links">
                    ${details.advisory_links.map(link => `
                        <a href="${link.url}" target="_blank" class="advisory-link" title="${link.description || link.url}">
                            ${link.name || new URL(link.url).hostname}
                        </a>
                    `).join('')}
                </div>
            </div>
        ` : ''}
        
        <div class="cna-scores">
            <div class="score-item">
                <span>CVSS Completeness:</span>
                <span class="${getScoreClass(cna.cvssCompletenessScore)}">${cna.cvssCompletenessScore?.toFixed(1) || 'N/A'}</span>
            </div>
            <div class="score-item">
                <span>Description Quality:</span>
                <span class="${getScoreClass(cna.descriptionQualityScore)}">${cna.descriptionQualityScore?.toFixed(1) || 'N/A'}</span>
            </div>
            <div class="score-item">
                <span>Reference Quality:</span>
                <span class="${getScoreClass(cna.referenceQualityScore)}">${cna.referenceQualityScore?.toFixed(1) || 'N/A'}</span>
            </div>
        </div>
        
        <div class="cna-actions">
            <a href="../cna-detail.html?cna=${encodeURIComponent(cna.name)}" class="view-details-btn">View Details</a>
        </div>
    `;
    
    return card;
}

// Get CSS class based on score
function getScoreClass(score) {
    if (!score) return 'score-na';
    if (score >= 8) return 'score-excellent';
    if (score >= 6) return 'score-good';
    if (score >= 4) return 'score-average';
    return 'score-poor';
}

// Search and filter functionality
function setupFilters() {
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    
    searchInput.addEventListener('input', filterAndSort);
    sortSelect.addEventListener('change', filterAndSort);
}

function filterAndSort() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const sortBy = document.getElementById('sortSelect').value;
    
    let filteredCNAs = allCNAs.filter(cna => {
        const searchableText = [
            cna.name,
            cna.details?.name,
            cna.details?.scope
        ].filter(Boolean).join(' ').toLowerCase();
        
        return searchableText.includes(searchTerm);
    });
    
    filteredCNAs.sort((a, b) => {
        switch (sortBy) {
            case 'score':
                return (b.overallScore || 0) - (a.overallScore || 0);
            case 'cveCount':
                return (b.cveCount || 0) - (a.cveCount || 0);
            case 'name':
            default:
                return a.name.localeCompare(b.name);
        }
    });
    
    renderCNAs(filteredCNAs);
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    loadCNAData();
    setupFilters();
});