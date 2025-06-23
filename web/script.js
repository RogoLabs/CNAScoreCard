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
    
    const cardsHTML = cnas.map(cna => createCNACard(cna)).join('');
    container.innerHTML = cardsHTML;
}

// Create individual CNA card
function createCNACard(cna) {
    const scoreClass = getScoreClass(cna.score);
    const lastUpdateDate = cna.lastUpdate ? new Date(cna.lastUpdate).toLocaleDateString() : 'Unknown';
    
    return `
        <div class="cna-card ${scoreClass}">
            <div class="cna-header">
                <h3 class="cna-name">${escapeHtml(cna.name)}</h3>
                <div class="cna-score">${cna.score.toFixed(1)}</div>
            </div>
            <div class="cna-details">
                <div class="detail-item">
                    <span class="label">CVE Count:</span>
                    <span class="value">${cna.cveCount}</span>
                </div>
                <div class="detail-item">
                    <span class="label">Avg Response Time:</span>
                    <span class="value">${cna.avgResponseTime} days</span>
                </div>
                <div class="detail-item">
                    <span class="label">Quality Score:</span>
                    <span class="value">${cna.qualityScore.toFixed(1)}</span>
                </div>
                <div class="detail-item">
                    <span class="label">Last Update:</span>
                    <span class="value">${lastUpdateDate}</span>
                </div>
                <div class="detail-item">
                    <span class="label">CVEs with CVSS Score:</span>
                    <span class="value">${cna.percentage_with_cvss}%</span>
                </div>
                <div class="detail-item">
                    <span class="label">CVEs with CWE ID:</span>
                    <span class="value">${cna.percentage_with_cwe}%</span>
                </div>
            </div>
        </div>
    `;
}

// Get CSS class based on score
function getScoreClass(score) {
    if (score >= 8) return 'score-excellent';
    if (score >= 6) return 'score-good';
    if (score >= 4) return 'score-fair';
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
    filteredCNAs = allCNAs.filter(cna => 
        cna.name.toLowerCase().includes(searchTerm)
    );
    displayCNAs(filteredCNAs);
}

// Handle sorting
function handleSort(event) {
    const sortBy = event.target.value;
    
    filteredCNAs.sort((a, b) => {
        switch (sortBy) {
            case 'name':
                return a.name.localeCompare(b.name);
            case 'cveCount':
                return b.cveCount - a.cveCount;
            case 'score':
            default:
                return b.score - a.score;
        }
    });
    
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