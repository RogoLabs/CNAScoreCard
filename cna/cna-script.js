// CNA-specific page functionality
let cnaData = null;
let filteredCves = [];

document.addEventListener('DOMContentLoaded', function() {
    loadCnaData();
    setupEventListeners();
});

function setupEventListeners() {
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    
    if (searchInput) {
        searchInput.addEventListener('input', filterAndDisplayCves);
    }
    
    if (sortSelect) {
        sortSelect.addEventListener('change', filterAndDisplayCves);
    }
}

async function loadCnaData() {
    try {
        const response = await fetch(`data/${SAFE_FILENAME}.json`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        cnaData = await response.json();
        displayCnaInfo();
        filteredCves = [...cnaData.recent_cves];
        filterAndDisplayCves();
        
    } catch (error) {
        console.error('Error loading CNA data:', error);
        document.getElementById('loading').innerHTML = 
            '<div class="error">Error loading CNA data. Please try again later.</div>';
    }
}

function displayCnaInfo() {
    if (!cnaData) return;
    
    const cnaInfo = cnaData.cna_info;
    const totalCves = cnaData.total_cves;
    
    // Update title
    document.getElementById('cnaTitle').textContent = cnaInfo.cna;
    
    // Update stats
    const statsContainer = document.getElementById('cnaStats');
    statsContainer.innerHTML = `
        <div class="stat-card">
            <span class="stat-value">${totalCves}</span>
            <span class="stat-label">Total CVEs (6 months)</span>
        </div>
        <div class="stat-card">
            <span class="stat-value">${cnaInfo.average_eas_score || 0}</span>
            <span class="stat-label">Average EAS Score</span>
        </div>
        <div class="stat-card">
            <span class="stat-value">${cnaInfo.percentile || 0}%</span>
            <span class="stat-label">Percentile Rank</span>
        </div>
        <div class="stat-card">
            <span class="stat-value">${cnaData.recent_cves.length}</span>
            <span class="stat-label">Recent CVEs Shown</span>
        </div>
    `;
}

function filterAndDisplayCves() {
    if (!cnaData) return;
    
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const sortBy = document.getElementById('sortSelect').value;
    
    // Filter CVEs
    filteredCves = cnaData.recent_cves.filter(cve => {
        if (!searchTerm) return true;
        
        return cve.cveId.toLowerCase().includes(searchTerm) ||
               (cve.assigningCna && cve.assigningCna.toLowerCase().includes(searchTerm));
    });
    
    // Sort CVEs
    filteredCves.sort((a, b) => {
        switch (sortBy) {
            case 'score':
                return (b.totalEasScore || 0) - (a.totalEasScore || 0);
            case 'cveId':
                return a.cveId.localeCompare(b.cveId);
            case 'date':
                return new Date(b.datePublished || 0) - new Date(a.datePublished || 0);
            default:
                return 0;
        }
    });
    
    displayCves();
}

function displayCves() {
    const container = document.getElementById('cveCards');
    const loadingElement = document.getElementById('loading');
    
    if (loadingElement) {
        loadingElement.style.display = 'none';
    }
    
    if (filteredCves.length === 0) {
        container.innerHTML = '<div class="no-results">No CVEs found matching your criteria.</div>';
        return;
    }
    
    container.innerHTML = filteredCves.map(cve => createCveCard(cve)).join('');
}

function createCveCard(cve) {
    const score = cve.totalEasScore || 0;
    const scoreClass = getScoreClass(score);
    const breakdown = cve.scoreBreakdown || {};
    
    const datePublished = cve.datePublished ? 
        new Date(cve.datePublished).toLocaleDateString() : 'Unknown';
    
    return `
        <div class="cve-card">
            <div class="cve-id">${cve.cveId}</div>
            <div class="cve-score ${scoreClass}">${score}</div>
            <div class="cve-date">Published: ${datePublished}</div>
            
            <div class="score-breakdown">
                <div class="breakdown-item">
                    <span class="breakdown-label">Foundational:</span>
                    <span class="breakdown-value">${breakdown.foundationalCompleteness || 0}</span>
                </div>
                <div class="breakdown-item">
                    <span class="breakdown-label">Root Cause:</span>
                    <span class="breakdown-value">${breakdown.rootCauseAnalysis || 0}</span>
                </div>
                <div class="breakdown-item">
                    <span class="breakdown-label">Severity:</span>
                    <span class="breakdown-value">${breakdown.severityAndImpactContext || 0}</span>
                </div>
                <div class="breakdown-item">
                    <span class="breakdown-label">Actionable:</span>
                    <span class="breakdown-value">${breakdown.actionableIntelligence || 0}</span>
                </div>
                <div class="breakdown-item">
                    <span class="breakdown-label">Format:</span>
                    <span class="breakdown-value">${breakdown.dataFormatAndPrecision || 0}</span>
                </div>
            </div>
        </div>
    `;
}

function getScoreClass(score) {
    if (score >= 80) return 'score-excellent';
    if (score >= 60) return 'score-good';
    if (score >= 40) return 'score-fair';
    if (score >= 20) return 'score-poor';
    return 'score-very-poor';
}