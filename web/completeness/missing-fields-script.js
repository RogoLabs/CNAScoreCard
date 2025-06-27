// CVEs Missing Required Fields JavaScript

let summaryData = {};
let missingCvesData = [];
let commonMissingFields = [];
let cnaPerformanceData = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    loadMissingFieldsData();
    setupEventListeners();
});

// Load missing fields data
async function loadMissingFieldsData() {
    try {
        // Load the summary data first
        const summaryResponse = await fetch('completeness_summary.json');
        if (!summaryResponse.ok) {
            throw new Error(`HTTP error! status: ${summaryResponse.status}`);
        }
        summaryData = await summaryResponse.json();
        
        // Load CNA completeness data to get missing CVEs
        const completenessResponse = await fetch('cna_completeness.json');
        if (!completenessResponse.ok) {
            throw new Error(`HTTP error! status: ${completenessResponse.status}`);
        }
        const completenessData = await completenessResponse.json();
        
        // Extract missing CVEs data from completeness data
        extractMissingCvesData(completenessData);
        
        // Update the UI with loaded data
        updateOverviewStats();
        updateMissingCvesSection();
        updateCommonMissingFields();
        updateCNAPerformance(completenessData);
        updateLastUpdated();
        
    } catch (error) {
        console.error('Error loading data:', error);
        showErrorMessage('Failed to load missing fields data. Please try again later.');
    }
}

// Extract missing CVEs data from completeness data
function extractMissingCvesData(completenessData) {
    missingCvesData = [];
    const fieldCounts = {};
    const cnaRequiredPerformance = {};
    
    // Process each CNA's data
    completenessData.forEach(cna => {
        // Track CNA performance on required fields
        cnaRequiredPerformance[cna.cna] = {
            cna: cna.cna,
            requiredFieldsCompleteness: cna.required_fields_completeness || 0,
            totalCves: cna.total_cves || 0,
            missingFieldsCves: 0
        };
        
        // Extract CVEs with missing required fields
        if (cna.cves_missing_required_fields) {
            cna.cves_missing_required_fields.forEach(cve => {
                missingCvesData.push({
                    cveId: cve.cve_id,
                    assigningCna: cna.cna,
                    datePublished: cve.date_published,
                    missingRequiredFields: cve.missing_required_fields || []
                });
                
                cnaRequiredPerformance[cna.cna].missingFieldsCves++;
                
                // Count frequency of missing fields
                cve.missing_required_fields?.forEach(field => {
                    fieldCounts[field] = (fieldCounts[field] || 0) + 1;
                });
            });
        }
    });
    
    // Convert field counts to sorted array
    commonMissingFields = Object.entries(fieldCounts)
        .map(([field, count]) => ({
            field: field,
            count: count,
            percentage: ((count / missingCvesData.length) * 100).toFixed(1)
        }))
        .sort((a, b) => b.count - a.count);
    
    // Convert CNA performance to sorted array
    cnaPerformanceData = Object.values(cnaRequiredPerformance)
        .sort((a, b) => b.requiredFieldsCompleteness - a.requiredFieldsCompleteness);
}

// Update overview statistics
function updateOverviewStats() {
    const missingCount = missingCvesData.length;
    const totalCves = summaryData.total_cves_analyzed || 1;
    const percentage = ((missingCount / totalCves) * 100).toFixed(2);
    const affectedCnas = new Set(missingCvesData.map(cve => cve.assigningCna)).size;
    
    document.getElementById('missing-cves-count').textContent = missingCount.toLocaleString();
    document.getElementById('missing-percentage').textContent = `${percentage}%`;
    document.getElementById('affected-cnas-count').textContent = affectedCnas;
    document.getElementById('total-cves-analyzed').textContent = totalCves.toLocaleString();
}

// Setup event listeners
function setupEventListeners() {
    const searchInput = document.getElementById('missing-cves-search');
    const sortSelect = document.getElementById('missing-cves-sort');
    
    if (searchInput) {
        searchInput.addEventListener('input', filterAndRenderMissingCves);
    }
    
    if (sortSelect) {
        sortSelect.addEventListener('change', filterAndRenderMissingCves);
    }
}

// Update missing CVEs section
function updateMissingCvesSection() {
    renderMissingCvesTable();
}

// Filter and render missing CVEs table
function filterAndRenderMissingCves() {
    renderMissingCvesTable();
}

// Render missing CVEs table
function renderMissingCvesTable() {
    const container = document.getElementById('missing-cves-table');
    if (!container) return;
    
    const searchTerm = document.getElementById('missing-cves-search')?.value.toLowerCase() || '';
    const sortBy = document.getElementById('missing-cves-sort')?.value || 'date';
    
    // Filter CVEs
    let filteredCves = missingCvesData.filter(cve => 
        cve.cveId.toLowerCase().includes(searchTerm) ||
        cve.assigningCna.toLowerCase().includes(searchTerm) ||
        cve.missingRequiredFields.some(field => field.toLowerCase().includes(searchTerm))
    );
    
    // Sort CVEs
    filteredCves.sort((a, b) => {
        switch (sortBy) {
            case 'cve':
                return a.cveId.localeCompare(b.cveId);
            case 'cna':
                return a.assigningCna.localeCompare(b.assigningCna);
            case 'fields':
                return b.missingRequiredFields.length - a.missingRequiredFields.length;
            case 'date':
            default:
                const dateA = new Date(a.datePublished || '1970-01-01');
                const dateB = new Date(b.datePublished || '1970-01-01');
                return dateB - dateA;
        }
    });
    
    // Update filtered count
    const filteredCountEl = document.getElementById('filtered-count');
    const totalMissingCountEl = document.getElementById('total-missing-count');
    if (filteredCountEl) filteredCountEl.textContent = filteredCves.length.toLocaleString();
    if (totalMissingCountEl) totalMissingCountEl.textContent = missingCvesData.length.toLocaleString();
    
    if (filteredCves.length === 0) {
        container.innerHTML = `
            <div class="empty-missing-fields">
                <div class="icon">🎉</div>
                <h3>No CVEs Found</h3>
                <p>No CVEs match your search criteria${searchTerm ? ` for "${searchTerm}"` : ''}.</p>
                ${searchTerm ? '<p>Try adjusting your search terms or clearing the search.</p>' : ''}
            </div>
        `;
        return;
    }
    
    // Create table
    const tableHTML = `
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>CNA</th>
                    <th>Date Published</th>
                    <th>Missing Required Fields</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                ${filteredCves.map(cve => `
                    <tr>
                        <td>
                            <a href="https://cve.org/CVERecord?id=${cve.cveId}" 
                               target="_blank" 
                               rel="noopener noreferrer" 
                               class="cve-link">
                                ${cve.cveId}
                            </a>
                        </td>
                        <td>
                            <span class="cna-badge">${escapeHtml(cve.assigningCna)}</span>
                        </td>
                        <td class="date-cell">
                            ${cve.datePublished ? new Date(cve.datePublished).toLocaleDateString() : 'Unknown'}
                        </td>
                        <td class="missing-fields-cell">
                            ${cve.missingRequiredFields.map(field => 
                                `<span class="missing-fields-badge">${escapeHtml(formatFieldName(field))}</span>`
                            ).join('')}
                        </td>
                        <td class="count-cell">
                            <span class="field-count">${cve.missingRequiredFields.length}</span>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
}

// Update common missing fields section
function updateCommonMissingFields() {
    const container = document.getElementById('common-missing-fields');
    if (!container) return;
    
    if (commonMissingFields.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-content">
                    <div class="empty-state-icon">🎉</div>
                    <h3>No Common Missing Fields</h3>
                    <p>No missing required fields data available.</p>
                </div>
            </div>
        `;
        return;
    }
    
    // Show top 20 most common missing fields
    const topFields = commonMissingFields.slice(0, 20);
    
    container.innerHTML = topFields.map(fieldData => `
        <div class="field-card">
            <div class="field-name">${escapeHtml(formatFieldName(fieldData.field))}</div>
            <div class="field-description">Missing in ${fieldData.count.toLocaleString()} CVEs</div>
            <div class="field-stats">
                <span class="field-percentage">${fieldData.percentage}%</span>
                <div class="field-progress">
                    <div class="field-progress-fill poor" style="width: ${Math.min(fieldData.percentage, 100)}%"></div>
                </div>
            </div>
        </div>
    `).join('');
}

// Update CNA performance section
function updateCNAPerformance(completenessData) {
    const container = document.getElementById('cna-required-performance');
    if (!container) return;
    
    if (cnaPerformanceData.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-content">
                    <div class="empty-state-icon">📊</div>
                    <h3>No Performance Data</h3>
                    <p>No CNA performance data available.</p>
                </div>
            </div>
        `;
        return;
    }
    
    const tableHTML = `
        <table class="performance-table">
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>CNA</th>
                    <th>Required Fields Completeness</th>
                    <th>Total CVEs</th>
                    <th>CVEs with Missing Fields</th>
                    <th>Compliance Rate</th>
                </tr>
            </thead>
            <tbody>
                ${cnaPerformanceData.map((cna, index) => {
                    const complianceRate = cna.totalCves > 0 ? 
                        (((cna.totalCves - cna.missingFieldsCves) / cna.totalCves) * 100).toFixed(1) : '0.0';
                    
                    return `
                        <tr>
                            <td class="rank-cell">${index + 1}</td>
                            <td class="cna-cell">
                                <span class="cna-name">${escapeHtml(cna.cna)}</span>
                            </td>
                            <td class="completeness-cell">
                                <div class="score-container">
                                    <span class="score ${getScoreClass(cna.requiredFieldsCompleteness)}">${cna.requiredFieldsCompleteness.toFixed(1)}%</span>
                                    <div class="score-bar">
                                        <div class="score-fill ${getScoreClass(cna.requiredFieldsCompleteness)}" 
                                             style="width: ${cna.requiredFieldsCompleteness}%"></div>
                                    </div>
                                </div>
                            </td>
                            <td class="count-cell">${cna.totalCves.toLocaleString()}</td>
                            <td class="missing-count-cell">
                                <span class="missing-count ${cna.missingFieldsCves > 0 ? 'has-missing' : 'no-missing'}">
                                    ${cna.missingFieldsCves.toLocaleString()}
                                </span>
                            </td>
                            <td class="compliance-cell">
                                <span class="compliance-rate ${getScoreClass(parseFloat(complianceRate))}">${complianceRate}%</span>
                            </td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
}

// Format field names for display
function formatFieldName(fieldName) {
    return fieldName
        .replace(/^containers\.cna\./, '')
        .replace(/^affected\./, 'affected: ')
        .replace(/^descriptions\./, 'descriptions: ')
        .replace(/([A-Z])/g, ' $1')
        .replace(/^\w/, c => c.toUpperCase());
}

// Helper functions
function getScoreClass(score) {
    if (score >= 90) return 'excellent';
    if (score >= 75) return 'good';
    if (score >= 50) return 'fair';
    return 'poor';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showErrorMessage(message) {
    const container = document.querySelector('.container');
    if (container) {
        container.innerHTML = `
            <div class="error-message">
                <h2>⚠️ Error Loading Data</h2>
                <p>${message}</p>
                <button onclick="location.reload()" class="retry-btn">🔄 Retry</button>
            </div>
        `;
    }
}

function updateLastUpdated() {
    const lastUpdatedEl = document.getElementById('last-updated');
    if (lastUpdatedEl) {
        lastUpdatedEl.textContent = new Date().toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !e.target.matches('input, textarea')) {
        e.preventDefault();
        document.getElementById('missing-cves-search')?.focus();
    }
});
