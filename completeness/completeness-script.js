// CVE Data Completeness Analysis JavaScript

let completenessData = [];
let summaryData = {};
let missingCvesData = [];
let currentSort = 'completeness';
let currentView = 'table';

// Chart instances for proper cleanup
let chartInstances = {
    histogram: null,
    scatter: null,
    topCNAs: null,
    fieldUtilization: null
};

// DOM elements
let tableView, chartView, tableViewBtn, chartViewBtn, cnaSearch, sortSelect, completenessTableBody;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Initialize DOM elements
    tableView = document.getElementById('table-view');
    chartView = document.getElementById('chart-view');
    tableViewBtn = document.getElementById('table-view-btn');
    chartViewBtn = document.getElementById('chart-view-btn');
    cnaSearch = document.getElementById('cna-search');
    sortSelect = document.getElementById('sort-select');
    completenessTableBody = document.getElementById('completeness-table-body');
    
    loadCompletenessData();
    setupEventListeners();
    setupTabs();
});

// Load completeness data
async function loadCompletenessData() {
    try {
        console.log('Loading completeness data...');
        
        // Load CNA completeness data
        const cnaResponse = await fetch('cna_completeness.json');
        if (!cnaResponse.ok) {
            throw new Error(`Failed to load CNA completeness data: ${cnaResponse.status}`);
        }
        completenessData = await cnaResponse.json();
        console.log('Loaded CNA completeness data:', completenessData.length, 'CNAs');
        
        // Load summary data
        const summaryResponse = await fetch('completeness_summary.json');
        if (!summaryResponse.ok) {
            throw new Error(`Failed to load summary data: ${summaryResponse.status}`);
        }
        summaryData = await summaryResponse.json();
        console.log('Loaded summary data');
        
        // Extract missing CVEs data for the quick count
        missingCvesData = summaryData.cves_missing_required_fields || [];
        console.log('Missing CVEs data loaded:', missingCvesData.length, 'CVEs');
        
        // Initialize the interface
        updateOverviewStats();
        renderTable();
        renderFieldAnalysis();
        updateLastUpdated();
        
        console.log('Data loading complete');
        
    } catch (error) {
        console.error('Error loading completeness data:', error);
        showErrorMessage('Failed to load completeness data. Please try again later.');
    }
}

// Update overview statistics
function updateOverviewStats() {
    document.getElementById('overall-completeness').textContent = 
        `${summaryData.global_completeness?.overall_completeness?.toFixed(1) || '0.0'}%`;
    
    document.getElementById('required-completeness').textContent = 
        `${summaryData.global_completeness?.required_fields_completeness?.toFixed(1) || '0.0'}%`;
        
    document.getElementById('optional-completeness').textContent = 
        `${summaryData.global_completeness?.optional_fields_completeness?.toFixed(1) || '0.0'}%`;
        
    document.getElementById('total-cnas').textContent = 
        summaryData.total_cnas || '0';
    
    // Update quick missing count for the link card
    updateQuickMissingCount();
}

// Update quick missing count for the missing fields link
function updateQuickMissingCount() {
    const quickMissingCount = document.getElementById('quick-missing-count');
    if (quickMissingCount) {
        let count = 0;
        if (missingCvesData && missingCvesData.length > 0) {
            count = missingCvesData.length;
        } else if (summaryData.cves_missing_required_fields && summaryData.cves_missing_required_fields.length > 0) {
            // Fallback to direct summary data access
            count = summaryData.cves_missing_required_fields.length;
        }
        
        console.log('Updating quick missing count:', count);
        quickMissingCount.textContent = count.toLocaleString();
    }
}

// Setup event listeners
function setupEventListeners() {
    // View toggle buttons
    if (tableViewBtn) {
        tableViewBtn.addEventListener('click', () => switchView('table'));
    }
    if (chartViewBtn) {
        chartViewBtn.addEventListener('click', () => switchView('chart'));
    }
    
    // Search and sort
    if (cnaSearch) {
        cnaSearch.addEventListener('input', filterAndRenderTable);
    }
    if (sortSelect) {
        sortSelect.addEventListener('change', (e) => {
            currentSort = e.target.value;
            filterAndRenderTable();
        });
    }
}

// Setup tab functionality
function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            
            // Update active tab button
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            
            // Update active tab content
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(`${tabId}-fields`).classList.add('active');
        });
    });
}

// Switch between table and chart views
function switchView(view) {
    currentView = view;
    
    if (!tableView || !chartView || !tableViewBtn || !chartViewBtn) {
        console.error('View elements not found');
        return;
    }
    
    if (view === 'table') {
        tableView.style.display = 'block';
        chartView.style.display = 'none';
        tableViewBtn.classList.add('active');
        chartViewBtn.classList.remove('active');
        
        // Clean up chart instances
        destroyCharts();
    } else {
        tableView.style.display = 'none';
        chartView.style.display = 'block';
        tableViewBtn.classList.remove('active');
        chartViewBtn.classList.add('active');
        
        // Small delay to ensure DOM is ready
        setTimeout(() => {
            renderCharts();
        }, 100);
    }
}

// Filter and render table based on search and sort
function filterAndRenderTable() {
    if (!cnaSearch || !sortSelect) {
        console.error('Search or sort elements not found');
        return;
    }
    
    const searchTerm = cnaSearch.value.toLowerCase();
    let filteredData = completenessData.filter(cna => 
        cna.cna.toLowerCase().includes(searchTerm)
    );
    
    // Sort data
    filteredData.sort((a, b) => {
        switch (currentSort) {
            case 'name':
                return a.cna.localeCompare(b.cna);
            case 'cves':
                return (b.total_cves || 0) - (a.total_cves || 0);
            case 'required':
                return (b.required_fields_completeness || 0) - (a.required_fields_completeness || 0);
            case 'optional':
                return (b.optional_fields_completeness || 0) - (a.optional_fields_completeness || 0);
            case 'completeness':
            default:
                return (b.completeness_score || 0) - (a.completeness_score || 0);
        }
    });
    
    renderTable(filteredData);
}

// Render the completeness table
function renderTable(data = completenessData) {
    if (!completenessTableBody) return;
    completenessTableBody.innerHTML = '';
    let sortedData = [...data];
    // Sort by currentSort
    if (currentSort === 'completeness') {
        sortedData.sort((a, b) => b.completeness_score - a.completeness_score);
    } else if (currentSort === 'name') {
        sortedData.sort((a, b) => a.cna.localeCompare(b.cna));
    } else if (currentSort === 'cves') {
        sortedData.sort((a, b) => b.total_cves - a.total_cves);
    } else if (currentSort === 'required') {
        sortedData.sort((a, b) => b.required_fields_completeness - a.required_fields_completeness);
    } else if (currentSort === 'optional') {
        sortedData.sort((a, b) => b.optional_fields_completeness - a.optional_fields_completeness);
    }
    sortedData.forEach((cna, idx) => {
        const row = document.createElement('tr');
        // Color class for progress bar
        function getBarClass(val) {
            if (val >= 90) return 'excellent';
            if (val >= 70) return 'good';
            if (val >= 50) return 'fair';
            return 'poor';
        }
        // Percentile badge class
        function getPercentileClass(val) {
            if (val >= 75) return 'percentile-top';
            if (val >= 50) return 'percentile-upper';
            if (val >= 25) return 'percentile-lower';
            return 'percentile-bottom';
        }
        row.innerHTML = `
            <td class="rank-cell">${idx + 1}</td>
            <td class="cna-cell">${cna.cna}</td>
            <td class="score-cell">
                <span class="score-value">${cna.completeness_score.toFixed(1)}%</span>
                <div class="progress-bar">
                    <div class="progress-fill ${getBarClass(cna.completeness_score)}" style="width: ${cna.completeness_score}%"></div>
                </div>
            </td>
            <td class="score-cell">
                <span class="score-value">${cna.required_fields_completeness.toFixed(1)}%</span>
                <div class="progress-bar">
                    <div class="progress-fill ${getBarClass(cna.required_fields_completeness)}" style="width: ${cna.required_fields_completeness}%"></div>
                </div>
            </td>
            <td class="score-cell">
                <span class="score-value">${cna.optional_fields_completeness.toFixed(1)}%</span>
                <div class="progress-bar">
                    <div class="progress-fill ${getBarClass(cna.optional_fields_completeness)}" style="width: ${cna.optional_fields_completeness}%"></div>
                </div>
            </td>
            <td>${cna.total_cves?.toLocaleString() || 0}</td>
            <td><span class="percentile-badge ${getPercentileClass(cna.percentile)}">${cna.percentile.toFixed(1)}%</span></td>
        `;
        completenessTableBody.appendChild(row);
    });
}

// Render field analysis sections
function renderFieldAnalysis() {
    if (!summaryData.global_completeness) return;
    
    const requiredFields = summaryData.global_completeness.required_fields || [];
    const optionalFields = summaryData.global_completeness.optional_fields || [];
    
    // Combine required and optional fields for least complete
    const allFields = [...requiredFields.map(f => ({...f, isRequired: true})), ...optionalFields.map(f => ({...f, isRequired: false}))];
    // Sort by completion rate ascending and take the lowest 10
    const leastCompleteFields = allFields.sort((a, b) => a.percentage - b.percentage).slice(0, 10);
    
    const topPresent = summaryData.global_completeness.top_present_optional || [];
    
    // Render required fields
    renderFieldGrid('required-fields-grid', requiredFields, true);
    
    // Render optional fields
    renderFieldGrid('optional-fields-grid', optionalFields, false);
    
    // Render least complete fields (lowest completion rates, required or optional)
    renderFieldGrid('missing-fields-grid', leastCompleteFields, null, true);
    
    // Render most utilized fields
    renderFieldGrid('utilized-fields-grid', topPresent, null, false);
}

// Render field grid
function renderFieldGrid(containerId, fields, isRequired = null, showMissing = false) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    container.innerHTML = '';
    
    // Handle empty arrays with informative messages
    if (fields.length === 0) {
        const emptyMessage = document.createElement('div');
        emptyMessage.className = 'empty-state';
        
        if (containerId === 'missing-fields-grid') {
            emptyMessage.innerHTML = `
                <div class="empty-state-content">
                    <div class="empty-state-icon">✅</div>
                    <h3>Excellent Schema Compliance!</h3>
                    <p>All CVE schema fields have high completion rates across CNAs. 
                       This indicates strong adherence to CVE schema requirements.</p>
                    <p><strong>Average completion rate:</strong> 
                       ${summaryData.global_completeness?.overall_completeness?.toFixed(1) || '0.0'}%</p>
                </div>
            `;
        } else {
            emptyMessage.innerHTML = `
                <div class="empty-state-content">
                    <div class="empty-state-icon">📊</div>
                    <h3>No Data Available</h3>
                    <p>No fields found for this category.</p>
                </div>
            `;
        }
        
        container.appendChild(emptyMessage);
        return;
    }
    
    fields.forEach(field => {
        const fieldCard = document.createElement('div');
        fieldCard.className = 'field-card';
        
        const percentage = field.percentage || 0;
        const progressClass = getScoreClass(percentage);
        
        // Get field description
        const description = getFieldDescription(field.field);
        
        fieldCard.innerHTML = `
            <div class="field-name">
                ${field.field}
                ${isRequired !== null ? 
                    `<span class="required-indicator ${isRequired ? 'required' : 'optional'}">
                        ${isRequired ? 'Required' : 'Optional'}
                    </span>` : 
                    ''
                }
            </div>
            <div class="field-description">${description}</div>
            <div class="field-stats">
                <span class="field-percentage">${percentage.toFixed(1)}%</span>
                <div class="field-progress">
                    <div class="field-progress-fill ${progressClass}" style="width: ${percentage}%"></div>
                </div>
                <span class="field-count">${field.present || 0}/${field.total || 0}</span>
            </div>
        `;
        
        container.appendChild(fieldCard);
    });
}

// Destroy chart instances for cleanup
function destroyCharts() {
    Object.values(chartInstances).forEach(chart => {
        if (chart) {
            chart.destroy();
        }
    });
    chartInstances = {
        histogram: null,
        scatter: null,
        topCNAs: null,
        fieldUtilization: null
    };
}

// Render charts using Chart.js
function renderCharts() {
    if (!completenessData || completenessData.length === 0) {
        console.error('No data available for charts');
        return;
    }
    
    // Chart colors
    const colors = {
        primary: '#3498db',
        success: '#27ae60',
        warning: '#f39c12',
        danger: '#e74c3c',
        secondary: '#95a5a6',
        info: '#2980b9'
    };
    
    try {
        // 1. Completeness Score Distribution (Histogram)
        renderCompletenessHistogram(colors);
        
        // 2. Required vs Optional Fields Scatter Plot
        renderRequiredVsOptionalScatter(colors);
        
        // 3. Top Performing CNAs Bar Chart
        renderTopCNAsBar(colors);
        
        // 4. Field Utilization Overview
        renderFieldUtilizationChart(colors);
        
    } catch (error) {
        console.error('Error rendering charts:', error);
    }
}

// Render completeness score distribution histogram
function renderCompletenessHistogram(colors) {
    const ctx = document.getElementById('completeness-histogram');
    if (!ctx) return;
    
    // Destroy existing chart
    if (chartInstances.histogram) {
        chartInstances.histogram.destroy();
    }
    
    // Create bins for histogram
    const bins = [];
    const binSize = 10;
    for (let i = 0; i < 100; i += binSize) {
        bins.push({ min: i, max: i + binSize, count: 0 });
    }
    
    // Count completeness scores in each bin
    completenessData.forEach(cna => {
        const score = cna.completeness_score || 0;
        const binIndex = Math.min(Math.floor(score / binSize), bins.length - 1);
        bins[binIndex].count++;
    });
    
    chartInstances.histogram = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: bins.map(bin => `${bin.min}-${bin.max}%`),
            datasets: [{
                label: 'Number of CNAs',
                data: bins.map(bin => bin.count),
                backgroundColor: colors.primary,
                borderColor: colors.info,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Distribution of CNA Completeness Scores'
                },
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of CNAs'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Completeness Score Range'
                    }
                }
            }
        }
    });
}

// Render required vs optional fields scatter plot
function renderRequiredVsOptionalScatter(colors) {
    const ctx = document.getElementById('required-vs-optional-scatter');
    if (!ctx) return;
    
    // Destroy existing chart
    if (chartInstances.scatter) {
        chartInstances.scatter.destroy();
    }
    
    const data = completenessData.map(cna => ({
        x: cna.required_fields_completeness || 0,
        y: cna.optional_fields_completeness || 0,
        label: cna.cna,
        cveCount: cna.total_cves || 0
    }));
    
    chartInstances.scatter = new Chart(ctx, {
        type: 'scatter',
        data: {
            datasets: [{
                label: 'CNAs',
                data: data,
                backgroundColor: colors.primary,
                borderColor: colors.info,
                borderWidth: 1,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Required vs Optional Field Completeness'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const point = context.raw;
                            return `${point.label}: Required ${point.x.toFixed(1)}%, Optional ${point.y.toFixed(1)}% (${point.cveCount} CVEs)`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Required Fields Completeness (%)'
                    }
                },
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Optional Fields Completeness (%)'
                    }
                }
            }
        }
    });
}

// Render top performing CNAs bar chart
function renderTopCNAsBar(colors) {
    const ctx = document.getElementById('top-cnas-bar');
    if (!ctx) return;
    
    // Destroy existing chart
    if (chartInstances.topCNAs) {
        chartInstances.topCNAs.destroy();
    }
    
    // Get top 10 CNAs by completeness score
    const topCNAs = [...completenessData]
        .sort((a, b) => (b.completeness_score || 0) - (a.completeness_score || 0))
        .slice(0, 10);
    
    chartInstances.topCNAs = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: topCNAs.map(cna => cna.cna),
            datasets: [{
                label: 'Completeness Score (%)',
                data: topCNAs.map(cna => cna.completeness_score || 0),
                backgroundColor: topCNAs.map((cna, index) => {
                    if (index < 3) return colors.success;
                    if (index < 6) return colors.primary;
                    return colors.secondary;
                }),
                borderColor: colors.info,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                title: {
                    display: true,
                    text: 'Top 10 CNAs by Completeness Score'
                },
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Completeness Score (%)'
                    }
                }
            }
        }
    });
}

// Render field utilization chart
function renderFieldUtilizationChart(colors) {
    const ctx = document.getElementById('field-utilization-heatmap');
    if (!ctx) return;
    
    // Destroy existing chart
    if (chartInstances.fieldUtilization) {
        chartInstances.fieldUtilization.destroy();
    }
    
    // Get field completion data from summary
    if (!summaryData.global_completeness) {
        console.warn('No global completeness data available for field utilization chart');
        return;
    }
    
    const requiredFields = summaryData.global_completeness.required_fields || [];
    const optionalFields = summaryData.global_completeness.optional_fields || [];
    
    // Combine and get top/bottom fields
    const allFields = [
        ...requiredFields.map(f => ({...f, type: 'Required'})),
        ...optionalFields.map(f => ({...f, type: 'Optional'}))
    ].sort((a, b) => (b.percentage || 0) - (a.percentage || 0));
    
    const topFields = allFields.slice(0, 10);
    
    chartInstances.fieldUtilization = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: topFields.map(f => f.field.replace('containers.cna.', '').replace('cveMetadata.', '')),
            datasets: [{
                label: 'Completion Rate (%)',
                data: topFields.map(f => f.percentage || 0),
                backgroundColor: topFields.map(f => {
                    const pct = f.percentage || 0;
                    if (pct >= 80) return colors.success;
                    if (pct >= 60) return colors.primary;
                    if (pct >= 40) return colors.warning;
                    return colors.danger;
                }),
                borderColor: colors.info,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Field Completion Rates'
                },
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        afterLabel: function(context) {
                            const field = topFields[context.dataIndex];
                            return `Type: ${field.type}\nPresent: ${field.present}/${field.total}`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Completion Rate (%)'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Schema Fields'
                    },
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            }
        }
    });
}

// Show CNA details modal
function showCNADetails(cnaName) {
    const cna = completenessData.find(c => c.cna === cnaName);
    if (!cna) return;
    
    // Create modal HTML
    const modalHtml = `
        <div id="cna-modal" class="modal" style="display: block;">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>${escapeHtml(cna.cna)} - Completeness Details</h2>
                    <span class="close" onclick="closeCNAModal()">&times;</span>
                </div>
                <div class="modal-body">
                    <div class="metric-grid">
                        <div class="metric-item">
                            <div class="metric-value">${cna.completeness_score}%</div>
                            <div class="metric-label">Overall Score</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.required_fields_completeness}%</div>
                            <div class="metric-label">Required Fields</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.optional_fields_completeness}%</div>
                            <div class="metric-label">Optional Fields</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.total_cves}</div>
                            <div class="metric-label">Total CVEs</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">${cna.percentile}%</div>
                            <div class="metric-label">Percentile Rank</div>
                        </div>
                    </div>
                    
                    <h3>Key Metrics Breakdown</h3>
                    <div class="field-grid">
                        ${Object.entries(cna.key_metrics || {}).map(([key, value]) => `
                            <div class="field-card">
                                <div class="field-name">${formatMetricName(key)}</div>
                                <div class="field-stats">
                                    <span class="field-percentage">${value.toFixed(1)}%</span>
                                    <div class="field-progress">
                                        <div class="field-progress-fill ${getScoreClass(value)}" 
                                             style="width: ${value}%"></div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    
    // Close modal when clicking outside
    document.getElementById('cna-modal').addEventListener('click', (e) => {
        if (e.target.id === 'cna-modal') {
            closeCNAModal();
        }
    });
}

// Close CNA details modal
function closeCNAModal() {
    const modal = document.getElementById('cna-modal');
    if (modal) {
        modal.remove();
    }
}

// Utility function to escape HTML for safety
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Get percentile class for styling
function getPercentileClass(percentile) {
    if (percentile >= 90) return 'percentile-90';
    if (percentile >= 75) return 'percentile-75';
    if (percentile >= 50) return 'percentile-50';
    return 'percentile-0';
}

// Get score class for progress bar coloring
function getScoreClass(score) {
    if (score >= 80) return 'score-excellent';
    if (score >= 60) return 'score-good';
    if (score >= 40) return 'score-fair';
    return 'score-poor';
}

// Format metric name for display
function formatMetricName(name) {
    return name
        .replace(/_/g, ' ')
        .replace(/\b\w/g, char => char.toUpperCase());
}

// Get field description based on field name
function getFieldDescription(fieldName) {
    const descriptions = {
        'cna': 'The CNA (CVE Numbering Authority) responsible for this CVE.',
        'cve_id': 'The unique identifier for the CVE.',
        'description': 'A brief summary of the CVE.',
        'published_date': 'The date the CVE was published.',
        'last_modified_date': 'The date the CVE was last modified.',
        'cvss_score': 'The CVSS (Common Vulnerability Scoring System) score of the CVE.',
        'cvss_vector': 'The CVSS vector string representing the attack vector, complexity, etc.',
        'exploitability_score': 'The score indicating how exploitable the CVE is.',
        'impact_score': 'The score indicating the potential impact of the CVE.',
        'severity': 'The severity level of the CVE (e.g., low, medium, high).',
        'access_vector': 'The access vector required to exploit the CVE.',
        'access_complexity': 'The complexity level of the access required to exploit the CVE.',
        'authentication': 'The authentication required to exploit the CVE.',
        'confidentiality_impact': 'The impact on confidentiality if the CVE is exploited.',
        'integrity_impact': 'The impact on integrity if the CVE is exploited.',
        'availability_impact': 'The impact on availability if the CVE is exploited.',
        'base_score': 'The base score of the CVE, combining exploitability and impact.',
        'temporal_score': 'The temporal score of the CVE, considering factors like exploit availability.',
        'environmental_score': 'The environmental score of the CVE, considering the specific environment.',
        'reporter': 'The person or entity who reported the CVE.',
        'reference': 'References for further information about the CVE.',
        'solution': 'Proposed solutions or mitigations for the CVE.',
        'comments': 'Additional comments or notes about the CVE.'
    };
    
    return descriptions[fieldName] || 'No description available.';
}

// Update the last updated timestamp in the footer
function updateLastUpdated() {
    const lastUpdatedElement = document.getElementById('last-updated');
    if (lastUpdatedElement && summaryData.last_updated) {
        const date = new Date(summaryData.last_updated);
        lastUpdatedElement.textContent = date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    }
}

// Show an error message to the user
function showErrorMessage(message) {
    const errorBanner = document.createElement('div');
    errorBanner.className = 'error-banner';
    errorBanner.textContent = message;
    document.body.prepend(errorBanner);
}

//# sourceMappingURL=main.js.map
