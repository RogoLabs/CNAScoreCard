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
        updateLastUpdated();
        console.log('Data loading complete');
    } catch (error) {
        console.error('Error loading completeness data:', error);
        showErrorMessage('Failed to load completeness data. Please try again later.');
    }
}

// Add a simple error message function if not present
function showErrorMessage(msg) {
    alert(msg);
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
        row.innerHTML = `
            <td>${idx + 1}</td>
            <td>${cna.cna}</td>
            <td>${(cna.completeness_score || 0).toFixed(1)}%</td>
            <td>${(cna.required_fields_completeness || 0).toFixed(1)}%</td>
            <td>${(cna.optional_fields_completeness || 0).toFixed(1)}%</td>
            <td>${cna.total_cves || 0}</td>
            <td>${(cna.percentile || 0).toFixed(1)}%</td>
        `;
        completenessTableBody.appendChild(row);
    });
}

// Update last updated timestamp
function updateLastUpdated() {
    const el = document.getElementById('last-updated');
    if (el && summaryData.generated_at) {
        const d = new Date(summaryData.generated_at);
        el.textContent = d.toLocaleString();
    } else if (el) {
        el.textContent = new Date().toLocaleString();
    }
}
