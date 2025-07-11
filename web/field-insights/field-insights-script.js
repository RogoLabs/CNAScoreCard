// field-insights-script.js
// Script for CVE Field Insights page

let summaryData = {};

// DOM elements
let fieldUtilizationCtx, mostUtilizedFields, leastUtilizedFields;
let requiredFieldsTableBody, optionalFieldsTableBody;
let requiredFieldsSearch, optionalFieldsSearch;

// --- Field Utilization Bar Chart Controls ---
let fieldFilter = 'all';
let fieldSort = 'util-desc';
let fieldTableSort = { key: 'util', dir: 'desc' };

// --- CNA Utilization Table Sorting ---
let cnaUtilSort = { key: 'cna_percent', dir: 'asc' };

// On DOMContentLoaded, initialize
window.addEventListener('DOMContentLoaded', () => {
    fieldUtilizationCtx = document.getElementById('field-utilization-heatmap');
    mostUtilizedFields = document.getElementById('most-utilized-fields');
    leastUtilizedFields = document.getElementById('least-utilized-fields');
    requiredFieldsTableBody = document.getElementById('required-fields-table-body');
    optionalFieldsTableBody = document.getElementById('optional-fields-table-body');
    requiredFieldsSearch = document.getElementById('required-fields-search');
    optionalFieldsSearch = document.getElementById('optional-fields-search');
    loadSummaryData();
    setupSearchFilters();
    // Add event listeners for filter and sort controls
    const filterGroup = document.getElementById('field-filter-group');
    if (filterGroup) {
        filterGroup.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', e => {
                filterGroup.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                fieldFilter = btn.getAttribute('data-filter');
                renderFieldUtilizationHeatmap();
            });
        });
    }
    const sortSelect = document.getElementById('field-sort-select');
    if (sortSelect) {
        sortSelect.addEventListener('change', e => {
            fieldSort = sortSelect.value;
            renderFieldUtilizationHeatmap();
        });
    }
    // Add table header sort listeners
    const sortRank = document.getElementById('sort-rank');
    const sortName = document.getElementById('sort-name');
    const sortUtil = document.getElementById('sort-util');
    if (sortRank) sortRank.addEventListener('click', () => setFieldTableSort('rank'));
    if (sortName) sortName.addEventListener('click', () => setFieldTableSort('name'));
    if (sortUtil) sortUtil.addEventListener('click', () => setFieldTableSort('util'));
    setupCnaUtilTableSort();
});

async function loadSummaryData() {
    try {
        const resp = await fetch('../completeness/completeness_summary.json');
        summaryData = await resp.json();
        renderFieldUtilizationHeatmap();
        renderFieldLeaderboards();
        renderRequiredFieldsTable();
        renderOptionalFieldsTable();
        renderOverallUtilizationTable(); // NEW
        await renderCnaUtilizationTable(); // NEW (async)
        updateLastUpdated();
    } catch (e) {
        showError('Failed to load field insights data.');
    }
}

// List of 10 automatically-populated CVE program fields to exclude
const EXCLUDED_FIELDS = new Set([
    "cveMetadata.datePublished",
    "cveMetadata.dateUpdated",
    "cveMetadata.dateReserved",
    "cveMetadata.state",
    "cveMetadata.assignerOrgId",
    "cveMetadata.serial",
    "cveMetadata.assignerShortName",
    "cveMetadata.providerMetadata.orgId",
    "cveMetadata.providerMetadata.shortName",
    "cveMetadata.providerMetadata.dateUpdated"
]);

function filterExcludedFields(fields) {
    return fields.filter(f => !EXCLUDED_FIELDS.has(f.field));
}

function renderFieldUtilizationHeatmap() {
    if (!fieldUtilizationCtx || !summaryData.global_completeness) return;
    let required = filterExcludedFields(summaryData.global_completeness.required_fields || []);
    let optional = filterExcludedFields(summaryData.global_completeness.optional_fields || []);
    let allFields = [];
    if (fieldFilter === 'required') allFields = required;
    else if (fieldFilter === 'optional') allFields = optional;
    else allFields = [...required, ...optional];
    // Sort
    if (fieldSort === 'util-desc') allFields.sort((a, b) => (b.percentage || 0) - (a.percentage || 0));
    else if (fieldSort === 'util-asc') allFields.sort((a, b) => (a.percentage || 0) - (b.percentage || 0));
    else if (fieldSort === 'az') allFields.sort((a, b) => a.field.localeCompare(b.field));
    else if (fieldSort === 'za') allFields.sort((a, b) => b.field.localeCompare(a.field));
    // Truncate labels for y-axis, show full in tooltip
    const labels = allFields.map((f, i) => {
        let shortLabel = formatFieldName(f.field);
        if (shortLabel.length > 18) shortLabel = shortLabel.slice(0, 16) + '…';
        return shortLabel;
    });
    const data = allFields.map(f => f.percentage);
    const bgColors = allFields.map(f => f.required ? '#2980b9' : '#b0b4ba');
    if (window.fieldUtilizationChart) window.fieldUtilizationChart.destroy();
    window.fieldUtilizationChart = new Chart(fieldUtilizationCtx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Utilization %',
                data: data,
                backgroundColor: bgColors,
                borderRadius: 8,
                borderSkipped: false,
                maxBarThickness: 24
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            plugins: {
                legend: { display: false },
                title: { display: false },
                tooltip: {
                    callbacks: {
                        title: ctx => formatFieldName(allFields[ctx[0].dataIndex].field),
                        label: ctx => `Utilization: ${ctx.parsed.x.toFixed(1)}%`
                    }
                }
            },
            scales: {
                x: {
                    min: 0,
                    max: 100,
                    title: { display: true, text: 'Utilization %', font: { weight: 'bold' } },
                    grid: { color: '#eee' }
                },
                y: {
                    title: { display: false },
                    ticks: { autoSkip: false, font: { size: 12 } },
                    grid: { display: false }
                }
            },
            layout: {
                padding: { left: 10, right: 30, top: 10, bottom: 10 }
            }
        }
    });
}

function renderFieldLeaderboards() {
    if (!mostUtilizedFields || !leastUtilizedFields || !summaryData.global_completeness) return;
    const required = filterExcludedFields(summaryData.global_completeness.required_fields || []);
    const optional = filterExcludedFields(summaryData.global_completeness.optional_fields || []);
    const allFields = [...required, ...optional];
    // Most utilized: top 15 (excluding excluded fields)
    const most = [...allFields].sort((a, b) => (b.percentage || 0) - (a.percentage || 0)).slice(0, 15);
    // Least utilized: bottom 15 (excluding excluded fields)
    const least = [...allFields].sort((a, b) => (a.percentage || 0) - (b.percentage || 0)).slice(0, 15);
    mostUtilizedFields.innerHTML = most.map(f => fieldCard(f)).join('');
    leastUtilizedFields.innerHTML = least.map(f => fieldCard(f)).join('');
}

function fieldCard(field) {
    return `<div class="field-card">
        <div class="field-name">${escapeHtml(formatFieldName(field.field))}</div>
        <div class="field-description">${escapeHtml(getFieldDescription(field.field))}</div>
        <div class="field-stats">
            <span class="field-percentage">${(field.percentage || 0).toFixed(1)}%</span>
            <div class="field-progress">
                <div class="field-progress-fill ${getScoreClass(field.percentage)}" style="width: ${Math.min(field.percentage, 100)}%"></div>
            </div>
        </div>
    </div>`;
}

function renderRequiredFieldsTable() {
    if (!requiredFieldsTableBody || !summaryData.global_completeness) return;
    const required = summaryData.global_completeness.required_fields || [];
    let search = (requiredFieldsSearch && requiredFieldsSearch.value) ? requiredFieldsSearch.value.toLowerCase() : '';
    let filtered = required.filter(f => f.field.toLowerCase().includes(search) || getFieldDescription(f.field).toLowerCase().includes(search));
    requiredFieldsTableBody.innerHTML = filtered.map(f => `<tr>
        <td>${escapeHtml(formatFieldName(f.field))}</td>
        <td>${(f.percentage || 0).toFixed(1)}%</td>
        <td>${escapeHtml(getFieldDescription(f.field))}</td>
    </tr>`).join('');
}

function setFieldTableSort(key) {
    if (fieldTableSort.key === key) {
        fieldTableSort.dir = fieldTableSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
        fieldTableSort.key = key;
        fieldTableSort.dir = key === 'rank' ? 'asc' : 'desc';
    }
    updateFieldTableSortIndicators();
    renderOptionalFieldsTable();
}

function updateFieldTableSortIndicators() {
    const headers = [
        { id: 'sort-rank', key: 'rank' },
        { id: 'sort-name', key: 'name' },
        { id: 'sort-util', key: 'util' }
    ];
    headers.forEach(h => {
        const el = document.getElementById(h.id);
        if (!el) return;
        el.classList.remove('sorted-asc', 'sorted-desc');
        if (fieldTableSort.key === h.key) {
            el.classList.add(fieldTableSort.dir === 'asc' ? 'sorted-asc' : 'sorted-desc');
        }
    });
}

function renderOptionalFieldsTable() {
    if (!optionalFieldsTableBody || !summaryData.global_completeness) return;
    let required = filterExcludedFields(summaryData.global_completeness.required_fields || []);
    let optional = filterExcludedFields(summaryData.global_completeness.optional_fields || []);
    let allFields = [...required, ...optional];
    // Sort
    let sorted;
    if (fieldTableSort.key === 'rank') {
        sorted = allFields.map((f, i) => ({ ...f, _rank: i + 1 }));
        if (fieldTableSort.dir === 'desc') sorted.reverse();
    } else if (fieldTableSort.key === 'name') {
        sorted = allFields.slice().sort((a, b) => fieldTableSort.dir === 'asc' ? a.field.localeCompare(b.field) : b.field.localeCompare(a.field));
    } else if (fieldTableSort.key === 'util') {
        sorted = allFields.slice().sort((a, b) => fieldTableSort.dir === 'asc' ? (a.percentage || 0) - (b.percentage || 0) : (b.percentage || 0) - (a.percentage || 0));
    } else {
        sorted = allFields;
    }
    optionalFieldsTableBody.innerHTML = sorted.map((f, idx) => `<tr>
        <td>${fieldTableSort.key === 'rank' ? (f._rank || idx + 1) : (idx + 1)}</td>
        <td>${escapeHtml(formatFieldName(f.field))}</td>
        <td>${(f.percentage || 0).toFixed(1)}%</td>
        <td>${escapeHtml(getFieldDescription(f.field))}</td>
    </tr>`).join('');
}

// Render the overall utilization table in the card box
function renderOverallUtilizationTable() {
    const tbody = document.getElementById('overall-utilization-table-body');
    if (!tbody || !summaryData.global_completeness) return;
    let required = filterExcludedFields(summaryData.global_completeness.required_fields || []);
    let optional = filterExcludedFields(summaryData.global_completeness.optional_fields || []);
    let allFields = [...required, ...optional];
    // Sort by utilization descending
    allFields.sort((a, b) => (b.percentage || 0) - (a.percentage || 0));
    tbody.innerHTML = allFields.map(f => `<tr>
        <td>${escapeHtml(formatFieldName(f.field))}</td>
        <td>${(f.percentage || 0).toFixed(1)}%</td>
        <td>${escapeHtml(getFieldDescription(f.field))}</td>
    </tr>`).join('');
}

// Render the CNA utilization table in the card box
async function renderCnaUtilizationTable() {
    const tbody = document.getElementById('cna-utilization-table-body');
    if (!tbody) return;
    // Load CNA field utilization data (precomputed or fallback to empty)
    let cnaFieldUtil = [];
    try {
        const resp = await fetch('cna_field_utilization.json');
        cnaFieldUtil = await resp.json();
    } catch (e) { cnaFieldUtil = []; }
    // If not available, show message
    if (!Array.isArray(cnaFieldUtil) || cnaFieldUtil.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3">No CNA field utilization data available.</td></tr>';
        return;
    }
    // Sort by selected column and direction
    cnaFieldUtil.sort((a, b) => {
        let vA = a[cnaUtilSort.key], vB = b[cnaUtilSort.key];
        if (typeof vA === 'string') vA = vA.toLowerCase();
        if (typeof vB === 'string') vB = vB.toLowerCase();
        if (vA < vB) return cnaUtilSort.dir === 'asc' ? -1 : 1;
        if (vA > vB) return cnaUtilSort.dir === 'asc' ? 1 : -1;
        return 0;
    });
    tbody.innerHTML = cnaFieldUtil.map(f => `<tr>
        <td>${escapeHtml(formatFieldName(f.field))}</td>
        <td>${f.unique_cnas || 0}</td>
        <td>${(f.cna_percent || 0).toFixed(1)}%</td>
    </tr>`).join('');
}

function setupSearchFilters() {
    if (requiredFieldsSearch) requiredFieldsSearch.addEventListener('input', renderRequiredFieldsTable);
    if (optionalFieldsSearch) optionalFieldsSearch.addEventListener('input', renderOptionalFieldsTable);
}

function setupCnaUtilTableSort() {
    const sortField = document.getElementById('cna-sort-field');
    const sortUnique = document.getElementById('cna-sort-unique');
    const sortPercent = document.getElementById('cna-sort-percent');
    if (sortField) sortField.addEventListener('click', () => setCnaUtilSort('field'));
    if (sortUnique) sortUnique.addEventListener('click', () => setCnaUtilSort('unique_cnas'));
    if (sortPercent) sortPercent.addEventListener('click', () => setCnaUtilSort('cna_percent'));
}

function setCnaUtilSort(key) {
    if (cnaUtilSort.key === key) {
        cnaUtilSort.dir = cnaUtilSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
        cnaUtilSort.key = key;
        cnaUtilSort.dir = key === 'cna_percent' ? 'asc' : 'desc';
    }
    updateCnaUtilSortIndicators();
    renderCnaUtilizationTable();
}

function updateCnaUtilSortIndicators() {
    const headers = [
        { id: 'cna-sort-field', key: 'field' },
        { id: 'cna-sort-unique', key: 'unique_cnas' },
        { id: 'cna-sort-percent', key: 'cna_percent' }
    ];
    headers.forEach(h => {
        const el = document.getElementById(h.id);
        if (!el) return;
        el.classList.remove('sorted-asc', 'sorted-desc');
        if (cnaUtilSort.key === h.key) {
            el.classList.add(cnaUtilSort.dir === 'asc' ? 'sorted-asc' : 'sorted-desc');
        }
    });
}

function updateLastUpdated() {
    const el = document.getElementById('last-updated');
    if (el && summaryData.generated_at) {
        const d = new Date(summaryData.generated_at);
        el.textContent = d.toLocaleString();
    }
}

function showError(msg) {
    document.body.innerHTML = `<div class='error-message'><h2>Error</h2><p>${escapeHtml(msg)}</p></div>`;
}

// Utility: escape HTML
function escapeHtml(unsafe) {
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
// Utility: format field name
function formatFieldName(name) {
    return name.replace(/\./g, ' → ').replace(/_/g, ' ');
}
// Utility: get field description from summaryData
function getFieldDescription(field) {
    if (summaryData.field_definitions && summaryData.field_definitions[field]) {
        return summaryData.field_definitions[field].description || '';
    }
    return '';
}
// Utility: get score class for progress bar
function getScoreClass(score) {
    if (score >= 90) return 'excellent';
    if (score >= 70) return 'good';
    if (score >= 40) return 'fair';
    return 'poor';
}
