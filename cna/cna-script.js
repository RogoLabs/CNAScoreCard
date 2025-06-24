// CNA-specific page functionality
let cnaData = null;
let filteredCves = [];

document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    const cnaList = document.getElementById('cnaList');
    const loading = document.getElementById('loading');

    let allCnas = [];

    // Load CNA data
    fetch('../data/cnas.json')
        .then(response => response.json())
        .then(data => {
            allCnas = data.filter(cna => cna.hasDetailPage);
            loading.style.display = 'none';
            displayCnas(allCnas);
        })
        .catch(error => {
            console.error('Error loading CNA data:', error);
            loading.textContent = 'Error loading CNA data';
        });

    function displayCnas(cnas) {
        if (cnas.length === 0) {
            cnaList.innerHTML = '<p class="no-results">No CNAs found matching your search.</p>';
            return;
        }

        cnaList.innerHTML = cnas.map(cna => `
            <div class="cna-card">
                <h3><a href="${cna.filename}.html">${cna.name}</a></h3>
                <div class="cna-score grade-${cna.letterGrade.toLowerCase()}">${cna.averageScore.toFixed(1)}</div>
                <div class="cna-grade">${cna.letterGrade}</div>
                <div class="cna-stats">
                    <span class="cve-count">${cna.cveCount} CVEs</span>
                    <span class="percentile">Top ${cna.percentileRank}%</span>
                </div>
            </div>
        `).join('');
    }

    function sortCnas(cnas, sortBy) {
        const sorted = [...cnas];
        switch (sortBy) {
            case 'name':
                return sorted.sort((a, b) => a.name.localeCompare(b.name));
            case 'score':
                return sorted.sort((a, b) => b.averageScore - a.averageScore);
            case 'cveCount':
                return sorted.sort((a, b) => b.cveCount - a.cveCount);
            default:
                return sorted;
        }
    }

    function filterAndSort() {
        const searchTerm = searchInput.value.toLowerCase();
        const sortBy = sortSelect.value;

        let filtered = allCnas;
        if (searchTerm) {
            filtered = allCnas.filter(cna => 
                cna.name.toLowerCase().includes(searchTerm)
            );
        }

        const sorted = sortCnas(filtered, sortBy);
        displayCnas(sorted);
    }

    searchInput.addEventListener('input', filterAndSort);
    sortSelect.addEventListener('change', filterAndSort);
});