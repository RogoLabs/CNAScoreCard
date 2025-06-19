document.addEventListener('DOMContentLoaded', () => {
    fetch('/api/cnas')
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById('cna-data');
            for (const cna in data) {
                const card = document.createElement('div');
                card.className = 'cna-card';
                const cnaData = data[cna];
                card.innerHTML = `
                    <h2>${cna}</h2>
                    <p>Total CVEs Scored: ${cnaData.total_cves_scored}</p>
                    <p>Overall Average Score: ${cnaData.overall_average_score}</p>
                `;
                container.appendChild(card);
            }
        });
});
