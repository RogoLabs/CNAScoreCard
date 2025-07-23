// Column Toggle Functionality for CNA Index Table
function setupColumnToggle() {
  const toggleButton = document.getElementById('toggleDetailColumns');
  const tableContainer = document.querySelector('.leaderboard-section');
  
  if (toggleButton && tableContainer) {
    // Ensure initial state is hidden (no showing-details class)
    tableContainer.classList.remove('showing-details');
    
    // Make sure all detail columns are initially hidden via inline style as well
    const detailCells = document.querySelectorAll('.detail-column');
    detailCells.forEach(cell => {
      cell.style.display = 'none';
      cell.style.transition = 'all 0.3s ease';
    });
    
    toggleButton.addEventListener('click', () => {
      // Toggle the class
      const isShowingDetails = tableContainer.classList.toggle('showing-details');
      
      // Also toggle display style explicitly to ensure it works
      detailCells.forEach(cell => {
        cell.style.display = isShowingDetails ? 'table-cell' : 'none';
      });
    });
  }
}

// Run when included on the page
document.addEventListener('DOMContentLoaded', () => {
  setupColumnToggle();
});
