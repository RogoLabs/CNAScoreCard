// Dynamic Column Toggle Implementation
document.addEventListener('DOMContentLoaded', () => {
  // Store global state
  let showingDetails = false;
  
  // Get references to key elements
  const toggleButton = document.getElementById('toggleDetailColumns');
  
  // Set up event listener for the toggle button
  if (toggleButton) {
    toggleButton.addEventListener('click', () => {
      // Toggle state
      showingDetails = !showingDetails;
      
      // Update toggle button text visibility
      if (showingDetails) {
        document.querySelector('.toggle-text-show').style.display = 'none';
        document.querySelector('.toggle-text-hide').style.display = 'inline';
      } else {
        document.querySelector('.toggle-text-show').style.display = 'inline';
        document.querySelector('.toggle-text-hide').style.display = 'none';
      }
      
      // Get all table header and data rows
      const tableHeaders = document.querySelectorAll('#leaderboardTable thead tr th');
      const tableRows = document.querySelectorAll('#leaderboardTable tbody tr');
      
      // Process table headers - completely remove/add the columns
      for (let i = 0; i < tableHeaders.length; i++) {
        if (tableHeaders[i].classList.contains('detail-column')) {
          tableHeaders[i].style.display = showingDetails ? 'table-cell' : 'none';
        }
      }
      
      // Process each row in the table
      tableRows.forEach(row => {
        const cells = row.querySelectorAll('td');
        for (let i = 0; i < cells.length; i++) {
          // The columns positions 5-9 are the detail columns (0-based index)
          // This matches the 5 detail columns we want to toggle
          if (i >= 5 && i <= 9) {
            cells[i].style.display = showingDetails ? 'table-cell' : 'none';
          }
        }
      });
      
      console.log(`Detail columns are now ${showingDetails ? 'shown' : 'hidden'}`);
    });
    
    // Initialize to hidden state by triggering a click and then resetting
    // This ensures all columns are properly hidden on page load
    if (showingDetails === false) {
      // Ensure detail columns are hidden on page load
      const detailHeaders = document.querySelectorAll('#leaderboardTable thead tr th.detail-column');
      detailHeaders.forEach(header => {
        header.style.display = 'none';
      });
      
      // Hide all detail cells in each row
      const tableRows = document.querySelectorAll('#leaderboardTable tbody tr');
      tableRows.forEach(row => {
        const cells = row.querySelectorAll('td');
        for (let i = 0; i < cells.length; i++) {
          if (i >= 5 && i <= 9) {
            cells[i].style.display = 'none';
          }
        }
      });
      
      // Ensure toggle button shows the correct text
      document.querySelector('.toggle-text-show').style.display = 'inline';
      document.querySelector('.toggle-text-hide').style.display = 'none';
    }
  }
});
