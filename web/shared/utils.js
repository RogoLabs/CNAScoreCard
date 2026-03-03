/**
 * Shared utilities for CNA Scorecard web pages.
 * Include this script before page-specific scripts.
 */

const ScoreCardUtils = {
  /**
   * Calculate letter grade from numerical score.
   * @param {number} score - Score from 0-100
   * @returns {string} Letter grade
   */
  getGrade(score) {
    if (score >= 95) return 'A+';
    if (score >= 90) return 'A';
    if (score >= 85) return 'B+';
    if (score >= 80) return 'B';
    if (score >= 75) return 'C+';
    if (score >= 70) return 'C';
    if (score >= 65) return 'D+';
    if (score >= 60) return 'D';
    return 'F';
  },

  /**
   * Get CSS color class for a grade.
   * @param {string} grade - Letter grade
   * @returns {string} CSS class name
   */
  getGradeColorClass(grade) {
    if (grade.startsWith('A')) return 'grade-excellent';
    if (grade.startsWith('B')) return 'grade-good';
    if (grade.startsWith('C')) return 'grade-average';
    if (grade.startsWith('D')) return 'grade-poor';
    return 'grade-failing';
  },

  /**
   * Format a date string for display.
   * @param {string} dateStr - ISO date string
   * @returns {string} Formatted date
   */
  formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    try {
      const date = new Date(dateStr);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return dateStr;
    }
  },

  /**
   * Format a number with commas.
   * @param {number} n - Number to format
   * @returns {string} Formatted number
   */
  formatNumber(n) {
    if (n === null || n === undefined) return '0';
    return n.toLocaleString();
  },

  /**
   * Debounce a function.
   * @param {Function} func - Function to debounce
   * @param {number} wait - Milliseconds to wait
   * @returns {Function} Debounced function
   */
  debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  },

  /**
   * Sanitize a string for safe HTML insertion (prevent XSS).
   * @param {string} str - String to sanitize
   * @returns {string} Sanitized string
   */
  sanitizeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },

  /**
   * Sanitize a URL parameter value.
   * @param {string} param - URL parameter value
   * @returns {string} Sanitized parameter
   */
  sanitizeParam(param) {
    if (!param) return '';
    return param.replace(/[^a-zA-Z0-9\-_.@ ]/g, '');
  },

  /**
   * Format score with visual bar HTML.
   * @param {number} score - Score value
   * @param {boolean} isPercentage - Whether score is a percentage
   * @returns {string} HTML string
   */
  formatScoreWithBar(score, isPercentage = false) {
    const value = score || 0;
    const percentage = isPercentage ? value : Math.min(100, (value / 100) * 100);
    let colorClass = 'score-low';

    if (percentage >= 80) colorClass = 'score-great';
    else if (percentage >= 60) colorClass = 'score-good';
    else if (percentage >= 40) colorClass = 'score-medium';

    const displayValue = isPercentage ? value.toFixed(1) + '%' : value.toFixed(1);

    return '<div class="score-display">' +
      '<div class="score-value">' + displayValue + '</div>' +
      '<div class="score-bar">' +
      '<div class="score-fill ' + colorClass + '" style="width: ' + percentage + '%"></div>' +
      '</div></div>';
  }
};
