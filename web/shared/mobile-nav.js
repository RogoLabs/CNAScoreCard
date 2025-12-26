/**
 * Mobile Navigation Toggle
 * Handles hamburger menu interactions for mobile devices
 */

document.addEventListener('DOMContentLoaded', function() {
  // Create and inject mobile menu toggle button into all navbars
  const navbars = document.querySelectorAll('.navbar');
  
  navbars.forEach(navbar => {
    const navLinks = navbar.querySelector('.navbar-links');
    if (!navLinks) return;
    
    // Check if toggle already exists
    if (navbar.querySelector('.mobile-menu-toggle')) return;
    
    // Create toggle button
    const toggle = document.createElement('button');
    toggle.className = 'mobile-menu-toggle';
    toggle.setAttribute('aria-label', 'Toggle navigation menu');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.innerHTML = '<span></span><span></span><span></span>';
    
    // Insert toggle after logo
    const logo = navbar.querySelector('.navbar-logo');
    if (logo) {
      logo.parentNode.insertBefore(toggle, logo.nextSibling);
    } else {
      navbar.insertBefore(toggle, navLinks);
    }
    
    // Toggle click handler
    toggle.addEventListener('click', function() {
      const isOpen = navLinks.classList.toggle('mobile-open');
      toggle.classList.toggle('open', isOpen);
      toggle.setAttribute('aria-expanded', isOpen.toString());
    });
    
    // Close menu when clicking a link
    navLinks.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', function() {
        navLinks.classList.remove('mobile-open');
        toggle.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      });
    });
  });
  
  // Close menu when clicking outside
  document.addEventListener('click', function(e) {
    const navbars = document.querySelectorAll('.navbar');
    navbars.forEach(navbar => {
      const toggle = navbar.querySelector('.mobile-menu-toggle');
      const navLinks = navbar.querySelector('.navbar-links');
      
      if (toggle && navLinks && !navbar.contains(e.target)) {
        navLinks.classList.remove('mobile-open');
        toggle.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });
  });
});
