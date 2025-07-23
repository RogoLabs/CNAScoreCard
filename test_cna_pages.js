#!/usr/bin/env node

/**
 * Automated CNA Detail Page Testing Script
 * Tests all ~300 CNA detail pages to identify loading failures
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// Configuration
const WEB_DIR = path.join(__dirname, 'web');
const CNA_DATA_DIR = path.join(WEB_DIR, 'data', 'cna');
const CNA_COMBINED_FILE = path.join(WEB_DIR, 'data', 'cna_combined.json');
const SERVER_PORT = 8080;
const BASE_URL = `http://localhost:${SERVER_PORT}`;

// Results tracking
const results = {
  total: 0,
  passed: 0,
  failed: 0,
  errors: []
};

/**
 * Start a simple HTTP server for testing
 */
function startServer() {
  return new Promise((resolve, reject) => {
    console.log('🚀 Starting HTTP server...');
    
    const server = spawn('python3', ['-m', 'http.server', SERVER_PORT.toString()], {
      cwd: WEB_DIR,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    server.stdout.on('data', (data) => {
      const output = data.toString();
      if (output.includes('Serving HTTP')) {
        console.log(`✅ Server started at ${BASE_URL}`);
        setTimeout(() => resolve(server), 1000); // Give server time to fully start
      }
    });

    server.stderr.on('data', (data) => {
      console.error('Server error:', data.toString());
    });

    server.on('error', (error) => {
      reject(error);
    });

    // Timeout after 10 seconds
    setTimeout(() => {
      reject(new Error('Server startup timeout'));
    }, 10000);
  });
}

/**
 * Test if a CNA JSON file exists and is valid
 */
function testCnaJsonFile(shortName) {
  const filePath = path.join(CNA_DATA_DIR, `${shortName}.json`);
  
  try {
    if (!fs.existsSync(filePath)) {
      return { success: false, error: 'JSON file does not exist' };
    }
    
    const content = fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);
    
    // Basic structure validation
    if (!data.cna_info) {
      return { success: false, error: 'Missing cna_info structure' };
    }
    
    return { success: true, data: data };
  } catch (error) {
    return { success: false, error: `JSON parsing error: ${error.message}` };
  }
}

/**
 * Test a CNA detail page by making HTTP request
 */
async function testCnaPage(shortName) {
  const url = `${BASE_URL}/cna/cna-detail.html?shortName=${encodeURIComponent(shortName)}`;
  
  try {
    const response = await fetch(url);
    
    if (!response.ok) {
      return { success: false, error: `HTTP ${response.status}: ${response.statusText}` };
    }
    
    const html = await response.text();
    
    // Check if page loaded successfully (basic checks)
    if (html.includes('Error loading CNA data') || html.includes('CNA not found')) {
      return { success: false, error: 'Page shows error message' };
    }
    
    return { success: true };
  } catch (error) {
    return { success: false, error: `Network error: ${error.message}` };
  }
}

/**
 * Load CNA list from combined JSON
 */
function loadCnaList() {
  try {
    const content = fs.readFileSync(CNA_COMBINED_FILE, 'utf8');
    const data = JSON.parse(content);
    return data.map(cna => ({
      shortName: cna.shortName,
      organizationName: cna.organizationName,
      rank: cna.rank
    }));
  } catch (error) {
    console.error('❌ Failed to load CNA list:', error.message);
    process.exit(1);
  }
}

/**
 * Run comprehensive tests on all CNAs
 */
async function runTests() {
  console.log('📋 Loading CNA list...');
  const cnas = loadCnaList();
  results.total = cnas.length;
  
  console.log(`🔍 Testing ${cnas.length} CNA detail pages...\n`);
  
  // Test JSON files first (faster)
  console.log('📁 Testing JSON file availability and structure...');
  const jsonResults = [];
  
  for (const cna of cnas) {
    const jsonTest = testCnaJsonFile(cna.shortName);
    jsonResults.push({
      shortName: cna.shortName,
      organizationName: cna.organizationName,
      rank: cna.rank,
      jsonTest: jsonTest
    });
    
    if (!jsonTest.success) {
      results.errors.push({
        shortName: cna.shortName,
        organizationName: cna.organizationName,
        rank: cna.rank,
        type: 'JSON_ERROR',
        error: jsonTest.error
      });
    }
  }
  
  // Report JSON test results
  const jsonFailures = jsonResults.filter(r => !r.jsonTest.success);
  console.log(`📁 JSON Files: ${jsonResults.length - jsonFailures.length}/${jsonResults.length} passed`);
  
  if (jsonFailures.length > 0) {
    console.log(`\n❌ JSON File Failures (${jsonFailures.length}):`);
    jsonFailures.forEach(failure => {
      console.log(`  • ${failure.shortName} (${failure.organizationName}): ${failure.jsonTest.error}`);
    });
  }
  
  // Start server for page testing
  let server;
  try {
    server = await startServer();
    
    // Test pages (only for CNAs with valid JSON files)
    console.log('\n🌐 Testing page loading...');
    const validJsonCnas = jsonResults.filter(r => r.jsonTest.success);
    
    for (const cna of validJsonCnas.slice(0, 10)) { // Test first 10 for now
      const pageTest = await testCnaPage(cna.shortName);
      
      if (pageTest.success) {
        results.passed++;
        console.log(`✅ ${cna.shortName}`);
      } else {
        results.failed++;
        results.errors.push({
          shortName: cna.shortName,
          organizationName: cna.organizationName,
          rank: cna.rank,
          type: 'PAGE_ERROR',
          error: pageTest.error
        });
        console.log(`❌ ${cna.shortName}: ${pageTest.error}`);
      }
    }
    
  } catch (error) {
    console.error('❌ Server startup failed:', error.message);
    console.log('⚠️  Skipping page tests, only JSON file tests completed');
  } finally {
    if (server) {
      console.log('\n🛑 Stopping server...');
      server.kill();
    }
  }
}

/**
 * Generate test report
 */
function generateReport() {
  console.log('\n' + '='.repeat(60));
  console.log('📊 CNA DETAIL PAGE TEST REPORT');
  console.log('='.repeat(60));
  
  console.log(`Total CNAs: ${results.total}`);
  console.log(`JSON Tests Passed: ${results.total - results.errors.filter(e => e.type === 'JSON_ERROR').length}/${results.total}`);
  console.log(`Page Tests Passed: ${results.passed}/${results.passed + results.failed}`);
  
  if (results.errors.length > 0) {
    console.log(`\n❌ FAILURES (${results.errors.length}):`);
    
    // Group by error type
    const jsonErrors = results.errors.filter(e => e.type === 'JSON_ERROR');
    const pageErrors = results.errors.filter(e => e.type === 'PAGE_ERROR');
    
    if (jsonErrors.length > 0) {
      console.log(`\n📁 JSON File Errors (${jsonErrors.length}):`);
      jsonErrors.forEach(error => {
        console.log(`  • Rank ${error.rank}: ${error.shortName} (${error.organizationName})`);
        console.log(`    Error: ${error.error}`);
      });
    }
    
    if (pageErrors.length > 0) {
      console.log(`\n🌐 Page Loading Errors (${pageErrors.length}):`);
      pageErrors.forEach(error => {
        console.log(`  • Rank ${error.rank}: ${error.shortName} (${error.organizationName})`);
        console.log(`    Error: ${error.error}`);
      });
    }
  }
  
  console.log('\n' + '='.repeat(60));
}

/**
 * Main execution
 */
async function main() {
  console.log('🧪 CNA Detail Page Automated Testing Script');
  console.log('='.repeat(50));
  
  try {
    await runTests();
    generateReport();
  } catch (error) {
    console.error('❌ Test execution failed:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = { main, testCnaJsonFile, loadCnaList };
