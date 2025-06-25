// Test the enhanced description quality scoring algorithm
// This file can be run in a browser console or Node.js to verify the algorithm

// Mock CVE data for testing
const testCVEs = [
    {
        // High quality example
        CVE_data_meta: { ID: "CVE-2024-TEST-1" },
        description: {
            description_data: [{
                value: "A buffer overflow vulnerability in the mod_rewrite module of Apache HTTP Server allows remote attackers to execute arbitrary code via crafted HTTP requests when processing malformed URL patterns in .htaccess files."
            }]
        }
    },
    {
        // Medium quality example
        CVE_data_meta: { ID: "CVE-2024-TEST-2" },
        description: {
            description_data: [{
                value: "A SQL injection vulnerability in the user authentication function allows authenticated users to execute arbitrary SQL commands."
            }]
        }
    },
    {
        // Low quality example
        CVE_data_meta: { ID: "CVE-2024-TEST-3" },
        description: {
            description_data: [{
                value: "A security vulnerability exists in the application."
            }]
        }
    },
    {
        // Very high quality example
        CVE_data_meta: { ID: "CVE-2024-TEST-4" },
        description: {
            description_data: [{
                value: "A use-after-free vulnerability in the JavaScript engine when handling DOM objects during garbage collection allows remote attackers to execute arbitrary code via specially crafted web pages that trigger object reuse after deallocation in the memory management module."
            }]
        }
    }
];

// Test function
function testDescriptionScoring() {
    console.log("Testing Enhanced Description Quality Scoring");
    console.log("=" * 50);
    
    testCVEs.forEach(cve => {
        const result = calculateEAS(cve);
        const desc = cve.description.description_data[0].value;
        
        console.log(`\nCVE: ${cve.CVE_data_meta.ID}`);
        console.log(`Description: ${desc.substring(0, 100)}${desc.length > 100 ? '...' : ''}`);
        console.log(`Foundational Completeness Score: ${result.foundationalCompleteness}/15`);
        console.log(`Overall EAS Score: ${result.overallScore}/100`);
    });
    
    console.log("\nExpected results:");
    console.log("- CVE-2024-TEST-1: Should score ~12-15 points (high quality)");
    console.log("- CVE-2024-TEST-2: Should score ~6-9 points (medium quality)");
    console.log("- CVE-2024-TEST-3: Should score ~1-3 points (low quality)");
    console.log("- CVE-2024-TEST-4: Should score ~13-15 points (very high quality)");
}

// Run test if calculateEAS function is available
if (typeof calculateEAS === 'function') {
    testDescriptionScoring();
} else {
    console.log("calculateEAS function not found. Please include the scoring script first.");
}