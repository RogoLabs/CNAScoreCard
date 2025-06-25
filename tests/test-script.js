// Local test script for CNA Score Card
// Run this before deploying to catch errors early

// Mock data for testing
const mockCNAData = [
    {
        name: "Test CNA 1",
        score: 85.5,
        description: "Test description 1",
        category: "Enterprise"
    },
    {
        name: "Test CNA 2",
        score: 92.3,
        description: "Test description 2", 
        category: "Cloud"
    },
    {
        name: "Test CNA 3",
        // Missing score to test error handling
        description: "Test description 3",
        category: "Security"
    }
];

// Test the createCNACard function
function testCreateCNACard() {
    console.log("Testing createCNACard function...");
    
    mockCNAData.forEach((cna, index) => {
        try {
            console.log(`Testing CNA ${index + 1}:`, cna);
            // This would call the actual createCNACard function
            // createCNACard(cna);
            
            // Check for required properties
            if (!cna.score) {
                console.error(`❌ Error: CNA ${index + 1} missing score property`);
            } else if (typeof cna.score !== 'number') {
                console.error(`❌ Error: CNA ${index + 1} score is not a number:`, typeof cna.score);
            } else {
                console.log(`✅ CNA ${index + 1} score valid:`, cna.score % 1 === 0 ? cna.score.toString() : cna.score.toFixed(1));
            }
            
        } catch (error) {
            console.error(`❌ Error testing CNA ${index + 1}:`, error);
        }
    });
}

// Test data validation
function testDataValidation() {
    console.log("Testing data validation...");
    
    // Test various score values
    const testScores = [85.5, "92.3", null, undefined, NaN, "invalid"];
    
    testScores.forEach((score, index) => {
        console.log(`Testing score ${index + 1}:`, score, typeof score);
        
        if (score !== null && score !== undefined && !isNaN(Number(score))) {
            const numScore = Number(score);
            console.log(`✅ Valid score: ${numScore.toFixed(1)}`);
        } else {
            console.log(`❌ Invalid score: ${score}`);
        }
    });
}

// Run tests
console.log("=== CNA Score Card Local Tests ===");
testCreateCNACard();
console.log("");
testDataValidation();
console.log("=== Tests Complete ===");