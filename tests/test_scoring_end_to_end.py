
import unittest
import json
import os
import sys
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cnascorecard.eas_scorer import EnhancedAggregateScorer

class TestScoringEndToEnd(unittest.TestCase):

    def setUp(self):
        # Set up Chrome options for headless browsing
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        self.driver = webdriver.Chrome(options=chrome_options)

    def tearDown(self):
        self.driver.quit()

    def get_test_cve(self, cve_id):
        """Load a test CVE from the cve_data directory."""
        # Note: This is a simplified loader. A real implementation would need
        # to handle the CVE JSON 5.0 format correctly.
        file_path = os.path.join(os.path.dirname(__file__), '..', 'cve_data', 'cves', '2023', '25xxx', f'{cve_id}.json')
        if not os.path.exists(file_path):
            # Create a dummy file for testing if it doesn't exist
            dummy_cve = {
                "cveMetadata": {
                    "cveId": cve_id,
                    "assignerShortName": "TestCNA",
                    "datePublished": "2023-01-01T00:00:00Z"
                },
                "containers": {
                    "cna": {
                        "affected": [
                            {
                                "vendor": "TestVendor",
                                "product": "TestProduct",
                                "versions": [
                                    {
                                        "version": "1.0",
                                        "status": "affected"
                                    }
                                ],
                                "cpes": ["cpe:2.3:a:testvendor:testproduct:1.0:*:*:*:*:*:*:*"]
                            }
                        ],
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "A test vulnerability description."
                            }
                        ],
                        "metrics": [
                            {
                                "cvssV3_1": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ],
                        "problemTypes": [
                            {
                                "descriptions": [
                                    {
                                        "type": "CWE",
                                        "lang": "en",
                                        "description": "CWE-79",
                                        "cweId": "CWE-79"
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
            with open(file_path, 'w') as f:
                json.dump(dummy_cve, f)

        with open(file_path, 'r') as f:
            return json.load(f)

    def test_backend_legacy_score_removed(self):
        """Test Case 1: Assert that 'Data Format & Precision' is not in the output."""
        cve_data = self.get_test_cve('CVE-2023-25001')
        scorer = EnhancedAggregateScorer(cve_data)
        scores = scorer.calculate_scores()
        self.assertNotIn('dataFormatAndPrecision', scores['scoreBreakdown'])

    def test_backend_correct_formatting_points(self):
        """Test Case 2: Assert that each component receives its format precision point."""
        cve_data = self.get_test_cve('CVE-2023-25002')
        # Ensure valid data for all components
        cna_container = cve_data['containers']['cna']
        cna_container['metrics'][0]['cvssV3_1']['vectorString'] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cna_container['problemTypes'][0]['descriptions'][0]['cweId'] = "CWE-79"
        cna_container['affected'][0]['cpes'] = ["cpe:2.3:a:testvendor:testproduct:1.0:*:*:*:*:*:*:*"]

        scorer = EnhancedAggregateScorer(cve_data)
        scores = scorer.calculate_scores()
        breakdown = scores['scoreBreakdown']

        # Check for the extra point in each relevant category
        self.assertGreater(breakdown['rootCauseAnalysis'], 10)
        self.assertGreater(breakdown['softwareIdentification'], 10)
        self.assertGreater(breakdown['severityAndImpactContext'], 10)


    def test_backend_incorrect_formatting_penalty(self):
        """Test Case 3: Assert that a malformed CVSS string does not get a precision point."""
        cve_data = self.get_test_cve('CVE-2023-25003')
        cve_data['containers']['cna']['metrics'][0]['cvssV3_1']['vectorString'] = "INVALID-CVSS-STRING"
        
        scorer = EnhancedAggregateScorer(cve_data)
        scores = scorer.calculate_scores()
        breakdown = scores['scoreBreakdown']
        
        self.assertLess(breakdown['severityAndImpactContext'], 11)

    def test_backend_total_score_integrity(self):
        """Test Case 4: Assert that the total score is the sum of the component scores."""
        cve_data = self.get_test_cve('CVE-2023-25004')
        scorer = EnhancedAggregateScorer(cve_data)
        scores = scorer.calculate_scores()
        
        total_from_breakdown = sum(scores['scoreBreakdown'].values())
        self.assertAlmostEqual(scores['totalEasScore'], total_from_breakdown, places=2)

    def test_frontend_ui_element_removed(self):
        """Test Case 5: Assert that 'Data Format & Precision' is not in the UI."""
        scoring_page = "file://" + os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'web', 'scoring.html'))
        self.driver.get(scoring_page)
        body_text = self.driver.find_element(By.TAG_NAME, 'body').text
        self.assertNotIn('Data Format & Precision', body_text)

    def test_frontend_ui_score_display(self):
        """Test Case 6: Assert that scores are correctly displayed in the UI."""
        scoring_page = "file://" + os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'web', 'scoring.html'))
        self.driver.get(scoring_page)
        
        # This test requires a mechanism to load a test CVE into the page.
        # For now, we'll just check if the score containers are present.
        self.assertIsNotNone(self.driver.find_element(By.ID, 'foundational-score'))
        self.assertIsNotNone(self.driver.find_element(By.ID, 'root-cause-score'))
        self.assertIsNotNone(self.driver.find_element(By.ID, 'software-identification-score'))
        self.assertIsNotNone(self.driver.find_element(By.ID, 'severity-context-score'))
        self.assertIsNotNone(self.driver.find_element(By.ID, 'actionable-intelligence-score'))

    def test_frontend_ui_total_score_display(self):
        """Test Case 7: Assert that the total score is correctly displayed."""
        scoring_page = "file://" + os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'web', 'scoring.html'))
        self.driver.get(scoring_page)
        
        # As with the previous test, this is a basic check.
        self.assertIsNotNone(self.driver.find_element(By.ID, 'total-score'))

if __name__ == '__main__':
    unittest.main()
