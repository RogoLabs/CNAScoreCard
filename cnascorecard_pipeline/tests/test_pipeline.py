"""
Integration tests for the main pipeline orchestration.

This module tests the complete pipeline execution to ensure all components
work together correctly and produce expected outputs.
"""
import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Import the module under test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline import CNAScoreCardPipeline, PipelineError, main


class TestPipelineFixtures:
    """Test fixtures for pipeline tests."""
    
    @pytest.fixture
    def sample_config(self) -> Dict[str, Any]:
        """Sample configuration for testing."""
        return {
            'directories': {
                'web_data': '/test/web/data',
                'completeness': '/test/web/data/completeness',
                'cna_data': '/test/web/data/cna'
            },
            'fields': {
                'field_list': ['containers.cna.descriptions', 'containers.cna.affected'],
                'canonical_fields': [
                    {
                        'field': 'containers.cna.descriptions',
                        'importance': 'High',
                        'description': 'Vulnerability descriptions',
                        'cna_scorecard_category': 'foundationalCompleteness'
                    }
                ]
            }
        }
    
    @pytest.fixture
    def sample_cve_records(self) -> List[Dict[str, Any]]:
        """Sample CVE records for testing."""
        return [
            {
                "cveId": "CVE-2024-0001",
                "cveMetadata": {
                    "datePublished": "2024-01-15T10:00:00.000Z"
                },
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "TestCNA1"}
                    }
                }
            },
            {
                "cveId": "CVE-2024-0002", 
                "cveMetadata": {
                    "datePublished": "2024-01-20T10:00:00.000Z"
                },
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "TestCNA2"}
                    }
                }
            }
        ]
    
    @pytest.fixture
    def sample_scored_cves(self) -> List[Dict[str, Any]]:
        """Sample scored CVE records for testing."""
        return [
            {
                "cveId": "CVE-2024-0001",
                "assigningCna": "TestCNA1",
                "datePublished": "2024-01-15",
                "totalScore": 85,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 15,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 5,
                    "patchinfo": 0
                }
            }
        ]
    
    @pytest.fixture
    def sample_cna_outputs(self) -> Dict[str, Any]:
        """Sample CNA aggregation outputs for testing."""
        return {
            "TestCNA1": {
                "cna_info": [{
                    "shortName": "TestCNA1",
                    "total_cves": 1,
                    "total_cves_scored": 1,
                    "organizationName": "Test Organization",
                    "scope": "Test scope",
                    "advisories": [],
                    "email": [],
                    "officialCnaID": "test-cna-1",
                    "cnaTypes": ["vendor"],
                    "country": "US",
                    "disclosurePolicy": [],
                    "rootCnaInfo": {},
                    "rank": 1,
                    "active_cna_count": 1,
                    "percentile": 100.0
                }],
                "cna_scoring": [{
                    "total_cves": 1,
                    "total_cves_scored": 1,
                    "recent_cves_count": 1,
                    "overall_average_score": 85.0,
                    "average_foundational_completeness": 50.0,
                    "average_root_cause_analysis": 15.0,
                    "average_software_identification": 5.0,
                    "average_severity_context": 15.0,
                    "average_patchinfo": 0.0,
                    "percent_foundational_completeness": 100.0,
                    "percent_root_cause_analysis": 100.0,
                    "percent_software_identification": 100.0,
                    "percent_severity_and_impact": 100.0,
                    "percent_patchinfo": 0.0,
                    "trend_direction": "steady",
                    "trend_description": "No significant change",
                    "monthly_trends": []
                }],
                "cve_scoring": [{
                    "cveId": "CVE-2024-0001",
                    "assigningCna": "TestCNA1",
                    "datePublished": "2024-01-15",
                    "totalCveScore": 85,
                    "scoreBreakdown": {
                        "foundationalCompleteness": 50,
                        "rootCauseAnalysis": 15,
                        "severityAndImpactContext": 15,
                        "softwareIdentification": 5,
                        "patchinfo": 0
                    }
                }]
            }
        }


class TestCNAScoreCardPipeline(TestPipelineFixtures):
    """Test the main CNAScoreCardPipeline class."""
    
    def test_pipeline_initialization(self, sample_config):
        """Test pipeline initialization."""
        pipeline = CNAScoreCardPipeline(sample_config)
        
        assert pipeline.config == sample_config
        assert pipeline.cve_records == []
        assert pipeline.filtered_cve_records == []
        assert pipeline.scored_cves == []
        assert pipeline.cna_outputs == {}
        assert pipeline.analysis_periods == {}
    
    def test_pipeline_initialization_default_config(self):
        """Test pipeline initialization with default config."""
        with patch('pipeline.get_config') as mock_get_config:
            mock_get_config.return_value = {'test': 'config'}
            
            pipeline = CNAScoreCardPipeline()
            
            assert pipeline.config == {'test': 'config'}
            mock_get_config.assert_called_once()
    
    @patch('pipeline.CNAScoreCardPipeline._generate_output_files')
    @patch('pipeline.CNAScoreCardPipeline._generate_completeness_analysis')
    @patch('pipeline.CNAScoreCardPipeline._aggregate_cna_scores')
    @patch('pipeline.CNAScoreCardPipeline._score_cve_records')
    @patch('pipeline.CNAScoreCardPipeline._load_cve_data')
    @patch('pipeline.CNAScoreCardPipeline._setup_analysis_periods')
    def test_pipeline_run_success(
        self,
        mock_setup_periods,
        mock_load_data,
        mock_score_cves,
        mock_aggregate,
        mock_completeness,
        mock_output,
        sample_config
    ):
        """Test successful pipeline execution."""
        # Setup mocks
        mock_output.return_value = {'test_file': '/path/to/file.json'}
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.cve_records = [{'test': 'cve'}]
        pipeline.filtered_cve_records = [{'test': 'filtered_cve'}]
        pipeline.scored_cves = [{'test': 'scored_cve'}]
        pipeline.cna_outputs = {'TestCNA': {'test': 'output'}}
        pipeline.analysis_periods = {
            'current': ('2024-01-01', '2024-06-30'),
            'previous': ('2023-07-01', '2023-12-31')
        }
        
        result = pipeline.run()
        
        # Verify all steps were called
        mock_setup_periods.assert_called_once_with(None, None)
        mock_load_data.assert_called_once()
        mock_score_cves.assert_called_once()
        mock_aggregate.assert_called_once()
        mock_completeness.assert_called_once()
        mock_output.assert_called_once_with(None)
        
        # Verify result structure
        assert result['status'] == 'success'
        assert 'execution_time' in result
        assert result['analysis_period'] == ('2024-01-01', '2024-06-30')
        assert result['total_cves_processed'] == 1
        assert result['filtered_cves_count'] == 1
        assert result['scored_cves_count'] == 1
        assert result['cnas_processed'] == 1
        assert result['output_files'] == {'test_file': '/path/to/file.json'}
    
    @patch('pipeline.CNAScoreCardPipeline._setup_analysis_periods')
    def test_pipeline_run_failure(self, mock_setup_periods, sample_config):
        """Test pipeline execution failure."""
        mock_setup_periods.side_effect = Exception("Test error")
        
        pipeline = CNAScoreCardPipeline(sample_config)
        
        with pytest.raises(PipelineError, match="Pipeline execution failed: Test error"):
            pipeline.run()
    
    def test_setup_analysis_periods_custom_dates(self, sample_config):
        """Test analysis period setup with custom dates."""
        pipeline = CNAScoreCardPipeline(sample_config)
        
        pipeline._setup_analysis_periods("2024-01-01", "2024-06-30")
        
        assert pipeline.analysis_periods['current'] == ("2024-01-01", "2024-06-30")
        assert pipeline.analysis_periods['previous'] == ("2023-07-03", "2023-12-31")
    
    @patch('pipeline.get_date_range_for_period')
    def test_setup_analysis_periods_default(self, mock_get_range, sample_config):
        """Test analysis period setup with default dates."""
        mock_get_range.return_value = ("2024-01-01", "2024-06-30")
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline._setup_analysis_periods(None, None)
        
        assert pipeline.analysis_periods['current'] == ("2024-01-01", "2024-06-30")
        mock_get_range.assert_called_once()
    
    def test_setup_analysis_periods_invalid_range(self, sample_config):
        """Test analysis period setup with invalid date range."""
        pipeline = CNAScoreCardPipeline(sample_config)
        
        with pytest.raises(PipelineError, match="Invalid date range"):
            pipeline._setup_analysis_periods("2024-06-30", "2024-01-01")
    
    @patch('pipeline.load_cve_records')
    def test_load_cve_data_success(self, mock_load_cves, sample_config, sample_cve_records):
        """Test successful CVE data loading."""
        mock_load_cves.side_effect = [sample_cve_records, [sample_cve_records[0]]]
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.analysis_periods = {'current': ('2024-01-01', '2024-06-30')}
        
        pipeline._load_cve_data()
        
        assert len(pipeline.cve_records) == 2
        assert len(pipeline.filtered_cve_records) == 1
        assert mock_load_cves.call_count == 2
    
    @patch('pipeline.load_cve_records')
    def test_load_cve_data_no_filtered_records(self, mock_load_cves, sample_config):
        """Test CVE data loading with no filtered records."""
        mock_load_cves.side_effect = [['some_cve'], []]  # No filtered records
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.analysis_periods = {'current': ('2024-01-01', '2024-06-30')}
        
        with pytest.raises(PipelineError, match="No CVE records found"):
            pipeline._load_cve_data()
    
    @patch('pipeline.score_multiple_cves')
    def test_score_cve_records_success(self, mock_score, sample_config, sample_scored_cves):
        """Test successful CVE scoring."""
        mock_score.return_value = sample_scored_cves
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.filtered_cve_records = [{'test': 'cve'}]
        
        pipeline._score_cve_records()
        
        assert pipeline.scored_cves == sample_scored_cves
        mock_score.assert_called_once_with([{'test': 'cve'}])
    
    @patch('pipeline.score_multiple_cves')
    def test_score_cve_records_no_scores(self, mock_score, sample_config):
        """Test CVE scoring with no successful scores."""
        mock_score.return_value = []
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.filtered_cve_records = [{'test': 'cve'}]
        
        with pytest.raises(PipelineError, match="No CVE records could be scored"):
            pipeline._score_cve_records()
    
    @patch('pipeline.aggregate_cna_scores')
    def test_aggregate_cna_scores_success(self, mock_aggregate, sample_config, sample_cna_outputs):
        """Test successful CNA score aggregation."""
        mock_aggregate.return_value = sample_cna_outputs
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.scored_cves = [{'test': 'scored_cve'}]
        pipeline.analysis_periods = {
            'current': ('2024-01-01', '2024-06-30'),
            'previous': ('2023-07-01', '2023-12-31')
        }
        
        pipeline._aggregate_cna_scores()
        
        assert pipeline.cna_outputs == sample_cna_outputs
        mock_aggregate.assert_called_once()
    
    @patch('pipeline.compute_individual_cna_field_utilization')
    @patch('pipeline.compute_field_utilization')
    def test_generate_completeness_analysis(
        self, 
        mock_field_util, 
        mock_individual_util,
        sample_config
    ):
        """Test completeness analysis generation."""
        mock_field_util.return_value = [{'field': 'test', 'cna_percent': 50.0}]
        mock_individual_util.return_value = {'TestCNA': [{'field': 'test', 'percent': 100.0}]}
        
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.filtered_cve_records = [{'test': 'cve'}]
        
        pipeline._generate_completeness_analysis()
        
        assert pipeline.field_utilization == [{'field': 'test', 'cna_percent': 50.0}]
        assert pipeline.individual_cna_utilization == {'TestCNA': [{'field': 'test', 'percent': 100.0}]}
    
    def test_calculate_grade(self, sample_config):
        """Test grade calculation."""
        pipeline = CNAScoreCardPipeline(sample_config)
        
        assert pipeline._calculate_grade(98) == "A+"
        assert pipeline._calculate_grade(92) == "A"
        assert pipeline._calculate_grade(87) == "B+"
        assert pipeline._calculate_grade(82) == "B"
        assert pipeline._calculate_grade(77) == "C+"
        assert pipeline._calculate_grade(72) == "C"
        assert pipeline._calculate_grade(67) == "D+"
        assert pipeline._calculate_grade(62) == "D"
        assert pipeline._calculate_grade(50) == "F"


class TestPipelineOutputGeneration(TestPipelineFixtures):
    """Test pipeline output file generation."""
    
    @patch('pipeline.write_json_file')
    @patch('pipeline.ensure_directory_exists')
    def test_generate_individual_cna_files(
        self, 
        mock_ensure_dir, 
        mock_write_json,
        sample_config,
        sample_cna_outputs
    ):
        """Test individual CNA file generation."""
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.cna_outputs = sample_cna_outputs
        
        result = pipeline._generate_individual_cna_files(Path('/test/output'))
        
        assert 'cna_TestCNA1' in result
        assert result['cna_TestCNA1'] == '/test/output/cna/TestCNA1.json'
        mock_write_json.assert_called()
        mock_ensure_dir.assert_called()
    
    @patch('pipeline.write_json_file')
    def test_generate_summary_files(
        self, 
        mock_write_json,
        sample_config,
        sample_cna_outputs
    ):
        """Test summary file generation."""
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.cna_outputs = sample_cna_outputs
        pipeline.analysis_periods = {'current': ('2024-01-01', '2024-06-30')}
        pipeline.filtered_cve_records = [{'test': 'cve'}]
        
        result = pipeline._generate_summary_files(Path('/test/output'))
        
        assert 'cna_combined' in result
        assert 'cna_summary' in result
        assert 'completeness_summary' in result
        assert mock_write_json.call_count == 3
    
    @patch('pipeline.write_json_file')
    @patch('pipeline.ensure_directory_exists')
    def test_generate_completeness_files(
        self, 
        mock_ensure_dir,
        mock_write_json,
        sample_config
    ):
        """Test completeness file generation."""
        pipeline = CNAScoreCardPipeline(sample_config)
        pipeline.field_utilization = [
            {'field': 'test_field', 'cna_percent': 75.0, 'unique_cnas': 10}
        ]
        pipeline.individual_cna_utilization = {
            'TestCNA': [{'field': 'test_field', 'percent': 100.0}]
        }
        
        result = pipeline._generate_completeness_files(Path('/test/output'))
        
        assert 'field_utilization' in result
        assert 'completeness_TestCNA' in result
        mock_ensure_dir.assert_called()
        assert mock_write_json.call_count >= 2


class TestPipelineMain:
    """Test the main function and CLI interface."""
    
    @patch('pipeline.CNAScoreCardPipeline')
    @patch('pipeline.setup_logging')
    @patch('sys.argv', ['pipeline.py', '--log-level', 'DEBUG'])
    def test_main_function_success(self, mock_setup_logging, mock_pipeline_class):
        """Test successful main function execution."""
        mock_logger = MagicMock()
        mock_setup_logging.return_value = mock_logger
        
        mock_pipeline = MagicMock()
        mock_pipeline.run.return_value = {
            'status': 'success',
            'execution_time': '0:01:30',
            'analysis_period': ('2024-01-01', '2024-06-30'),
            'total_cves_processed': 1000,
            'filtered_cves_count': 500,
            'scored_cves_count': 500,
            'cnas_processed': 50,
            'output_files': {'test': 'file.json'}
        }
        mock_pipeline_class.return_value = mock_pipeline
        
        # Should not raise an exception
        main()
        
        mock_setup_logging.assert_called_once_with('DEBUG')
        mock_pipeline_class.assert_called_once()
        mock_pipeline.run.assert_called_once()
    
    @patch('pipeline.CNAScoreCardPipeline')
    @patch('pipeline.setup_logging')
    @patch('sys.argv', ['pipeline.py'])
    def test_main_function_failure(self, mock_setup_logging, mock_pipeline_class):
        """Test main function with pipeline failure."""
        mock_logger = MagicMock()
        mock_setup_logging.return_value = mock_logger
        
        mock_pipeline = MagicMock()
        mock_pipeline.run.side_effect = Exception("Pipeline failed")
        mock_pipeline_class.return_value = mock_pipeline
        
        with pytest.raises(Exception, match="Pipeline failed"):
            main()


class TestPipelineErrorHandling:
    """Test error handling throughout the pipeline."""
    
    def test_pipeline_error_creation(self):
        """Test PipelineError exception creation."""
        error = PipelineError("Test error message")
        assert str(error) == "Test error message"
        assert isinstance(error, Exception)
    
    @patch('pipeline.CNAScoreCardPipeline._load_cve_data')
    def test_pipeline_error_propagation(self, mock_load_data):
        """Test that errors are properly propagated as PipelineError."""
        mock_load_data.side_effect = ValueError("Data loading failed")
        
        # Create sample config directly
        from pathlib import Path
        sample_config = {
            'cve_data_dir': Path('/test/cve_data'),
            'output_dir': Path('/test/output'),
            'start_date': '2024-01-01',
            'end_date': '2024-06-30'
        }
        
        pipeline = CNAScoreCardPipeline(sample_config)
        
        with pytest.raises(PipelineError) as exc_info:
            pipeline.run()
        
        assert "Pipeline execution failed" in str(exc_info.value)
        assert "Data loading failed" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
