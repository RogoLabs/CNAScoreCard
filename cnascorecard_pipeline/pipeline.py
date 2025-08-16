"""
CNA Scorecard Pipeline - Main Orchestration Module.

This module provides the main entry point for the CNA Scorecard data pipeline,
orchestrating the entire process from data ingestion to output generation.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path

from config import get_config, ANALYSIS_PERIOD_MONTHS
from utils import setup_logging, ensure_directory_exists, write_json_file, ProgressTracker
from ingest import load_cve_records, load_cna_list, get_date_range_for_period, validate_date_range
from scoring import score_multiple_cves
from completeness import compute_field_utilization, compute_individual_cna_field_utilization
from aggregation import aggregate_cna_scores
from trends import calculate_daily_trends, calculate_top_improvers

from sync_cna_list import sync_cna_list

# Initialize logging
logger = logging.getLogger('cnascorecard.pipeline')


class PipelineError(Exception):
    """Custom exception for pipeline errors."""
    pass


class CNAScoreCardPipeline:
    """
    Main pipeline class for CNA Scorecard data processing.
    
    This class orchestrates the entire pipeline from data loading to output generation,
    providing a clean interface for running the complete analysis.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the pipeline with configuration.
        
        Args:
            config: Optional configuration dictionary. If None, uses default config.
        """
        self.config = config or get_config()
        self.logger = logging.getLogger('cnascorecard.pipeline')
        
        # Initialize pipeline state
        self.cve_records: List[Dict[str, Any]] = []
        self.filtered_cve_records: List[Dict[str, Any]] = []
        self.scored_cves: List[Dict[str, Any]] = []
        self.cna_outputs: Dict[str, Any] = {}
        self.analysis_periods: Dict[str, Tuple[str, str]] = {}
        
        self.logger.info("CNA Scorecard Pipeline initialized")
    
    def run(
        self, 
        start_date: Optional[str] = None, 
        end_date: Optional[str] = None,
        output_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run the complete CNA Scorecard pipeline.
        
        Args:
            start_date: Start date for analysis in YYYY-MM-DD format
            end_date: End date for analysis in YYYY-MM-DD format
            output_dir: Output directory for generated files
            
        Returns:
            Dictionary containing pipeline execution summary
            
        Raises:
            PipelineError: If pipeline execution fails
        """
        try:
            self.logger.info("Starting CNA Scorecard Pipeline execution")
            start_time = datetime.now()
            
            # Step 1: Setup analysis periods
            self._setup_analysis_periods(start_date, end_date)
            
            # Step 2: Sync CNA metadata
            self._sync_cna_metadata()
            
            # Step 3: Load CVE data
            self._load_cve_data()
            
            # Step 4: Score CVE records
            self._score_cve_records()
            
            # Step 5: Aggregate CNA scores
            self._aggregate_cna_scores()
            
            # Step 6: Generate completeness analysis
            self._generate_completeness_analysis()
            
            # Step 7: Generate performance trends analysis
            self._generate_trends_analysis()
            
            # Step 8: Generate output files
            output_summary = self._generate_output_files(output_dir)
            
            # Calculate execution time
            execution_time = datetime.now() - start_time
            
            # Create execution summary
            summary = {
                'execution_time': str(execution_time),
                'analysis_period': self.analysis_periods['current'],
                'total_cves_processed': len(self.cve_records),
                'filtered_cves_count': len(self.filtered_cve_records),
                'scored_cves_count': len(self.scored_cves),
                'cnas_processed': len(self.cna_outputs),
                'output_files': output_summary,
                'status': 'success'
            }
            
            self.logger.info(f"Pipeline execution completed successfully in {execution_time}")
            return summary
            
        except Exception as e:
            self.logger.error(f"Pipeline execution failed: {e}")
            raise PipelineError(f"Pipeline execution failed: {e}") from e
    
    def _setup_analysis_periods(
        self, 
        start_date: Optional[str], 
        end_date: Optional[str]
    ) -> None:
        """
        Setup analysis periods for current and previous periods.
        
        Args:
            start_date: Optional start date override
            end_date: Optional end date override
        """
        self.logger.info("Setting up analysis periods")
        
        if start_date and end_date:
            # Use provided dates
            if not validate_date_range(start_date, end_date):
                raise PipelineError(f"Invalid date range: {start_date} to {end_date}")
            
            current_start, current_end = start_date, end_date
        else:
            # Use default period (last 6 months)
            current_start, current_end = get_date_range_for_period(ANALYSIS_PERIOD_MONTHS)
        
        # Calculate previous period for trend analysis
        start_dt = datetime.strptime(current_start, "%Y-%m-%d")
        end_dt = datetime.strptime(current_end, "%Y-%m-%d")
        period_length = end_dt - start_dt
        
        previous_end = start_dt - timedelta(days=1)
        previous_start = previous_end - period_length
        
        self.analysis_periods = {
            'current': (current_start, current_end),
            'previous': (
                previous_start.strftime("%Y-%m-%d"),
                previous_end.strftime("%Y-%m-%d")
            )
        }
        
        self.logger.info(f"Current analysis period: {current_start} to {current_end}")
        self.logger.info(f"Previous analysis period: {previous_start.strftime('%Y-%m-%d')} to {previous_end.strftime('%Y-%m-%d')}")
    
    def _sync_cna_metadata(self) -> None:
        """
        Sync CNA metadata from official CVE Project repository.
        
        This ensures we have the latest official CNA list for proper
        name mapping and metadata enrichment.
        """
        self.logger.info("Syncing CNA metadata from official CVE Project repository")
        
        try:
            sync_success = sync_cna_list()
            if sync_success:
                self.logger.info("Successfully synced CNA metadata")
            else:
                self.logger.warning("CNA metadata sync failed, continuing with existing data")
        except Exception as e:
            self.logger.warning(f"CNA metadata sync failed: {e}, continuing with existing data")
    
    def _load_cve_data(self) -> None:
        """Load CVE data for analysis."""
        self.logger.info("Loading CVE data")
        
        # Load all CVE records (needed for trend analysis)
        self.cve_records = load_cve_records()
        self.logger.info(f"Loaded {len(self.cve_records)} total CVE records")
        
        # Filter CVE records for current analysis period
        current_start, current_end = self.analysis_periods['current']
        self.filtered_cve_records = load_cve_records(
            start_date=current_start,
            end_date=current_end
        )
        self.logger.info(f"Filtered to {len(self.filtered_cve_records)} CVE records for current period")
        
        if not self.filtered_cve_records:
            raise PipelineError("No CVE records found for the specified analysis period")
    
    def _score_cve_records(self) -> None:
        """Score CVE records using the CNA Scorecard methodology."""
        self.logger.info("Scoring CVE records")
        
        self.scored_cves = score_multiple_cves(self.filtered_cve_records)
        
        if not self.scored_cves:
            raise PipelineError("No CVE records could be scored")
        
        # Log scoring statistics
        total_score = sum(cve['totalScore'] for cve in self.scored_cves)
        avg_score = total_score / len(self.scored_cves) if self.scored_cves else 0
        
        self.logger.info(f"Scored {len(self.scored_cves)} CVE records")
        self.logger.info(f"Average CVE score: {avg_score:.2f}/100")
    
    def _aggregate_cna_scores(self) -> None:
        """Aggregate scores by CNA and calculate trends."""
        self.logger.info("Aggregating CNA scores")
        
        # Create period tuples for aggregation
        current_period = tuple(
            datetime.strptime(date, "%Y-%m-%d") 
            for date in self.analysis_periods['current']
        )
        previous_period = tuple(
            datetime.strptime(date, "%Y-%m-%d") 
            for date in self.analysis_periods['previous']
        )
        
        periods = [current_period, previous_period]
        
        self.cna_outputs = aggregate_cna_scores(self.scored_cves, periods)
        
        self.logger.info(f"Aggregated scores for {len(self.cna_outputs)} CNAs")
    
    def _generate_completeness_analysis(self) -> None:
        """Generate field completeness analysis."""
        self.logger.info("Generating completeness analysis")
        
        # Generate overall field utilization
        field_list = self.config['fields']['field_list']
        self.field_utilization = compute_field_utilization(
            self.filtered_cve_records, 
            field_list
        )
        
        # Generate individual CNA field utilization
        self.individual_cna_utilization = compute_individual_cna_field_utilization(
            self.filtered_cve_records,
            field_list
        )
        
        self.logger.info(f"Generated completeness analysis for {len(field_list)} fields")
        self.logger.info(f"Generated individual analysis for {len(self.individual_cna_utilization)} CNAs")
    
    def _generate_trends_analysis(self) -> None:
        """Generate performance trends analysis for the dashboard."""
        self.logger.info("Generating performance trends analysis...")
        
        # Calculate daily trends with 7-day rolling averages
        self.trends_data = calculate_daily_trends(
            self.filtered_cve_records,
            Path(self.config.get('web_output_dir', '../web/data')),
            analysis_days=180  # 6 months
        )
        
        # Calculate top improving CNAs
        self.top_improvers = calculate_top_improvers(
            self.filtered_cve_records,
            Path(self.config.get('web_output_dir', '../web/data')),
            top_n=10
        )
        
        self.logger.info(f"Generated trends analysis with {len(self.trends_data['rolling_trends'])} data points")
        self.logger.info(f"Identified {len(self.top_improvers)} improving CNAs")
    
    def _generate_output_files(self, output_dir: Optional[str] = None) -> Dict[str, str]:
        """
        Generate all output files.
        
        Args:
            output_dir: Optional output directory override
            
        Returns:
            Dictionary mapping output type to file path
        """
        self.logger.info("Generating output files")
        
        if output_dir:
            web_data_dir = Path(output_dir)
        else:
            web_data_dir = Path(self.config['directories']['web_data'])
        
        ensure_directory_exists(web_data_dir)
        
        output_files = {}
        
        # Generate individual CNA JSON files
        output_files.update(self._generate_individual_cna_files(web_data_dir))
        
        # Generate summary files
        output_files.update(self._generate_summary_files(web_data_dir))
        
        # Generate completeness files
        output_files.update(self._generate_completeness_files(web_data_dir))
        
        self.logger.info(f"Generated {len(output_files)} output files")
        return output_files
    
    def _generate_individual_cna_files(self, output_dir: Path) -> Dict[str, str]:
        """Generate individual CNA JSON files matching original format exactly."""
        self.logger.info("Generating individual CNA files")
        
        # Load official CNA metadata for proper formatting
        import os, json
        cna_list_path = output_dir / 'cna_list.json'
        official_cna_metadata = {}
        if os.path.exists(cna_list_path):
            with open(cna_list_path, 'r') as f:
                cna_list_data = json.load(f)
                official_cna_metadata = {meta.get('shortName'): meta for meta in cna_list_data if meta.get('shortName')}
        
        cna_dir = output_dir / "cna"
        ensure_directory_exists(cna_dir)
        
        output_files = {}
        progress = ProgressTracker(len(self.cna_outputs), "Generating CNA files")
        
        # Calculate active CNA count for ranking
        active_cna_count = sum(1 for cna_data in self.cna_outputs.values() 
                              if cna_data['cna_scoring'][0].get('recent_cves_count', 0) > 0)
        
        # Sort CNAs by score for ranking
        sorted_cnas = []
        for cna_name, cna_data in self.cna_outputs.items():
            if cna_data['cna_info'] and cna_data['cna_scoring']:
                cna_scoring = cna_data['cna_scoring'][0]
                recent_cves = cna_scoring.get('recent_cves_count', 0)
                if recent_cves > 0:  # Only include active CNAs
                    sorted_cnas.append((cna_name, cna_data, cna_scoring.get('overall_average_score', 0.0)))
        
        # Sort by score descending for ranking
        sorted_cnas.sort(key=lambda x: x[2], reverse=True)
        
        # Create rank mapping
        rank_mapping = {}
        current_rank = 1
        for i, (cna_name, _, score) in enumerate(sorted_cnas):
            if i > 0 and sorted_cnas[i-1][2] != score:
                current_rank = i + 1
            rank_mapping[cna_name] = current_rank
        
        for cna_name, cna_data in self.cna_outputs.items():
            try:
                # Create safe filename
                safe_filename = ''.join(
                    c for c in cna_name 
                    if c.isalnum() or c in ('-', '_', '.')
                ).rstrip()
                
                if not safe_filename:
                    safe_filename = "unknown_cna"
                
                filename = f"{safe_filename}.json"
                filepath = cna_dir / filename
                
                # Get official metadata
                official_meta = official_cna_metadata.get(cna_name, {})
                
                # Get CNA info and scoring data
                cna_info = cna_data['cna_info'][0] if cna_data['cna_info'] else {}
                cna_scoring = cna_data['cna_scoring'][0] if cna_data['cna_scoring'] else {}
                
                # Calculate rank and percentile
                cna_rank = rank_mapping.get(cna_name, 0)
                percentile = ((active_cna_count - cna_rank + 1) / active_cna_count) * 100.0 if cna_rank > 0 else 0.0
                
                # Get recent CVEs with proper scoring details from cve_scoring data
                recent_cves = []
                if 'cve_scoring' in cna_data and cna_data['cve_scoring']:
                    for cve_data in cna_data['cve_scoring']:
                        # Create properly formatted CVE entry matching original structure
                        recent_cve = {
                            "cveId": cve_data.get('cveId', ''),
                            "assigningCna": cve_data.get('assigningCna', cna_name),
                            "datePublished": cve_data.get('datePublished', ''),
                            "totalCveScore": cve_data.get('totalCveScore', 0),
                            "scoreBreakdown": {
                                "foundationalCompleteness": cve_data.get('scoreBreakdown', {}).get('foundationalCompleteness', 0),
                                "rootCauseAnalysis": cve_data.get('scoreBreakdown', {}).get('rootCauseAnalysis', 0),
                                "severityAndImpactContext": cve_data.get('scoreBreakdown', {}).get('severityAndImpactContext', 0),
                                "softwareIdentification": cve_data.get('scoreBreakdown', {}).get('softwareIdentification', 0),
                                "patchinfo": cve_data.get('scoreBreakdown', {}).get('patchinfo', 0)
                            }
                        }
                        recent_cves.append(recent_cve)
                
                # Format individual CNA file in original structure
                individual_cna_data = {
                    "cna_info": {
                        "cna": cna_name,
                        "total_cves": cna_info.get('total_cves', 0),
                        "total_cves_scored": cna_scoring.get('total_cves_scored', 0),
                        "organizationName": official_meta.get('organizationName', cna_name),
                        "scope": official_meta.get('scope', ''),
                        "advisories": official_meta.get('advisories', []),
                        "email": official_meta.get('email', []),
                        "officialCnaID": official_meta.get('cnaID', ''),
                        "cnaTypes": official_meta.get('type', ['Unknown']),
                        "country": official_meta.get('country', ''),
                        "disclosurePolicy": official_meta.get('disclosurePolicy', []),
                        "rootCnaInfo": {}
                    },
                    "trend_direction": cna_scoring.get('trend_direction', 'steady'),
                    "trend_description": cna_scoring.get('trend_description', 'No trend data available'),
                    "rank": cna_rank,
                    "active_cna_count": active_cna_count,
                    "percentile": round(percentile, 1),
                    "cna_scoring": [cna_scoring],
                    "recent_cves": recent_cves
                }
                
                # Write CNA data to file
                write_json_file(individual_cna_data, filepath)
                output_files[f"cna_{safe_filename}"] = str(filepath)
                
            except Exception as e:
                self.logger.error(f"Failed to generate file for CNA {cna_name}: {e}")
            finally:
                progress.update()
        return output_files
    
    def _generate_summary_files(self, output_dir: Path) -> Dict[str, str]:
        """
        Generate summary files for web interface matching original format exactly.
        
        Args:
            output_dir: Output directory path
            
        Returns:
            Dictionary mapping file types to file paths
        """
        output_files = {}
        
        # Load official CNA metadata for proper formatting
        import os, json
        cna_list_path = output_dir / 'cna_list.json'
        official_cna_metadata = {}
        if os.path.exists(cna_list_path):
            with open(cna_list_path, 'r') as f:
                cna_list_data = json.load(f)
                official_cna_metadata = {meta.get('shortName'): meta for meta in cna_list_data if meta.get('shortName')}
        
        # Generate CNA combined rankings file in original format
        web_formatted_cnas = []
        active_cna_count = sum(1 for cna_data in self.cna_outputs.values() 
                              if cna_data['cna_scoring'][0].get('recent_cves_count', 0) > 0)
        
        # Sort CNAs by score for ranking
        sorted_cnas = []
        for cna_name, cna_data in self.cna_outputs.items():
            if cna_data['cna_info'] and cna_data['cna_scoring']:
                cna_info = cna_data['cna_info'][0]
                cna_scoring = cna_data['cna_scoring'][0]
                recent_cves = cna_scoring.get('recent_cves_count', 0)
                if recent_cves > 0:  # Only include active CNAs
                    sorted_cnas.append((cna_name, cna_data, cna_scoring.get('overall_average_score', 0.0)))
        
        # Sort by score descending
        sorted_cnas.sort(key=lambda x: x[2], reverse=True)
        
        # Calculate ranks with proper tie handling
        current_rank = 1
        for i, (cna_name, cna_data, score) in enumerate(sorted_cnas):
            # Handle tied rankings
            if i > 0 and sorted_cnas[i-1][2] != score:
                current_rank = i + 1
            
            cna_info = cna_data['cna_info'][0]
            cna_scoring = cna_data['cna_scoring'][0]
            
            # Get official metadata
            official_meta = official_cna_metadata.get(cna_name, {})
            
            # Determine CNA type
            types = official_meta.get('type', [])
            if types and len(types) > 0:
                valid_types = [t for t in types if t and t.strip() and t.strip().upper() != 'N/A']
                if valid_types:
                    primary_type, types_array = valid_types[0], valid_types
                else:
                    primary_type, types_array = 'Unknown', ['Unknown']
            else:
                primary_type, types_array = 'Unknown', ['Unknown']
            
            # Calculate percentile
            percentile = ((active_cna_count - current_rank + 1) / active_cna_count) * 100.0
            
            web_cna = {
                "shortName": cna_name,
                "organizationName": official_meta.get('organizationName', cna_name),
                "cnaType": primary_type,
                "cnaTypes": types_array,
                "rank": current_rank,
                "active_cna_count": active_cna_count,
                "percentile": round(percentile, 1),
                "total_cves": cna_info.get('total_cves', 0),
                "recent_cves": cna_scoring.get('recent_cves_count', 0),
                "is_active": True,
                "scores": {
                    "overall_average_score": cna_scoring.get('overall_average_score', 0),
                    "foundational_completeness": cna_scoring.get('percent_foundational_completeness', 0),
                    "root_cause_analysis": cna_scoring.get('percent_root_cause_analysis', 0),
                    "software_identification": cna_scoring.get('percent_software_identification', 0),
                    "severity_and_impact": cna_scoring.get('percent_severity_and_impact', 0),
                    "patchinfo": cna_scoring.get('percent_patchinfo', 0)
                },
                "trend": {
                    "direction": cna_scoring.get('trend_direction', 'steady'),
                    "description": cna_scoring.get('trend_description', 'No trend data available'),
                    "monthly_data": cna_scoring.get('monthly_trends', [])
                },
                "scope": official_meta.get('scope', ''),
                "advisories": official_meta.get('advisories', []),
                "officialCnaID": official_meta.get('cnaID', ''),
                "country": official_meta.get('country', ''),
                "disclosurePolicy": official_meta.get('disclosurePolicy', [])
            }
            
            web_formatted_cnas.append(web_cna)
        
        cna_combined_path = output_dir / 'cna_combined.json'
        write_json_file(web_formatted_cnas, cna_combined_path)
        output_files['cna_combined'] = str(cna_combined_path)
        
        # Generate cna_summary.json for completeness page
        cna_summary_list = []
        for cna_name, cna_data in self.cna_outputs.items():
            if cna_data['cna_info'] and cna_data['cna_scoring']:
                cna_info = cna_data['cna_info'][0]
                cna_scoring = cna_data['cna_scoring'][0]
                official_meta = official_cna_metadata.get(cna_name, {})
                
                summary_entry = {
                    "cnaId": official_meta.get('cnaID', ''),
                    "shortName": cna_name,
                    "overallScore": cna_scoring.get('overall_average_score', 0),
                    "grade": self._calculate_grade(cna_scoring.get('overall_average_score', 0)),
                    "previousPeriodCveCount": 0,  # Placeholder for trend data
                    "cveCount": cna_scoring.get('recent_cves_count', 0),
                    "type": official_meta.get('type', ['Unknown'])[0] if official_meta.get('type') else 'Unknown',
                    "trend": cna_scoring.get('trend_direction', 'steady')
                }
                cna_summary_list.append(summary_entry)
        
        # Sort by overall score descending
        cna_summary_list.sort(key=lambda x: x['overallScore'], reverse=True)
        
        cna_summary_path = output_dir / 'cna_summary.json'
        write_json_file(cna_summary_list, cna_summary_path)
        output_files['cna_summary'] = str(cna_summary_path)
        
        # Generate completeness summary
        completeness_summary = {
            'analysis_period': f"{self.analysis_periods['current'][0]} to {self.analysis_periods['current'][1]}",
            'total_cves_analyzed': len(self.filtered_cve_records),
            'total_fields_analyzed': len(self.field_utilization) if hasattr(self, 'field_utilization') else 0
        }
        
        summary_path = output_dir / 'completeness_summary.json'
        write_json_file(completeness_summary, summary_path)
        output_files['completeness_summary'] = str(summary_path)
        
        return output_files
    
    def _generate_completeness_files(self, output_dir: Path) -> Dict[str, str]:
        """Generate completeness analysis files."""
        self.logger.info("Generating completeness files")
        
        output_files = {}
        
        # Generate enhanced field utilization data
        canonical_fields = self.config['fields']['canonical_fields']
        enhanced_field_data = []
        
        for field_data in self.field_utilization:
            field_name = field_data['field']
            field_metadata = next(
                (f for f in canonical_fields if f['field'] == field_name), 
                {}
            )
            
            enhanced_entry = {
                'field': field_name,
                'percent': field_data['cna_percent'],
                'unique_cnas': field_data['unique_cnas'],
                'importance': field_metadata.get('importance', 'Medium'),
                'description': field_metadata.get('description', ''),
                'cna_scorecard_category': field_metadata.get('cna_scorecard_category')
            }
            enhanced_field_data.append(enhanced_entry)
        
        # Write field utilization file
        field_util_path = output_dir / "field_utilization.json"
        write_json_file(enhanced_field_data, field_util_path)
        output_files['field_utilization'] = str(field_util_path)
        
        # Generate individual CNA completeness files
        completeness_dir = output_dir / "completeness"
        ensure_directory_exists(completeness_dir)
        
        for cna_name, utilization_data in self.individual_cna_utilization.items():
            safe_filename = "".join(
                c for c in cna_name 
                if c.isalnum() or c in ('-', '_', '.')
            ).rstrip()
            
            if not safe_filename:
                safe_filename = "unknown_cna"
            
            filename = f"{safe_filename}_completeness.json"
            filepath = completeness_dir / filename
            
            write_json_file(utilization_data, filepath)
            output_files[f"completeness_{safe_filename}"] = str(filepath)
        
        return output_files
    
    def _calculate_grade(self, score: float) -> str:
        """
        Calculate letter grade from numerical score.
        
        Args:
            score: Numerical score (0-100)
            
        Returns:
            Letter grade (A+, A, B+, etc.)
        """
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "B+"
        elif score >= 80:
            return "B"
        elif score >= 75:
            return "C+"
        elif score >= 70:
            return "C"
        elif score >= 65:
            return "D+"
        elif score >= 60:
            return "D"
        else:
            return "F"


def main() -> None:
    """
    Main entry point for the CNA Scorecard Pipeline.
    
    This function sets up logging and runs the complete pipeline.
    """
    import argparse
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(
        description="CNA Scorecard Data Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pipeline.py                           # Run with default 6-month period
  python pipeline.py --start 2024-01-01 --end 2024-12-31  # Custom date range
  python pipeline.py --output /custom/output   # Custom output directory
  python pipeline.py --log-level DEBUG         # Enable debug logging
        """
    )
    
    parser.add_argument(
        '--start-date', 
        help='Start date for analysis (YYYY-MM-DD format)'
    )
    parser.add_argument(
        '--end-date', 
        help='End date for analysis (YYYY-MM-DD format)'
    )
    parser.add_argument(
        '--output-dir', 
        help='Output directory for generated files'
    )
    parser.add_argument(
        '--log-level', 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    parser.add_argument(
        '--config-file',
        help='Path to custom configuration file'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    try:
        # Load configuration
        config = None
        if args.config_file:
            from utils import load_json_file
            config = load_json_file(Path(args.config_file))
        
        # Initialize and run pipeline
        pipeline = CNAScoreCardPipeline(config)
        
        summary = pipeline.run(
            start_date=args.start_date,
            end_date=args.end_date,
            output_dir=args.output_dir
        )
        
        # Print execution summary
        logger.info("Pipeline Execution Summary:")
        logger.info(f"  Status: {summary['status']}")
        logger.info(f"  Execution Time: {summary['execution_time']}")
        logger.info(f"  Analysis Period: {summary['analysis_period'][0]} to {summary['analysis_period'][1]}")
        logger.info(f"  CVEs Processed: {summary['total_cves_processed']}")
        logger.info(f"  CVEs in Analysis Period: {summary['filtered_cves_count']}")
        logger.info(f"  CVEs Scored: {summary['scored_cves_count']}")
        logger.info(f"  CNAs Processed: {summary['cnas_processed']}")
        logger.info(f"  Output Files Generated: {len(summary['output_files'])}")
        
        logger.info("CNA Scorecard Pipeline completed successfully!")
        
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        raise


if __name__ == "__main__":
    main()
