#!/usr/bin/env python3
"""
CVE Description Quality Analysis Test

This script analyzes 10,000 recent CVE descriptions using the Enhanced Aggregate 
Scoring (EAS) methodology to evaluate and improve the description quality algorithm.
"""

import sys
import os
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter, defaultdict
import statistics

# Add the parent directory to the path to import cnascorecard modules
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from cnascorecard.data_ingestor import get_cve_records
    # EAS Scorer may not exist yet, we'll implement our own for testing
    EAS_SCORER_AVAILABLE = True
except ImportError as e:
    print(f"❌ Error importing cnascorecard modules: {e}")
    print("Make sure you're running this from the project root or the modules exist.")
    sys.exit(1)

# Optional ML libraries for advanced analysis
try:
    import numpy as np
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA
    import matplotlib.pyplot as plt
    import seaborn as sns
    try:
        from textblob import TextBlob
        TEXTBLOB_AVAILABLE = True
    except ImportError:
        TEXTBLOB_AVAILABLE = False
    ML_AVAILABLE = True
    print("✅ ML libraries available - advanced analysis enabled")
except ImportError:
    ML_AVAILABLE = False
    TEXTBLOB_AVAILABLE = False
    print("⚠️  ML libraries not available - basic analysis only")

class DescriptionQualityAnalyzer:
    """Analyzes CVE description quality using the EAS methodology."""
    
    def __init__(self):
        # We'll implement our own scoring logic for testing
        self.analysis_results = {}
        
    def extract_description(self, cve_data):
        """Extract description from CVE data with error handling"""
        try:
            # Handle different possible data structures
            if isinstance(cve_data, dict):
                # Try different possible paths for description
                descriptions = []
                
                # Path 1: cve.description.description_data
                if 'cve' in cve_data and isinstance(cve_data['cve'], dict) and 'description' in cve_data['cve']:
                    desc_data = cve_data['cve']['description']
                    if isinstance(desc_data, dict) and 'description_data' in desc_data:
                        desc_list = desc_data['description_data']
                        if isinstance(desc_list, list):
                            for desc in desc_list:
                                if isinstance(desc, dict) and desc.get('lang') == 'en':
                                    descriptions.append(desc.get('value', ''))
                
                # Path 2: description.description_data (direct)
                elif 'description' in cve_data and isinstance(cve_data['description'], dict):
                    desc_data = cve_data['description']
                    if 'description_data' in desc_data:
                        desc_list = desc_data['description_data']
                        if isinstance(desc_list, list):
                            for desc in desc_list:
                                if isinstance(desc, dict) and desc.get('lang') == 'en':
                                    descriptions.append(desc.get('value', ''))
                
                # Path 3: containers.cna.descriptions
                elif 'containers' in cve_data and isinstance(cve_data['containers'], dict) and 'cna' in cve_data['containers']:
                    cna_data = cve_data['containers']['cna']
                    if isinstance(cna_data, dict) and 'descriptions' in cna_data:
                        desc_list = cna_data['descriptions']
                        if isinstance(desc_list, list):
                            for desc in desc_list:
                                if isinstance(desc, dict) and desc.get('lang') == 'en':
                                    descriptions.append(desc.get('value', ''))
                
                # Return first valid description
                for desc in descriptions:
                    if desc and desc.strip():
                        return desc.strip()
                        
            elif isinstance(cve_data, str):
                return cve_data.strip() if cve_data.strip() else None
                        
            return None
            
        except Exception as e:
            # Don't print the warning for every single failure
            return None
    
    def analyze_description_quality(self, description):
        """Analyze description quality using enhanced metrics."""
        if not description:
            return {
                'score': 0,
                'length': 0,
                'components': {
                    'length_structure': 0,
                    'technical_types': 0,
                    'impact_context': 0,
                    'technical_specificity': 0,
                    'generic_penalty': 0
                },
                'metrics': {}
            }
        
        desc_lower = description.lower()
        score = 0
        components = {}
        metrics = {}
        
        # Length and structure (3 points max)
        length_score = 0
        if len(description) >= 50: length_score += 1
        if len(description) >= 100: length_score += 1
        if len(description) >= 200: length_score += 1
        components['length_structure'] = length_score
        score += length_score
        
        # Technical vulnerability types (4 points max)
        # Technical vulnerability types (4 points max)
        vuln_types = [
            'file inclusion', 'sql injection', 'access control', 'local file inclusion',
            'remote file inclusion', 'cross-site scripting', 'command injection', 
            'buffer overflow', 'sanitization', 'authentication bypass',
            'null pointer dereference', 'path traversal', 'improper validation',
            'xss', 'denial of service', 'out-of-bounds', 'code injection',
            'privilege escalation', 'xml external entity', 'double free',
            'use after free', 'race condition', 'integer overflow', 'format string',
            'heap overflow', 'stack overflow', 'type confusion', 'memory corruption',
            'deserialization', 'directory traversal', 'xxe', 'server-side request forgery',
            'ssrf', 'csrf', 'cross-site request forgery', 'remote code execution',
            'arbitrary code execution', 'prototype pollution', 'insecure deserialization',
            'ldap injection', 'xpath injection', 'template injection', 'header injection',
            'clickjacking', 'certificate validation', 'weak encryption', 'cryptographic',
            'resource exhaustion', 'infinite loop', 'zip slip', 'business logic',
            'improper input validation', 'missing authentication', 'weak authentication',
            'logic error'
        ]
        vuln_matches = sum(1 for vtype in vuln_types if vtype in desc_lower)
        tech_score = min(4, vuln_matches * 2)
        components['technical_types'] = tech_score
        score += tech_score
        
        # Impact/exploitation context (4 points max)
        impact_terms = [
            'leads to', 'disclose', 'execute arbitrary', 'arbitrary code execution', 
            'remote attackers', 'authenticated attackers', 'allows', 'bypass',
            'can be exploited', 'remote code execution', 'unauthenticated attackers',
            'attackers can', 'results in', 'manipulate', 'obtain', 'compromise',
            'gain access', 'unauthorized access', 'enables', 'permits', 'facilitates',
            'triggers', 'may allow', 'could allow', 'escalate privileges', 'circumvent',
            'retrieve', 'expose', 'information disclosure', 'data exposure',
            'sensitive information', 'leak', 'reveal', 'crash', 'hang', 'freeze',
            'terminate', 'local attackers', 'malicious users', 'crafted',
            'specially crafted', 'malicious', 'attacker', 'exploitation',
            'exploitable', 'when processing', 'during processing', 'via the'
        ]
        impact_matches = sum(1 for term in impact_terms if term in desc_lower)
        impact_score = min(4, impact_matches)
        components['impact_context'] = impact_score
        score += impact_score
        
        # Technical specificity (4 points max)
        tech_terms = [
            'function', 'parameter', 'api', 'endpoint', 'module',
            'component', 'library', 'service', 'method', 'routine',
            'handler', 'parser', 'application', 'when processing',
            'variable', 'field', 'header', 'request', 'response',
            'protocol', 'interface', 'object', 'class', 'property',
            'argument', 'buffer', 'stream', 'connection', 'socket',
            'channel', 'thread', 'process'
        ]
        tech_matches = sum(1 for term in tech_terms if term in desc_lower)
        spec_score = min(4, tech_matches)
        components['technical_specificity'] = spec_score
        score += spec_score
        
        # Generic content penalty (max -2 points)
        generic_phrases = [
            'security vulnerability', 'vulnerability exists', 'may allow',
            'could allow', 'potential vulnerability', 'security issue',
            'security flaw', 'weakness'
        ]
        generic_count = sum(1 for phrase in generic_phrases if phrase in desc_lower)
        penalty = 0
        if len(description) < 100 and generic_count >= 2:
            penalty = -2
        components['generic_penalty'] = penalty
        score += penalty
        
        # Additional metrics for analysis
        metrics.update({
            'length': len(description),
            'word_count': len(description.split()),
            'sentence_count': description.count('.') + description.count('!') + description.count('?'),
            'vuln_type_matches': vuln_matches,
            'impact_matches': impact_matches,
            'tech_matches': tech_matches,
            'generic_matches': generic_count,
            'has_cve_id': 'cve-' in desc_lower,
            'has_version': any(v in desc_lower for v in ['version', 'v1.', 'v2.', '1.0', '2.0']),
            'has_product': any(p in desc_lower for p in ['apache', 'microsoft', 'google', 'oracle'])
        })
        
        return {
            'score': max(0, min(15, score)),
            'length': len(description),
            'components': components,
            'metrics': metrics
        }
    
    def analyze_cve_sample(self, cve_records, sample_size=10000):
        """Analyze a sample of CVE records."""
        print(f"🔍 Analyzing sample of {sample_size} CVE records...")
        
        # Debug: check first few CVE records to understand format
        if len(cve_records) > 0:
            print(f"First CVE record type: {type(cve_records[0])}")
            if isinstance(cve_records[0], dict):
                print(f"First CVE keys: {list(cve_records[0].keys())}")
                # Print a small sample of the structure
                import json
                print(f"First CVE structure sample: {json.dumps(cve_records[0], indent=2)[:500]}...")
            else:
                print(f"First CVE content preview: {str(cve_records[0])[:200]}...")
        
        # Randomly sample CVEs
        if len(cve_records) > sample_size:
            sample = random.sample(cve_records, sample_size)
        else:
            sample = cve_records
            print(f"Using all {len(sample)} available records")
        
        results = []
        cna_stats = defaultdict(list)
        successful_extractions = 0
        
        for i, cve in enumerate(sample):
            if i % 1000 == 0:
                print(f"  Processed {i}/{len(sample)} CVEs...")
            
            description = self.extract_description(cve)
            if description:
                successful_extractions += 1
                if successful_extractions <= 3:  # Debug first few successful extractions
                    print(f"  Successful extraction {successful_extractions}: {description[:100]}...")
                
                analysis = self.analyze_description_quality(description)
                
                # Get CNA info
                cna = self.extract_cna(cve)
                
                result = {
                    'cve_id': self.extract_cve_id(cve),
                    'cna': cna,
                    'description': description,
                    'analysis': analysis
                }
                results.append(result)
                cna_stats[cna].append(analysis['score'])
        
        print(f"✅ Analyzed {len(results)} CVEs with descriptions out of {len(sample)} total")
        print(f"Success rate: {len(results)/len(sample)*100:.1f}%")
        
        self.analysis_results = {
            'total_analyzed': len(results),
            'results': results,
            'cna_stats': dict(cna_stats)
        }
        
        return self.analysis_results
    
    def extract_cna(self, cve_data):
        """Extract CNA from CVE data."""
        try:
            # CVE 5.x format
            if isinstance(cve_data, dict) and 'cveMetadata' in cve_data:
                return cve_data['cveMetadata'].get('assignerShortName', 'Unknown')
            
            # Container format
            if isinstance(cve_data, dict) and 'containers' in cve_data:
                containers = cve_data.get('containers', [])
                if isinstance(containers, list):
                    for container in containers:
                        if isinstance(container, dict) and 'cna' in container:
                            cna = container.get('cna', {})
                            if isinstance(cna, dict) and 'assignerShortName' in cna:
                                return cna['assignerShortName']
            
            # Legacy format
            if isinstance(cve_data, dict) and 'CVE_data_meta' in cve_data:
                return cve_data['CVE_data_meta'].get('ASSIGNER', 'Unknown')
            
            return 'Unknown'
        except:
            return 'Unknown'
    
    def extract_cve_id(self, cve_data):
        """Extract CVE ID from CVE data."""
        try:
            # CVE 5.x format
            if isinstance(cve_data, dict) and 'cveMetadata' in cve_data:
                return cve_data['cveMetadata'].get('cveId', 'Unknown')
            
            # Container format
            if isinstance(cve_data, dict) and 'containers' in cve_data:
                containers = cve_data.get('containers', [])
                if isinstance(containers, list):
                    for container in containers:
                        if isinstance(container, dict) and 'cna' in container:
                            cna = container.get('cna', {})
                            if isinstance(cna, dict) and 'cveId' in cna:
                                return cna['cveId']
            
            # Legacy format
            if isinstance(cve_data, dict) and 'CVE_data_meta' in cve_data:
                return cve_data['CVE_data_meta'].get('ID', 'Unknown')
            
            # Try direct cveId field
            if isinstance(cve_data, dict) and 'cveId' in cve_data:
                return cve_data['cveId']
            
            return 'Unknown'
        except:
            return 'Unknown'
    
    def generate_statistics_report(self):
        """Generate comprehensive statistics report."""
        if not self.analysis_results:
            return "No analysis results available"
        
        results = self.analysis_results['results']
        
        if not results:
            return "No CVE descriptions were successfully analyzed. Check the CVE data format and extraction logic."
        
        scores = [r['analysis']['score'] for r in results]
        
        report = []
        report.append("=" * 60)
        report.append("CVE DESCRIPTION QUALITY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Total CVEs Analyzed: {len(results)}")
        report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Overall score distribution
        report.append("📊 OVERALL SCORE DISTRIBUTION")
        report.append("-" * 30)
        report.append(f"Mean Score: {statistics.mean(scores):.2f}/15")
        report.append(f"Median Score: {statistics.median(scores):.2f}/15")
        report.append(f"Standard Deviation: {statistics.stdev(scores) if len(scores) > 1 else 0:.2f}")
        report.append(f"Min Score: {min(scores):.1f}")
        report.append(f"Max Score: {max(scores):.1f}")
        report.append("")
        
        # Score categories
        excellent = sum(1 for s in scores if s >= 12)
        good = sum(1 for s in scores if 8 <= s < 12)
        fair = sum(1 for s in scores if 4 <= s < 8)
        poor = sum(1 for s in scores if s < 4)
        
        report.append("🎯 QUALITY CATEGORIES")
        report.append("-" * 20)
        report.append(f"Excellent (12-15): {excellent} ({excellent/len(scores)*100:.1f}%)")
        report.append(f"Good (8-11): {good} ({good/len(scores)*100:.1f}%)")
        report.append(f"Fair (4-7): {fair} ({fair/len(scores)*100:.1f}%)")
        report.append(f"Poor (0-3): {poor} ({poor/len(scores)*100:.1f}%)")
        report.append("")
        
        # Component analysis
        components = ['length_structure', 'technical_types', 'impact_context', 'technical_specificity']
        report.append("🔧 COMPONENT PERFORMANCE")
        report.append("-" * 25)
        for comp in components:
            comp_scores = [r['analysis']['components'][comp] for r in results]
            avg = statistics.mean(comp_scores)
            report.append(f"{comp.replace('_', ' ').title()}: {avg:.2f}")
        report.append("")
        
        # Length analysis
        lengths = [r['analysis']['metrics']['length'] for r in results]
        report.append("📏 DESCRIPTION LENGTH ANALYSIS")
        report.append("-" * 30)
        report.append(f"Average Length: {statistics.mean(lengths):.0f} characters")
        report.append(f"Median Length: {statistics.median(lengths):.0f} characters")
        
        short = sum(1 for l in lengths if l < 50)
        medium = sum(1 for l in lengths if 50 <= l < 200)
        long = sum(1 for l in lengths if l >= 200)
        
        report.append(f"Short (<50 chars): {short} ({short/len(lengths)*100:.1f}%)")
        report.append(f"Medium (50-199): {medium} ({medium/len(lengths)*100:.1f}%)")
        report.append(f"Long (≥200): {long} ({long/len(lengths)*100:.1f}%)")
        report.append("")
        
        # Top/Bottom CNAs
        cna_stats = self.analysis_results['cna_stats']
        cna_averages = {cna: statistics.mean(scores) for cna, scores in cna_stats.items() if len(scores) >= 5}
        
        if cna_averages:
            report.append("🏆 TOP PERFORMING CNAs (≥5 CVEs)")
            report.append("-" * 35)
            top_cnas = sorted(cna_averages.items(), key=lambda x: x[1], reverse=True)[:10]
            for i, (cna, avg) in enumerate(top_cnas, 1):
                count = len(cna_stats[cna])
                report.append(f"{i:2d}. {cna}: {avg:.2f} (n={count})")
            report.append("")
            
            report.append("📉 BOTTOM PERFORMING CNAs (≥5 CVEs)")
            report.append("-" * 38)
            bottom_cnas = sorted(cna_averages.items(), key=lambda x: x[1])[:10]
            for i, (cna, avg) in enumerate(bottom_cnas, 1):
                count = len(cna_stats[cna])
                report.append(f"{i:2d}. {cna}: {avg:.2f} (n={count})")
            report.append("")
        
        # Sample descriptions by quality
        report.append("📝 SAMPLE DESCRIPTIONS BY QUALITY")
        report.append("-" * 35)
        
        # Excellent examples
        excellent_examples = [r for r in results if r['analysis']['score'] >= 12]
        if excellent_examples:
            example = random.choice(excellent_examples)
            report.append("EXCELLENT (Score: 12-15):")
            report.append(f"CVE: {example['cve_id']}")
            report.append(f"Score: {example['analysis']['score']}/15")
            report.append(f"Description: {example['description'][:200]}...")
            report.append("")
        
        # Poor examples
        poor_examples = [r for r in results if r['analysis']['score'] < 4]
        if poor_examples:
            example = random.choice(poor_examples)
            report.append("POOR (Score: 0-3):")
            report.append(f"CVE: {example['cve_id']}")
            report.append(f"Score: {example['analysis']['score']}/15")
            report.append(f"Description: {example['description']}")
            report.append("")
        
        return "\n".join(report)
    
    def generate_ml_analysis(self):
        """Generate ML-based analysis if libraries are available."""
        if not ML_AVAILABLE or not self.analysis_results:
            return "ML analysis not available"
        
        results = self.analysis_results['results']
        descriptions = [r['description'] for r in results]
        scores = [r['analysis']['score'] for r in results]
        
        report = []
        report.append("🤖 MACHINE LEARNING ANALYSIS")
        report.append("=" * 35)
        
        try:
            # TF-IDF Analysis
            vectorizer = TfidfVectorizer(
                max_features=100,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=5
            )
            
            tfidf_matrix = vectorizer.fit_transform(descriptions)
            feature_names = vectorizer.get_feature_names_out()
            
            # Correlation between terms and scores
            term_scores = defaultdict(list)
            
            # Simple approach: check if each term appears in each description
            for i, desc in enumerate(descriptions):
                desc_lower = desc.lower()
                for term in feature_names:
                    if term in desc_lower:
                        term_scores[term].append(scores[i])
            
            # Top terms correlated with high scores
            term_correlations = {}
            for term, term_score_list in term_scores.items():
                if len(term_score_list) >= 10:  # At least 10 occurrences
                    avg_score = statistics.mean(term_score_list)
                    term_correlations[term] = avg_score
            
            report.append("🔍 TOP TERMS ASSOCIATED WITH HIGH SCORES:")
            top_terms = sorted(term_correlations.items(), key=lambda x: x[1], reverse=True)[:15]
            for term, avg_score in top_terms:
                count = len(term_scores[term])
                report.append(f"  '{term}': {avg_score:.2f} avg score (n={count})")
            report.append("")
            
            # Clustering analysis
            if len(descriptions) >= 100:
                report.append("🎯 CLUSTERING ANALYSIS:")
                kmeans = KMeans(n_clusters=5, random_state=42)
                clusters = kmeans.fit_predict(tfidf_matrix)
                
                cluster_scores = defaultdict(list)
                for i, cluster in enumerate(clusters):
                    cluster_scores[cluster].append(scores[i])
                
                for cluster_id in range(5):
                    cluster_score_list = cluster_scores[cluster_id]
                    if cluster_score_list:
                        avg_score = statistics.mean(cluster_score_list)
                        count = len(cluster_score_list)
                        report.append(f"  Cluster {cluster_id}: {avg_score:.2f} avg score ({count} CVEs)")
                report.append("")
            
            # Sentiment analysis (disabled due to type issues)
            # if TEXTBLOB_AVAILABLE:
            #     report.append("💭 SENTIMENT ANALYSIS:")
            #     sentiments = []
            #     for desc in descriptions[:1000]:  # Sample for performance
            #         try:
            #             blob = TextBlob(desc)
            #             sentiment = blob.sentiment
            #             sentiments.append(sentiment.polarity)
            #         except Exception:
            #             pass  # Skip problematic texts
            #     
            #     if sentiments:
            #         avg_sentiment = statistics.mean(sentiments)
            #         report.append(f"  Average sentiment: {avg_sentiment:.3f} (-1=negative, 1=positive)")
            #         report.append(f"  Neutral descriptions: {sum(1 for s in sentiments if -0.1 <= s <= 0.1)/len(sentiments)*100:.1f}%")
            #     else:
            #         report.append("  No sentiment data available")
            #     report.append("")
            
        except Exception as e:
            report.append(f"Error in ML analysis: {e}")
        
        return "\n".join(report)
    
    def generate_recommendations(self):
        """Generate recommendations for improving the scoring algorithm."""
        if not self.analysis_results:
            return "No analysis results available for recommendations"
        
        results = self.analysis_results['results']
        scores = [r['analysis']['score'] for r in results]
        
        recommendations = []
        recommendations.append("💡 ALGORITHM IMPROVEMENT RECOMMENDATIONS")
        recommendations.append("=" * 45)
        
        # Analyze score distribution
        mean_score = statistics.mean(scores)
        recommendations.append(f"Current average score: {mean_score:.2f}/15")
        recommendations.append("")
        
        # Component effectiveness
        components = ['length_structure', 'technical_types', 'impact_context', 'technical_specificity']
        comp_effectiveness = {}
        
        for comp in components:
            comp_scores = [r['analysis']['components'][comp] for r in results]
            # Calculate how often this component contributes to total score
            non_zero = sum(1 for s in comp_scores if s > 0)
            comp_effectiveness[comp] = non_zero / len(comp_scores)
        
        recommendations.append("🎯 COMPONENT EFFECTIVENESS:")
        for comp, effectiveness in sorted(comp_effectiveness.items(), key=lambda x: x[1], reverse=True):
            recommendations.append(f"  {comp.replace('_', ' ').title()}: {effectiveness*100:.1f}% of CVEs score points")
        recommendations.append("")
        
        # Specific recommendations
        recommendations.append("📋 SPECIFIC RECOMMENDATIONS:")
        recommendations.append("")
        
        # Length analysis
        lengths = [r['analysis']['metrics']['length'] for r in results]
        very_short = sum(1 for l in lengths if l < 30)
        if very_short / len(lengths) > 0.1:
            recommendations.append("1. MINIMUM LENGTH THRESHOLD:")
            recommendations.append("   - Consider requiring at least 30 characters for any points")
            recommendations.append("   - Current: 50 char threshold may be too lenient")
            recommendations.append("")
        
        # Technical specificity
        tech_matches = [r['analysis']['metrics']['tech_matches'] for r in results]
        low_tech = sum(1 for m in tech_matches if m == 0)
        if low_tech / len(tech_matches) > 0.5:
            recommendations.append("2. TECHNICAL VOCABULARY EXPANSION:")
            recommendations.append("   - Add more domain-specific terms (web, network, crypto, etc.)")
            recommendations.append("   - Include version-specific terminology")
            recommendations.append("   - Consider weighted scoring for more specific terms")
            recommendations.append("")
        
        # Impact context
        impact_matches = [r['analysis']['metrics']['impact_matches'] for r in results]
        low_impact = sum(1 for m in impact_matches if m == 0)
        if low_impact / len(impact_matches) > 0.3:
            recommendations.append("3. IMPACT SCORING REFINEMENT:")
            recommendations.append("   - Expand impact terminology")
            recommendations.append("   - Add severity-related terms (critical, high, medium)")
            recommendations.append("   - Include business impact terms")
            recommendations.append("")
        
        # Generic penalty effectiveness
        penalties = [r['analysis']['components']['generic_penalty'] for r in results]
        penalized_count = sum(1 for p in penalties if p < 0)
        if len(penalties) > 0 and penalized_count / len(penalties) < 0.05:
            recommendations.append("4. GENERIC CONTENT DETECTION:")
            recommendations.append("   - Current penalty may be too narrow")
            recommendations.append("   - Consider ML-based generic content detection")
            recommendations.append("   - Expand generic phrase list")
            recommendations.append("")
        
        # CNA-specific recommendations
        cna_stats = self.analysis_results['cna_stats']
        cna_averages = {cna: statistics.mean(cna_scores) for cna, cna_scores in cna_stats.items() if len(cna_scores) >= 10}
        
        if cna_averages:
            score_variance = statistics.stdev(list(cna_averages.values()))
            recommendations.append("5. CNA PERFORMANCE VARIANCE:")
            recommendations.append(f"   - Score variance across CNAs: {score_variance:.2f}")
            if score_variance > 3:
                recommendations.append("   - Consider CNA-specific training/guidance")
                recommendations.append("   - Implement best practice sharing")
            recommendations.append("")
        
        recommendations.append("6. OVERALL ALGORITHM TUNING:")
        if mean_score < 5:
            recommendations.append("   - Scores may be too low overall")
            recommendations.append("   - Consider adjusting component weights")
        elif mean_score > 10:
            recommendations.append("   - Scores may be too high overall")
            recommendations.append("   - Consider making criteria more stringent")
        else:
            recommendations.append("   - Current scoring distribution appears reasonable")
        
        recommendations.append("")
        recommendations.append("7. PROPOSED SCORING ADJUSTMENTS:")
        recommendations.append("   - Move from 15-point to 10-point scale for better distribution")
        recommendations.append("   - Implement progressive scoring within components")
        recommendations.append("   - Add bonus points for exceptional technical detail")
        recommendations.append("   - Consider machine learning for quality assessment")
        
        return "\n".join(recommendations)

    def load_cve_data(self, file_path):
        """Load CVE data from JSON file with debug info"""
        print(f"Loading CVE data from {file_path}...")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Debug: Print structure of first few items
            if isinstance(data, list) and len(data) > 0:
                print(f"Data is a list with {len(data)} items")
                print(f"First item type: {type(data[0])}")
                if isinstance(data[0], dict):
                    print(f"First item keys: {list(data[0].keys())[:10]}")  # Show first 10 keys
            elif isinstance(data, dict):
                print(f"Data is a dict with keys: {list(data.keys())[:10]}")  # Show first 10 keys
            
            return data
            
        except Exception as e:
            print(f"Error loading CVE data: {e}")
            return None


def main():
    """Main function to run the analysis."""
    print("🚀 Starting CVE Description Quality Analysis")
    print("=" * 50)
    
    # Load CVE data
    print("📥 Loading CVE data from cve_data folder...")
    try:
        cve_records = get_cve_records()
        print(f"✅ Loaded {len(cve_records)} CVE records")
        
        # Debug the structure
        if len(cve_records) > 0:
            print(f"First record type: {type(cve_records[0])}")
            if isinstance(cve_records[0], str):
                print(f"First record (string): {cve_records[0][:100]}...")
            elif isinstance(cve_records[0], dict):
                print(f"First record keys: {list(cve_records[0].keys())}")
            else:
                print(f"First record content: {str(cve_records[0])[:100]}...")
    except Exception as e:
        print(f"❌ Error loading CVE data: {e}")
        print("Make sure the cve_data folder exists and contains CVE data")
        return
    
    if len(cve_records) == 0:
        print("❌ No CVE records found. Make sure the cve_data folder contains data.")
        return
    
    # Initialize analyzer
    analyzer = DescriptionQualityAnalyzer()
    
    # Run analysis
    sample_size = min(10000, len(cve_records))
    analysis_results = analyzer.analyze_cve_sample(cve_records, sample_size)
    
    # Generate reports
    print("\n📊 Generating analysis reports...")
    
    # Statistics report
    stats_report = analyzer.generate_statistics_report()
    print(stats_report)
    
    # ML analysis (if available)
    if ML_AVAILABLE:
        print("\n" + analyzer.generate_ml_analysis())
    
    # Recommendations
    print("\n" + analyzer.generate_recommendations())
    
    # Save detailed results
    output_dir = Path(__file__).parent / "analysis_output"
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save full report
    with open(output_dir / f"description_quality_report_{timestamp}.txt", 'w') as f:
        f.write(stats_report)
        f.write("\n\n")
        if ML_AVAILABLE:
            f.write(analyzer.generate_ml_analysis())
            f.write("\n\n")
        f.write(analyzer.generate_recommendations())
    
    # Save raw data for further analysis
    with open(output_dir / f"analysis_data_{timestamp}.json", 'w') as f:
        # Simplify data for JSON serialization
        simplified_results = []
        for result in analysis_results['results']:
            simplified_results.append({
                'cve_id': result['cve_id'],
                'cna': result['cna'],
                'description_length': len(result['description']),
                'score': result['analysis']['score'],
                'components': result['analysis']['components'],
                'metrics': result['analysis']['metrics']
            })
        
        json.dump({
            'timestamp': timestamp,
            'total_analyzed': analysis_results['total_analyzed'],
            'results': simplified_results,
            'summary': {
                'mean_score': statistics.mean([r['analysis']['score'] for r in analysis_results['results']]),
                'median_score': statistics.median([r['analysis']['score'] for r in analysis_results['results']]),
                'cna_count': len(analysis_results['cna_stats'])
            }
        }, f, indent=2)
    
    print(f"\n💾 Reports saved to {output_dir}/")
    print(f"   - description_quality_report_{timestamp}.txt")
    print(f"   - analysis_data_{timestamp}.json")
    
    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    main()