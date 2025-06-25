#!/usr/bin/env python3
"""
CVE Description Term Extraction

This script analyzes actual CVE descriptions to extract the most effective
vulnerability types, impact terms, and technical terms for improving the
EAS description quality scoring algorithm.
"""

import sys
import os
import json
import re
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict
import statistics

# Add the parent directory to the path to import cnascorecard modules
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from cnascorecard.data_ingestor import get_cve_records
    from cnascorecard.eas_scorer import EnhancedAggregateScorer
except ImportError as e:
    print(f"❌ Error importing cnascorecard modules: {e}")
    sys.exit(1)

class CVETermExtractor:
    """Extracts and analyzes terms from CVE descriptions to improve scoring."""
    
    def __init__(self):
        self.vulnerability_patterns = []
        self.impact_patterns = []
        self.technical_patterns = []
        self.generic_patterns = []
        
    def extract_description(self, cve_data):
        """Extract description from CVE data"""
        try:
            # Handle CVE 5.x format
            if isinstance(cve_data, dict) and 'containers' in cve_data:
                containers = cve_data.get('containers', {})
                if 'cna' in containers:
                    descriptions = containers['cna'].get('descriptions', [])
                    for desc in descriptions:
                        if isinstance(desc, dict) and desc.get('lang') == 'en':
                            return desc.get('value', '').strip()
            
            # Handle legacy format
            if isinstance(cve_data, dict) and 'description' in cve_data:
                desc_data = cve_data['description']
                if isinstance(desc_data, dict) and 'description_data' in desc_data:
                    desc_list = desc_data['description_data']
                    for desc in desc_list:
                        if isinstance(desc, dict) and desc.get('lang') == 'en':
                            return desc.get('value', '').strip()
            
            return None
        except Exception:
            return None
    
    def analyze_high_quality_descriptions(self, cve_records, sample_size=5000):
        """Analyze high-quality CVE descriptions to extract effective terms."""
        print(f"🔍 Analyzing {sample_size} CVE descriptions for term extraction...")
        
        # Get descriptions and their quality scores
        descriptions_with_scores = []
        
        for i, cve in enumerate(cve_records[:sample_size]):
            if i % 1000 == 0:
                print(f"  Processing {i}/{sample_size}...")
            
            description = self.extract_description(cve)
            if description and len(description) > 50:
                try:
                    scorer = EnhancedAggregateScorer(cve)
                    scores = scorer.calculate_scores()
                    foundational_score = scores['scoreBreakdown']['foundationalCompleteness']
                    
                    descriptions_with_scores.append({
                        'description': description,
                        'foundational_score': foundational_score,
                        'cve_id': scores.get('cveId', 'Unknown')
                    })
                except Exception as e:
                    continue
        
        print(f"✅ Collected {len(descriptions_with_scores)} valid descriptions")
        
        # Sort by foundational score
        descriptions_with_scores.sort(key=lambda x: x['foundational_score'], reverse=True)
        
        # Analyze top performers vs bottom performers
        top_third = descriptions_with_scores[:len(descriptions_with_scores)//3]
        bottom_third = descriptions_with_scores[-len(descriptions_with_scores)//3:]
        
        print(f"📊 Analyzing top {len(top_third)} vs bottom {len(bottom_third)} descriptions")
        
        # Extract terms from each group
        top_terms = self._extract_terms_from_descriptions([d['description'] for d in top_third])
        bottom_terms = self._extract_terms_from_descriptions([d['description'] for d in bottom_third])
        
        # Find terms that are significantly more common in high-quality descriptions
        effective_terms = self._find_discriminative_terms(top_terms, bottom_terms)
        
        return effective_terms, descriptions_with_scores
    
    def _extract_terms_from_descriptions(self, descriptions):
        """Extract various types of terms from descriptions."""
        vuln_terms = Counter()
        impact_terms = Counter()
        tech_terms = Counter()
        generic_terms = Counter()
        
        # Comprehensive patterns for different term types
        vulnerability_patterns = [
            # Buffer-related
            r'buffer overflow', r'heap overflow', r'stack overflow', r'out-of-bounds',
            r'buffer underflow', r'buffer overrun', r'memory corruption',
            
            # Injection attacks
            r'sql injection', r'code injection', r'command injection', r'script injection',
            r'ldap injection', r'xpath injection', r'template injection', r'header injection',
            
            # XSS and CSRF
            r'cross-site scripting', r'xss', r'stored xss', r'reflected xss', r'dom xss',
            r'cross-site request forgery', r'csrf', r'clickjacking',
            
            # Path and traversal
            r'path traversal', r'directory traversal', r'file inclusion', r'local file inclusion',
            r'remote file inclusion', r'zip slip',
            
            # Authentication and authorization
            r'authentication bypass', r'authorization bypass', r'privilege escalation',
            r'access control', r'missing authentication', r'weak authentication',
            
            # Memory issues
            r'use after free', r'double free', r'null pointer dereference', r'memory leak',
            r'race condition', r'integer overflow', r'integer underflow', r'format string',
            
            # Crypto and TLS
            r'weak encryption', r'certificate validation', r'tls', r'ssl', r'cryptographic',
            r'weak cipher', r'key management',
            
            # Web-specific
            r'server-side request forgery', r'ssrf', r'xml external entity', r'xxe',
            r'insecure deserialization', r'prototype pollution',
            
            # DoS
            r'denial of service', r'dos', r'resource exhaustion', r'infinite loop',
            
            # Logic flaws
            r'logic error', r'business logic', r'improper validation', r'input validation',
            r'output encoding', r'sanitization'
        ]
        
        impact_patterns = [
            # Direct impact verbs
            r'allows?', r'enables?', r'leads to', r'results? in', r'causes?',
            r'permits?', r'facilitates?', r'triggers?',
            
            # Exploitation context
            r'can be exploited', r'may be exploited', r'could be exploited',
            r'exploitable', r'attackers? can', r'attackers? may',
            
            # Access and execution
            r'execute arbitrary', r'arbitrary code execution', r'remote code execution',
            r'gain access', r'unauthorized access', r'escalate privileges',
            r'bypass', r'circumvent', r'obtain', r'retrieve',
            
            # Information exposure
            r'information disclosure', r'data exposure', r'sensitive information',
            r'expose', r'disclose', r'leak', r'reveal',
            
            # System impact
            r'compromise', r'manipulate', r'modify', r'delete', r'corrupt',
            r'crash', r'hang', r'freeze', r'terminate',
            
            # Attacker capabilities
            r'remote attackers?', r'local attackers?', r'authenticated attackers?',
            r'unauthenticated attackers?', r'malicious users?'
        ]
        
        tech_patterns = [
            # Development terms
            r'function', r'method', r'parameter', r'argument', r'variable',
            r'field', r'property', r'class', r'object', r'instance',
            
            # Web technology
            r'endpoint', r'api', r'rest api', r'web service', r'servlet',
            r'request', r'response', r'header', r'cookie', r'session',
            
            # System components
            r'component', r'module', r'library', r'framework', r'plugin',
            r'driver', r'service', r'daemon', r'process', r'thread',
            
            # Data handling
            r'parser', r'processor', r'handler', r'validator', r'serializer',
            r'deserializer', r'encoder', r'decoder',
            
            # Protocols and interfaces
            r'protocol', r'interface', r'socket', r'connection', r'channel',
            r'stream', r'buffer', r'queue',
            
            # Processing context
            r'when processing', r'during processing', r'while handling',
            r'when parsing', r'during parsing', r'via the', r'through the',
            r'in the', r'within the'
        ]
        
        generic_patterns = [
            r'vulnerability exists', r'security vulnerability', r'security issue',
            r'security flaw', r'security weakness', r'vulnerability in',
            r'issue has been identified', r'problem has been found',
            r'flaw exists', r'weakness in', r'issue in'
        ]
        
        # Count occurrences in descriptions
        for desc in descriptions:
            desc_lower = desc.lower()
            
            for pattern in vulnerability_patterns:
                matches = re.findall(pattern, desc_lower)
                vuln_terms[pattern] += len(matches)
            
            for pattern in impact_patterns:
                matches = re.findall(pattern, desc_lower)
                impact_terms[pattern] += len(matches)
            
            for pattern in tech_patterns:
                matches = re.findall(pattern, desc_lower)
                tech_terms[pattern] += len(matches)
            
            for pattern in generic_patterns:
                matches = re.findall(pattern, desc_lower)
                generic_terms[pattern] += len(matches)
        
        return {
            'vulnerability': vuln_terms,
            'impact': impact_terms,
            'technical': tech_terms,
            'generic': generic_terms
        }
    
    def _find_discriminative_terms(self, top_terms, bottom_terms):
        """Find terms that discriminate between high and low quality descriptions."""
        discriminative = {
            'vulnerability': [],
            'impact': [],
            'technical': [],
            'generic': []
        }
        
        for category in discriminative.keys():
            top_category = top_terms[category]
            bottom_category = bottom_terms[category]
            
            # Calculate discrimination ratio for each term
            term_scores = {}
            
            for term in set(list(top_category.keys()) + list(bottom_category.keys())):
                top_count = top_category.get(term, 0)
                bottom_count = bottom_category.get(term, 0)
                
                # Only consider terms that appear at least 5 times in top descriptions
                if top_count >= 5:
                    # Calculate ratio (with smoothing)
                    ratio = (top_count + 1) / (bottom_count + 1)
                    
                    # Also consider absolute frequency in top descriptions
                    frequency_score = top_count / len(top_terms)
                    
                    # Combined score: ratio * frequency
                    combined_score = ratio * frequency_score
                    
                    term_scores[term] = {
                        'ratio': ratio,
                        'top_count': top_count,
                        'bottom_count': bottom_count,
                        'frequency_score': frequency_score,
                        'combined_score': combined_score
                    }
            
            # Sort by combined score and take top terms
            sorted_terms = sorted(term_scores.items(), key=lambda x: x[1]['combined_score'], reverse=True)
            discriminative[category] = sorted_terms[:20]  # Top 20 terms per category
        
        return discriminative
    
    def generate_term_analysis_report(self, effective_terms, descriptions_with_scores):
        """Generate a comprehensive report of term analysis."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(__file__).parent / "analysis_output"
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"term_extraction_report_{timestamp}.txt"
        
        report = []
        report.append("=" * 70)
        report.append("CVE DESCRIPTION TERM EXTRACTION REPORT")
        report.append("=" * 70)
        report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Descriptions Analyzed: {len(descriptions_with_scores)}")
        report.append("")
        
        # Overall quality distribution
        scores = [d['foundational_score'] for d in descriptions_with_scores]
        report.append("📊 QUALITY DISTRIBUTION")
        report.append("-" * 30)
        report.append(f"Mean Foundational Score: {statistics.mean(scores):.2f}")
        report.append(f"Median Foundational Score: {statistics.median(scores):.2f}")
        report.append(f"Standard Deviation: {statistics.stdev(scores):.2f}")
        report.append("")
        
        # Analyze each term category
        for category, terms in effective_terms.items():
            report.append(f"🔍 {category.upper()} TERMS")
            report.append("-" * 40)
            
            for i, (term, stats) in enumerate(terms[:15], 1):
                ratio = stats['ratio']
                top_count = stats['top_count']
                bottom_count = stats['bottom_count']
                combined_score = stats['combined_score']
                
                report.append(f"{i:2d}. '{term}'")
                report.append(f"    Ratio: {ratio:.2f} | Top: {top_count} | Bottom: {bottom_count} | Score: {combined_score:.4f}")
            
            report.append("")
        
        # Generate improved term lists for implementation
        report.append("💡 RECOMMENDED TERM LISTS FOR IMPLEMENTATION")
        report.append("=" * 50)
        
        # Vulnerability types (top terms with ratio > 1.5)
        vuln_terms = [term for term, stats in effective_terms['vulnerability'] 
                     if stats['ratio'] > 1.5 and stats['top_count'] >= 5][:25]
        report.append("# Vulnerability Types (for vulnTypes array):")
        report.append("vuln_types = [")
        for term in vuln_terms:
            report.append(f"    '{term}',")
        report.append("]")
        report.append("")
        
        # Impact terms (top terms with ratio > 1.3)
        impact_terms_list = [term for term, stats in effective_terms['impact'] 
                            if stats['ratio'] > 1.3 and stats['top_count'] >= 5][:25]
        report.append("# Impact Terms (for impactTerms array):")
        report.append("impact_terms = [")
        for term in impact_terms_list:
            report.append(f"    '{term}',")
        report.append("]")
        report.append("")
        
        # Technical terms (top terms with ratio > 1.2)
        tech_terms_list = [term for term, stats in effective_terms['technical'] 
                          if stats['ratio'] > 1.2 and stats['top_count'] >= 5][:25]
        report.append("# Technical Terms (for techTerms array):")
        report.append("tech_terms = [")
        for term in tech_terms_list:
            report.append(f"    '{term}',")
        report.append("]")
        report.append("")
        
        # Generic terms to avoid (high in bottom descriptions)
        generic_avoid = [term for term, stats in effective_terms['generic'] 
                        if stats['ratio'] < 0.8 and stats['bottom_count'] >= 5][:15]
        report.append("# Generic Terms to Penalize (for genericPhrases array):")
        report.append("generic_phrases = [")
        for term in generic_avoid:
            report.append(f"    '{term}',")
        report.append("]")
        report.append("")
        
        # Example high and low quality descriptions
        report.append("📝 EXAMPLE DESCRIPTIONS")
        report.append("-" * 30)
        
        top_examples = descriptions_with_scores[:5]
        bottom_examples = descriptions_with_scores[-5:]
        
        report.append("HIGH QUALITY EXAMPLES:")
        for i, example in enumerate(top_examples, 1):
            report.append(f"\n{i}. {example['cve_id']} (Score: {example['foundational_score']:.1f})")
            report.append(f"   {example['description'][:200]}...")
        
        report.append("\nLOW QUALITY EXAMPLES:")
        for i, example in enumerate(bottom_examples, 1):
            report.append(f"\n{i}. {example['cve_id']} (Score: {example['foundational_score']:.1f})")
            report.append(f"   {example['description'][:200]}...")
        
        # Write report to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        print(f"📄 Term extraction report written to: {output_file}")
        return '\n'.join(report)

def main():
    """Main execution function."""
    print("🚀 Starting CVE Description Term Extraction Analysis")
    
    # Load CVE data
    print("📥 Loading CVE data...")
    try:
        cve_records = get_cve_records()  # Load available CVE records
        print(f"✅ Loaded {len(cve_records)} CVE records")
    except Exception as e:
        print(f"❌ Error loading CVE data: {e}")
        return
    
    # Initialize extractor and analyze
    extractor = CVETermExtractor()
    
    try:
        effective_terms, descriptions_with_scores = extractor.analyze_high_quality_descriptions(
            cve_records, sample_size=10000
        )
        
        # Generate report
        report = extractor.generate_term_analysis_report(effective_terms, descriptions_with_scores)
        
        # Print summary to console
        print("\n" + "=" * 50)
        print("🎯 ANALYSIS COMPLETE - KEY FINDINGS:")
        print("=" * 50)
        
        for category, terms in effective_terms.items():
            if terms:
                top_term = terms[0]
                print(f"{category.title()}: Top term '{top_term[0]}' (ratio: {top_term[1]['ratio']:.2f})")
        
        print(f"\n📊 Quality range: {min(d['foundational_score'] for d in descriptions_with_scores):.1f} - {max(d['foundational_score'] for d in descriptions_with_scores):.1f}")
        print(f"📈 Analyzed {len(descriptions_with_scores)} descriptions")
        print("\n✅ Check the generated report file for detailed recommendations!")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()