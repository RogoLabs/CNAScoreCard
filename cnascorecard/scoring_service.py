import textstat
from datetime import datetime

class ScoringService:
    def score_description_readability(self, description_text):
        """
        Scores the readability of a description text using the Gunning Fog index,
        which is more suitable for technical documentation.
        """
        if not description_text or len(description_text.split()) < 15:
            return 0
        
        # Gunning Fog Index is better for technical text. A lower score is better.
        # A score of ~12 is ideal, scores > 17 are difficult.
        # We'll normalize this to a 0-10 scale where 10 is the best.
        # A score of 10 or less gets a perfect 10/10.
        # A score of 25 or more gets a 0/10.
        gunning_fog_score = textstat.gunning_fog(description_text)
        
        # Normalize the score
        normalized_score = 10 * (1 - (gunning_fog_score - 10) / 15)
        
        # Clamp the score between 0 and 10
        return min(max(normalized_score, 0), 10)

    def score_references_quality(self, references_array):
        """
        Scores the quality of references based on quantity and tags.
        """
        if not references_array:
            return 0

        score = min(len(references_array), 5)
        bonus = sum(1 for ref in references_array if "tags" in ref and "vendor-advisory" in ref["tags"])
        score += min(bonus, 5)
        
        return min(score, 10)

    def score_timeliness(self, date_published_str, date_updated_str, references_score):
        """
        Scores the timeliness based on how quickly a CVE is enriched after publication.
        A higher score is better.
        """
        if not date_published_str or not date_updated_str:
            return 0

        try:
            date_published = datetime.fromisoformat(date_published_str.replace("Z", "+00:00"))
            date_updated = datetime.fromisoformat(date_updated_str.replace("Z", "+00:00"))
            delta = date_updated - date_published
            days = delta.days

            if days <= 0:  # Published and not updated, or updated same day.
                # If the reference score is high, it was likely published complete.
                return 10 if references_score > 5 else 1
            elif days <= 7:
                return 9  # Very responsive
            elif days <= 30:
                return 6  # Good
            elif days <= 90:
                return 3  # Slow
            else:
                return 1  # Very slow
        except (ValueError, TypeError):
            return 0

    def score_completeness(self, cve_record):
        """
        Scores the completeness of a CVE record based on the presence of key fields.
        """
        score = 0
        try:
            cna_container = cve_record["containers"]["cna"]
            if cna_container.get("affected"): score += 3
            if cna_container.get("problemTypes"): score += 2
            if cna_container.get("metrics"): score += 2
            if cna_container.get("solutions"): score += 1
            if cna_container.get("workarounds"): score += 1
            if cna_container.get("credits"): score += 1
        except (KeyError, IndexError):
            pass
        return score

    def score_cve(self, cve_record):
        """Score a single CVE record across multiple quality metrics."""
        try:
            cve_id = cve_record.get("cveMetadata", {}).get("cveId", "Unknown")
            cna = cve_record.get("cveMetadata", {}).get("assignerShortName", "Unknown")
            
            # Safely extract description
            description = ""
            try:
                description = cve_record["containers"]["cna"]["descriptions"][0]["value"]
            except (KeyError, IndexError):
                pass

            # Safely extract references
            references = []
            try:
                references = cve_record["containers"]["cna"]["references"]
            except (KeyError, IndexError):
                pass

            # Safely extract dates
            date_published = cve_record.get("cveMetadata", {}).get("datePublished")
            date_updated = cve_record.get("containers", {}).get("cna", {}).get("providerMetadata", {}).get("dateUpdated")

            readability_score = self.score_description_readability(description)
            references_score = self.score_references_quality(references)
            timeliness_score = self.score_timeliness(date_published, date_updated, references_score)
            completeness_score = self.score_completeness(cve_record)
            
            # Check for CVSS score presence according to CVE 5.0 schema
            has_cvss = False
            try:
                cna_container = cve_record["containers"]["cna"]
                if 'metrics' in cna_container:
                    # metrics is an array of metric objects
                    for metric in cna_container['metrics']:
                        # Each metric can have cvssV3_1, cvssV3_0, cvssV2_0, etc.
                        if any(key.startswith('cvssV') for key in metric.keys()):
                            has_cvss = True
                            break
            except (KeyError, TypeError):
                pass
            
            # Check for CWE ID presence according to CVE 5.0 schema
            has_cwe = False
            try:
                cna_container = cve_record["containers"]["cna"]
                if 'problemTypes' in cna_container:
                    # problemTypes is an array of problemType objects
                    for problem_type in cna_container['problemTypes']:
                        if 'descriptions' in problem_type:
                            # descriptions is an array of description objects
                            for description in problem_type['descriptions']:
                                # CWE references can be in 'cweId' field or 'references' with type 'CWE'
                                if ('cweId' in description and description['cweId']) or \
                                   ('type' in description and description['type'] == 'CWE'):
                                    has_cwe = True
                                    break
                        if has_cwe:
                            break
            except (KeyError, TypeError):
                pass
            
            overall_score = (readability_score + references_score + timeliness_score + completeness_score) / 4

            return {
                "cve_id": cve_id,
                "cna": cna,
                "readability_score": readability_score,
                "references_score": references_score,
                "timeliness_score": timeliness_score,
                "completeness_score": completeness_score,
                "overall_score": round(overall_score, 2),
                'has_cvss': has_cvss,
                'has_cwe': has_cwe
            }
            
        except Exception as e:
            print(f"Error scoring CVE: {e}")
            return None
