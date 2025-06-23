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
        """
        Orchestrates the scoring of a single CVE record.
        """
        cve_id = cve_record.get("cveMetadata", {}).get("cveId", "N/A")
        cna = cve_record.get("cveMetadata", {}).get("assignerShortName", "N/A")
        
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
        
        # Check for CVSS score presence
        has_cvss = False
        if 'metrics' in cve_record:
            metrics = cve_record['metrics']
            # Check for any CVSS version (v3.0, v3.1, v2.0, etc.)
            for metric_source in metrics.values():
                if any(key.startswith('cvss') for key in metric_source.keys()):
                    has_cvss = True
                    break
        
        # Check for CWE ID presence
        has_cwe = False
        if 'problemTypes' in cve_record:
            for problem_type in cve_record['problemTypes']:
                if 'descriptions' in problem_type:
                    for description in problem_type['descriptions']:
                        if 'cweId' in description and description['cweId']:
                            has_cwe = True
                            break
                if has_cwe:
                    break
        
        overall_score = (readability_score + references_score + timeliness_score + completeness_score) / 4

        return {
            "cve_id": cve_id,
            "cna": cna,
            "readability_score": readability_score,
            "references_score": references_score,
            "timeliness_score": timeliness_score,
            "completeness_score": completeness_score,
            "overall_score": round(overall_score, 2),
            "has_cvss": has_cvss,
            "has_cwe": has_cwe
        }
