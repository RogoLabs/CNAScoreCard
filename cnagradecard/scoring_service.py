import textstat
from datetime import datetime

class ScoringService:
    def score_description_readability(self, description_text):
        """
        Scores the readability of a description text using Flesch Reading Ease.
        """
        if not description_text or len(description_text.split()) < 15:
            return 0
        
        flesch_score = textstat.flesch_reading_ease(description_text)
        # Normalize the Flesch score (0-100) to a 0-10 scale.
        return min(max(flesch_score / 10, 0), 10)

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

    def score_timeliness(self, date_reserved_str, date_published_str):
        """
        Scores the timeliness based on the difference between reservation and publication dates.
        """
        try:
            date_reserved = datetime.fromisoformat(date_reserved_str.replace("Z", "+00:00"))
            date_published = datetime.fromisoformat(date_published_str.replace("Z", "+00:00"))
            delta = date_published - date_reserved
            days = delta.days

            if days <= 7:
                return 10
            elif days <= 30:
                return 7
            elif days <= 90:
                return 4
            else:
                return 1
        except (ValueError, TypeError):
            return 0

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
        date_reserved = cve_record.get("cveMetadata", {}).get("dateReserved")
        date_published = cve_record.get("cveMetadata", {}).get("datePublished")

        readability_score = self.score_description_readability(description)
        references_score = self.score_references_quality(references)
        timeliness_score = self.score_timeliness(date_reserved, date_published)

        return {
            "cve_id": cve_id,
            "cna": cna,
            "readability_score": readability_score,
            "references_score": references_score,
            "timeliness_score": timeliness_score,
        }
