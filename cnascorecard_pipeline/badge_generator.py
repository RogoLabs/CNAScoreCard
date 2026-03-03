"""
CNA Scorecard Badge Generator.

This module generates SVG badges for CNAs to display on their homepages,
showing their current CNA Scorecard rank and score.
"""
import logging
from typing import Dict, Optional
from pathlib import Path

logger = logging.getLogger('cnascorecard.badge_generator')

# Mapping of individual metric badge styles to (abbreviation, category key)
METRIC_STYLES = {
    "fc": ("FC", "foundational_completeness"),
    "rc": ("RC", "root_cause_analysis"),
    "si": ("SI", "software_identification"),
    "sv": ("SV", "severity_and_impact"),
    "pi": ("PI", "patchinfo"),
}


def get_color_from_score(score: float) -> str:
    """
    Get color based on score.
    
    Args:
        score: Numerical score (0-100)
        
    Returns:
        Hex color code
    """
    if score >= 90:
        return "#00A86B"  # Emerald green for excellent
    elif score >= 80:
        return "#10B981"  # Green for very good
    elif score >= 70:
        return "#60A5FA"  # Blue for good
    elif score >= 60:
        return "#FBBF24"  # Yellow for fair
    else:
        return "#EF4444"  # Red for needs improvement


def generate_badge_svg(
    cna_name: str,
    score: float,
    rank: int,
    badge_style: str = "rank",
    categories: Optional[Dict[str, float]] = None
) -> str:
    """
    Generate SVG badge for a CNA.

    Args:
        cna_name: Name of the CNA
        score: CNA's overall average score (0-100)
        rank: CNA's rank position
        badge_style: Style of badge - "rank", "score", "both", "detailed",
            or a metric key ("fc", "rc", "si", "sv", "pi")
        categories: Dict of individual category scores (0-100) for detailed/metric badges

    Returns:
        SVG badge as string
    """
    color = get_color_from_score(score)

    if badge_style == "rank":
        return _generate_rank_badge(rank, color)
    elif badge_style == "score":
        return _generate_score_badge(score, color)
    elif badge_style == "both":
        return _generate_combined_badge(score, rank, color)
    elif badge_style == "detailed":
        return _generate_detailed_badge(categories if categories else {})
    elif badge_style in METRIC_STYLES:
        abbrev, key = METRIC_STYLES[badge_style]
        pct = (categories or {}).get(key, 0)
        return _generate_metric_badge(abbrev, pct)
    else:
        return _generate_rank_badge(rank, color)


def _generate_rank_badge(rank: int, color: str) -> str:
    """Generate rank-only badge."""
    rank_str = f"#{rank}"
    # Calculate text length based on rank string length
    text_length = len(rank_str) * 70
    badge_width = 145 + (text_length / 10 + 10)
    rect_x = 145
    text_x = rect_x + (text_length / 20 + 5)
    
    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{int(badge_width)}" height="28" role="img" aria-label="CNAScorecard.org Rank: {rank_str}">
    <title>CNAScorecard.org Rank: {rank_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{int(badge_width)}" height="28" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="145" height="28" fill="#555"/>
        <rect x="145" width="{int(badge_width - 145)}" height="28" fill="{color}"/>
        <rect width="{int(badge_width)}" height="28" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="735" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="1350">CNAScorecard.org Rank</text>
        <text x="735" y="185" transform="scale(.1)" fill="#fff" textLength="1350">CNAScorecard.org Rank</text>
        <text aria-hidden="true" x="{int(text_x * 10)}" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{text_length}">{rank_str}</text>
        <text x="{int(text_x * 10)}" y="185" transform="scale(.1)" fill="#fff" textLength="{text_length}">{rank_str}</text>
    </g>
</svg>'''


def _generate_score_badge(score: float, color: str) -> str:
    """Generate score-only badge."""
    score_str = f"{score:.1f}%"
    # Calculate text length based on score string length
    text_length = len(score_str) * 60
    badge_width = 145 + (text_length / 10 + 10)
    rect_x = 145
    text_x = rect_x + (text_length / 20 + 5)
    
    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{int(badge_width)}" height="28" role="img" aria-label="CNAScorecard.org Score: {score_str}">
    <title>CNAScorecard.org Score: {score_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{int(badge_width)}" height="28" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="145" height="28" fill="#555"/>
        <rect x="145" width="{int(badge_width - 145)}" height="28" fill="{color}"/>
        <rect width="{int(badge_width)}" height="28" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="735" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="1350">CNAScorecard.org Score</text>
        <text x="735" y="185" transform="scale(.1)" fill="#fff" textLength="1350">CNAScorecard.org Score</text>
        <text aria-hidden="true" x="{int(text_x * 10)}" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{text_length}">{score_str}</text>
        <text x="{int(text_x * 10)}" y="185" transform="scale(.1)" fill="#fff" textLength="{text_length}">{score_str}</text>
    </g>
</svg>'''


def _generate_combined_badge(score: float, rank: int, color: str) -> str:
    """Generate combined rank and score badge."""
    badge_str = f"#{rank} - {score:.1f}%"
    text_length = len(badge_str) * 55
    badge_width = 145 + (text_length / 10 + 15)
    rect_x = 145
    text_x = rect_x + (text_length / 20 + 7.5)

    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{int(badge_width)}" height="28" role="img" aria-label="CNAScorecard.org: {badge_str}">
    <title>CNAScorecard.org: {badge_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{int(badge_width)}" height="28" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="145" height="28" fill="#555"/>
        <rect x="145" width="{int(badge_width - 145)}" height="28" fill="{color}"/>
        <rect width="{int(badge_width)}" height="28" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="735" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="1350">CNAScorecard.org</text>
        <text x="735" y="185" transform="scale(.1)" fill="#fff" textLength="1350">CNAScorecard.org</text>
        <text aria-hidden="true" x="{int(text_x * 10)}" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{text_length}">{badge_str}</text>
        <text x="{int(text_x * 10)}" y="185" transform="scale(.1)" fill="#fff" textLength="{text_length}">{badge_str}</text>
    </g>
</svg>'''


def _generate_detailed_badge(categories: Dict[str, float]) -> str:
    """Generate detailed badge showing all 5 individual category scores."""
    metrics = [
        ("FC", categories.get("foundational_completeness", 0)),
        ("RC", categories.get("root_cause_analysis", 0)),
        ("SI", categories.get("software_identification", 0)),
        ("SV", categories.get("severity_and_impact", 0)),
        ("PI", categories.get("patchinfo", 0)),
    ]

    label_width = 125
    segment_width = 60
    total_width = label_width + len(metrics) * segment_width  # 425

    # Build colored segments and text
    segments_rects = []
    metric_texts = []
    x_offset = label_width

    for abbrev, pct in metrics:
        metric_color = get_color_from_score(pct)
        pct_str = f"{pct:.0f}%"
        text = f"{abbrev}: {pct_str}"
        text_center_x = int((x_offset + segment_width / 2) * 10)
        text_length = len(text) * 55

        segments_rects.append(
            f'        <rect x="{x_offset}" width="{segment_width}" height="28" fill="{metric_color}"/>'
        )
        metric_texts.append(
            f'        <text aria-hidden="true" x="{text_center_x}" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{text_length}">{text}</text>'
        )
        metric_texts.append(
            f'        <text x="{text_center_x}" y="185" transform="scale(.1)" fill="#fff" textLength="{text_length}">{text}</text>'
        )
        x_offset += segment_width

    segments_str = "\n".join(segments_rects)
    texts_str = "\n".join(metric_texts)

    label_center_x = int(label_width * 10 / 2)
    title_parts = " ".join(f"{a}:{p:.0f}%" for a, p in metrics)
    title_text = f"CNAScorecard.org: {title_parts}"

    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{total_width}" height="28" role="img" aria-label="{title_text}">
    <title>{title_text}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{total_width}" height="28" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="{label_width}" height="28" fill="#555"/>
{segments_str}
        <rect width="{total_width}" height="28" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="{label_center_x}" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="1050">CNAScorecard.org</text>
        <text x="{label_center_x}" y="185" transform="scale(.1)" fill="#fff" textLength="1050">CNAScorecard.org</text>
{texts_str}
    </g>
</svg>'''


def _generate_metric_badge(abbrev: str, pct: float) -> str:
    """Generate individual metric score badge."""
    color = get_color_from_score(pct)
    label_text = f"CNAScorecard.org {abbrev}"
    pct_str = f"{pct:.0f}%"

    label_width = 145
    label_text_length = len(label_text) * 62
    label_center_x = int(label_width * 10 / 2)

    value_text_length = len(pct_str) * 70
    badge_width = label_width + int(value_text_length / 10 + 16)
    value_center_x = int((label_width + (value_text_length / 20 + 8)) * 10)

    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{badge_width}" height="28" role="img" aria-label="{label_text}: {pct_str}">
    <title>{label_text}: {pct_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{badge_width}" height="28" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="{label_width}" height="28" fill="#555"/>
        <rect x="{label_width}" width="{badge_width - label_width}" height="28" fill="{color}"/>
        <rect width="{badge_width}" height="28" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="{label_center_x}" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{label_text_length}">{label_text}</text>
        <text x="{label_center_x}" y="185" transform="scale(.1)" fill="#fff" textLength="{label_text_length}">{label_text}</text>
        <text aria-hidden="true" x="{value_center_x}" y="195" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{value_text_length}">{pct_str}</text>
        <text x="{value_center_x}" y="185" transform="scale(.1)" fill="#fff" textLength="{value_text_length}">{pct_str}</text>
    </g>
</svg>'''


def generate_cna_badges(
    cna_outputs: Dict[str, Dict],
    output_dir: Path
) -> Dict[str, str]:
    """
    Generate SVG badges for all CNAs.
    
    Args:
        cna_outputs: Dictionary of CNA data from aggregation
        output_dir: Base output directory (web/data)
        
    Returns:
        Dictionary mapping badge types to file paths
    """
    logger.info("Generating CNA badges")
    
    # Create badges directory
    badges_dir = output_dir.parent / 'badges'
    badges_dir.mkdir(parents=True, exist_ok=True)
    
    badge_files = {}
    generated_count = 0
    
    for cna_name, cna_data in cna_outputs.items():
        if not cna_data.get('cna_scoring'):
            continue
            
        cna_scoring = cna_data['cna_scoring'][0]
        score = cna_scoring.get('overall_average_score', 0)
        rank = cna_data.get('rank', 999)  # Get rank from cna_data
        
        # Only generate badges for active CNAs with scores
        if score <= 0:
            continue

        # Extract category percentages for detailed badge
        categories = {
            "foundational_completeness": cna_scoring.get('percent_foundational_completeness', 0),
            "root_cause_analysis": cna_scoring.get('percent_root_cause_analysis', 0),
            "software_identification": cna_scoring.get('percent_software_identification', 0),
            "severity_and_impact": cna_scoring.get('percent_severity_and_impact', 0),
            "patchinfo": cna_scoring.get('percent_patchinfo', 0),
        }

        # Create safe filename
        safe_name = cna_name.replace('/', '_').replace('\\', '_')

        # Generate all badge styles: 3 aggregate + detailed + 5 individual metrics
        all_styles = ['rank', 'score', 'both', 'detailed'] + list(METRIC_STYLES.keys())
        for badge_style in all_styles:
            svg_content = generate_badge_svg(cna_name, score, rank, badge_style, categories)
            filename = f"{safe_name}-{badge_style}.svg"
            filepath = badges_dir / filename

            # Write SVG file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(svg_content)

            badge_key = f"{safe_name}_{badge_style}"
            badge_files[badge_key] = str(filepath)

        generated_count += 1

    logger.info(f"Generated badges for {generated_count} CNAs (9 styles each)")
    return badge_files


def generate_badge_documentation(output_dir: Path, base_url: str = "https://cnascorecard.org") -> str:
    """
    Generate README documentation for using badges.
    
    Args:
        output_dir: Output directory for README
        base_url: Base URL for the CNA Scorecard website
        
    Returns:
        Path to generated README file
    """
    badges_dir = output_dir.parent / 'badges'
    readme_path = badges_dir / 'README.md'
    
    readme_content = f'''# CNA Scorecard Badges

Display your CNA Scorecard rating on your website, README, or documentation!

## Badge Styles

We provide nine badge styles for each CNA:

1. **Rank Badge** - Shows your CNA rank (e.g., #1, #5, #42)
2. **Score Badge** - Shows numerical score percentage
3. **Combined Badge** - Shows both rank and score
4. **Detailed Badge** - Shows all 5 individual metric scores (FC, RC, SI, SV, PI)
5. **FC Badge** - Foundational Completeness score
6. **RC Badge** - Root Cause Analysis score
7. **SI Badge** - Software Identification score
8. **SV Badge** - Severity & Impact score
9. **PI Badge** - Patch Info score

## Usage

### Markdown

Replace `{{CNA_NAME}}` with your CNA shortName (e.g., `Microsoft`, `Cisco`, `Linux`):

**Rank Badge:**
```markdown
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-rank.svg)
```

**Score Badge:**
```markdown
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-score.svg)
```

**Combined Badge:**
```markdown
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-both.svg)
```

**Detailed Badge:**
```markdown
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-detailed.svg)
```

**Individual Metric Badges** (fc, rc, si, sv, pi):
```markdown
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-fc.svg)
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-rc.svg)
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-si.svg)
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-sv.svg)
![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-pi.svg)
```

### HTML

```html
<img src="{{base_url}}/badges/{{{{CNA_NAME}}}}-rank.svg" alt="CNA Scorecard">
```

### Examples

**Microsoft (Rank):**
```markdown
![CNA Scorecard]({{base_url}}/badges/Microsoft-rank.svg)
```

**Linux (Score):**
```markdown
![CNA Scorecard]({{base_url}}/badges/Linux-score.svg)
```

**Cisco (Combined):**
```markdown
![CNA Scorecard]({{base_url}}/badges/Cisco-both.svg)
```

**HeroDevs (Detailed):**
```markdown
![CNA Scorecard]({{base_url}}/badges/HeroDevs-detailed.svg)
```

## Linking to Your CNA Page

Make your badge clickable by wrapping it in a link:

```markdown
[![CNA Scorecard]({{base_url}}/badges/{{{{CNA_NAME}}}}-rank.svg)]({{base_url}}/cna/cna-detail.html?shortName={{{{CNA_NAME}}}})
```

## Badge Updates

Badges are automatically regenerated every time the CNA Scorecard pipeline runs (typically every 6 hours). Your badge will always reflect your latest rank and score!

## Color Scheme

Badges are color-coded based on score:
- **90-100%**: Green (Excellent)
- **80-89%**: Light Green (Very Good)
- **70-79%**: Blue (Good)
- **60-69%**: Yellow (Fair)
- **Below 60%**: Red (Needs Improvement)

## Questions?

Visit [CNA Scorecard]({base_url}) or open an issue on [GitHub](https://github.com/RogoLabs/CNAScoreCard).
'''
    
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    logger.info(f"Generated badge documentation at {readme_path}")
    return str(readme_path)
