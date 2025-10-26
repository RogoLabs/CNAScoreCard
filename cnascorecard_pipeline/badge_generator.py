"""
CNA Scorecard Badge Generator.

This module generates SVG badges for CNAs to display on their homepages,
showing their current CNA Scorecard rank and score.
"""
import logging
from typing import Dict, Optional
from pathlib import Path

logger = logging.getLogger('cnascorecard.badge_generator')


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
    badge_style: str = "rank"
) -> str:
    """
    Generate SVG badge for a CNA.
    
    Args:
        cna_name: Name of the CNA
        score: CNA's overall average score (0-100)
        rank: CNA's rank position
        badge_style: Style of badge - "rank", "score", or "both"
        
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
    
    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{int(badge_width)}" height="20" role="img" aria-label="CNAScorecard.org Rank: {rank_str}">
    <title>CNAScorecard.org Rank: {rank_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{int(badge_width)}" height="20" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="145" height="20" fill="#555"/>
        <rect x="145" width="{int(badge_width - 145)}" height="20" fill="{color}"/>
        <rect width="{int(badge_width)}" height="20" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="735" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="1350">CNAScorecard.org Rank</text>
        <text x="735" y="140" transform="scale(.1)" fill="#fff" textLength="1350">CNAScorecard.org Rank</text>
        <text aria-hidden="true" x="{int(text_x * 10)}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{text_length}">{rank_str}</text>
        <text x="{int(text_x * 10)}" y="140" transform="scale(.1)" fill="#fff" textLength="{text_length}">{rank_str}</text>
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
    
    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{int(badge_width)}" height="20" role="img" aria-label="CNAScorecard.org Score: {score_str}">
    <title>CNAScorecard.org Score: {score_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{int(badge_width)}" height="20" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="145" height="20" fill="#555"/>
        <rect x="145" width="{int(badge_width - 145)}" height="20" fill="{color}"/>
        <rect width="{int(badge_width)}" height="20" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="735" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="1350">CNAScorecard.org Score</text>
        <text x="735" y="140" transform="scale(.1)" fill="#fff" textLength="1350">CNAScorecard.org Score</text>
        <text aria-hidden="true" x="{int(text_x * 10)}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{text_length}">{score_str}</text>
        <text x="{int(text_x * 10)}" y="140" transform="scale(.1)" fill="#fff" textLength="{text_length}">{score_str}</text>
    </g>
</svg>'''


def _generate_combined_badge(score: float, rank: int, color: str) -> str:
    """Generate combined rank and score badge."""
    badge_str = f"#{rank} - {score:.1f}%"
    text_length = len(badge_str) * 55
    badge_width = 145 + (text_length / 10 + 15)
    rect_x = 145
    text_x = rect_x + (text_length / 20 + 7.5)
    
    return f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{int(badge_width)}" height="20" role="img" aria-label="CNAScorecard.org: {badge_str}">
    <title>CNAScorecard.org: {badge_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
        <stop offset="1" stop-opacity=".1"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{int(badge_width)}" height="20" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="145" height="20" fill="#555"/>
        <rect x="145" width="{int(badge_width - 145)}" height="20" fill="{color}"/>
        <rect width="{int(badge_width)}" height="20" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
        <text aria-hidden="true" x="735" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="1350">CNAScorecard.org</text>
        <text x="735" y="140" transform="scale(.1)" fill="#fff" textLength="1350">CNAScorecard.org</text>
        <text aria-hidden="true" x="{int(text_x * 10)}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{text_length}">{badge_str}</text>
        <text x="{int(text_x * 10)}" y="140" transform="scale(.1)" fill="#fff" textLength="{text_length}">{badge_str}</text>
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
        
        # Create safe filename
        safe_name = cna_name.replace('/', '_').replace('\\', '_')
        
        # Generate all three badge styles
        for badge_style in ['rank', 'score', 'both']:
            svg_content = generate_badge_svg(cna_name, score, rank, badge_style)
            filename = f"{safe_name}-{badge_style}.svg"
            filepath = badges_dir / filename
            
            # Write SVG file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(svg_content)
            
            badge_key = f"{safe_name}_{badge_style}"
            badge_files[badge_key] = str(filepath)
        
        generated_count += 1
    
    logger.info(f"Generated badges for {generated_count} CNAs (3 styles each)")
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

We provide three badge styles for each CNA:

1. **Rank Badge** - Shows your CNA rank (e.g., #1, #5, #42)
2. **Score Badge** - Shows numerical score percentage
3. **Combined Badge** - Shows both rank and score

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
