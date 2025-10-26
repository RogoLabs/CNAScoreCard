# CNA Scorecard Badges

Display your CNA Scorecard rating on your website, README, or documentation!

## Badge Styles

We provide three badge styles for each CNA:

1. **Rank Badge** - Shows your CNA rank (e.g., #1, #5, #42)
2. **Score Badge** - Shows numerical score percentage
3. **Combined Badge** - Shows both rank and score

## Usage

### Markdown

Replace `{CNA_NAME}` with your CNA shortName (e.g., `Microsoft`, `Cisco`, `Linux`):

**Rank Badge:**
```markdown
![CNA Scorecard]({base_url}/badges/{{CNA_NAME}}-rank.svg)
```

**Score Badge:**
```markdown
![CNA Scorecard]({base_url}/badges/{{CNA_NAME}}-score.svg)
```

**Combined Badge:**
```markdown
![CNA Scorecard]({base_url}/badges/{{CNA_NAME}}-both.svg)
```

### HTML

```html
<img src="{base_url}/badges/{{CNA_NAME}}-rank.svg" alt="CNA Scorecard">
```

### Examples

**Microsoft (Rank):**
```markdown
![CNA Scorecard]({base_url}/badges/Microsoft-rank.svg)
```

**Linux (Score):**
```markdown
![CNA Scorecard]({base_url}/badges/Linux-score.svg)
```

**Cisco (Combined):**
```markdown
![CNA Scorecard]({base_url}/badges/Cisco-both.svg)
```

## Linking to Your CNA Page

Make your badge clickable by wrapping it in a link:

```markdown
[![CNA Scorecard]({base_url}/badges/{{CNA_NAME}}-rank.svg)]({base_url}/cna/cna-detail.html?shortName={{CNA_NAME}})
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

Visit [CNA Scorecard](https://cnascorecard.org) or open an issue on [GitHub](https://github.com/RogoLabs/CNAScoreCard).
