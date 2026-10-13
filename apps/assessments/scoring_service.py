"""
Transparent Cybersecurity Posture Scoring Service
Calculates reproducible, category-weighted scores and risk levels.
"""

PRIORITY_WEIGHTS = {
    'CRITICAL': 4.0,
    'HIGH': 3.0,
    'MEDIUM': 2.0,
    'LOW': 1.0,
}

def calculate_assessment_score(assessment):
    """
    Scoring Formula:
      Score = (Sum of Compliant Weights / Sum of Applicable Weights) * 100

    Rules:
      - 'NOT_APPLICABLE' items are excluded from total applicable weights.
      - 'NEEDS_IMPROVEMENT' and 'NOT_ASSESSED' receive 0 compliant weight.
      - Category weight multiplier applies to both numerator and denominator.
    """
    from .models import ResponseChoices, RiskLevel

    responses = assessment.responses.select_related('item', 'item__category')

    total_applicable_weight = 0.0
    total_compliant_weight = 0.0

    category_stats = {}
    critical_unresolved_count = 0
    high_unresolved_count = 0

    for resp in responses:
        item = resp.item
        cat = item.category

        if cat.id not in category_stats:
            category_stats[cat.id] = {
                'name': cat.name,
                'weight': cat.weight,
                'compliant_weight': 0.0,
                'applicable_weight': 0.0,
                'total_items': 0,
                'compliant_items': 0,
                'needs_improvement_items': 0,
                'na_items': 0,
            }

        stats = category_stats[cat.id]
        stats['total_items'] += 1

        if resp.response == ResponseChoices.NOT_APPLICABLE:
            stats['na_items'] += 1
            continue  # Excluded from scoring denominator

        item_p_weight = PRIORITY_WEIGHTS.get(item.priority, 1.0)
        combined_weight = item_p_weight * cat.weight

        total_applicable_weight += combined_weight
        stats['applicable_weight'] += combined_weight

        if resp.response == ResponseChoices.COMPLIANT:
            total_compliant_weight += combined_weight
            stats['compliant_weight'] += combined_weight
            stats['compliant_items'] += 1
        elif resp.response == ResponseChoices.NEEDS_IMPROVEMENT:
            stats['needs_improvement_items'] += 1
            if item.priority == 'CRITICAL':
                critical_unresolved_count += 1
            elif item.priority == 'HIGH':
                high_unresolved_count += 1

    # Overall Score Calculation
    if total_applicable_weight > 0:
        overall_score = round((total_compliant_weight / total_applicable_weight) * 100.0, 1)
    else:
        overall_score = 100.0

    # Risk Level Determination
    if critical_unresolved_count > 0 or overall_score < 60.0:
        risk_level = RiskLevel.HIGH
    elif high_unresolved_count > 0 or overall_score < 85.0:
        risk_level = RiskLevel.MODERATE
    else:
        risk_level = RiskLevel.LOW

    # Category Breakdown Scores
    breakdown = []
    for cat_id, data in category_stats.items():
        if data['applicable_weight'] > 0:
            cat_score = round((data['compliant_weight'] / data['applicable_weight']) * 100.0, 1)
        else:
            cat_score = 100.0
        breakdown.append({
            'category_id': cat_id,
            'name': data['name'],
            'score': cat_score,
            'compliant_items': data['compliant_items'],
            'needs_improvement_items': data['needs_improvement_items'],
            'total_items': data['total_items'],
        })

    return {
        'overall_score': overall_score,
        'risk_level': risk_level,
        'critical_unresolved_count': critical_unresolved_count,
        'high_unresolved_count': high_unresolved_count,
        'category_breakdown': breakdown,
        'disclaimer': (
            "CyberSafe posture score is an indicator of self-attested checklist compliance. "
            "It does not replace dynamic intrusion detection, vulnerability scanning, or penetration testing."
        )
    }
