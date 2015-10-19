import collections

from ..cvssv2 import calculator as v2_calculator
from ..cvssv3 import calculator as v3_calculator


def parse_text_info_score(comment):
    """ Returns the result of parsing a wiki table like formatted cvss
        score.
    """
    score_d = collections.OrderedDict()
    for line in comment.split("\n"):
        if "||" not in line:
            continue
        info = [item.strip() for item in line.split("|") if item != ""]
        if len(info) < 2:
            continue
        mini_dict = {info[0]: info[1]}
        score_d.update(mini_dict)

    score = None
    version = 3.0
    if len(list(score_d.keys())) == 6:
        version = 2.0
        score = _compute_cvssv2_score(score_d)
    elif len(list(score_d.keys())) == 8:
        score = _compute_cvssv3_score(score_d)
    if score is None:
        return None
    score_d.update({'score': score, 'version': version})
    return score_d


def _compute_cvssv2_score(comment_dictionary):
    """ Returns the result of computing a cvss v2 score from the
        given comment dictionary.
    """
    impact = v2_calculator.get_impact_score(
        comment_dictionary['ConfImpact'],
        comment_dictionary['IntegImpact'],
        comment_dictionary['AvailImpact'])
    exploit = v2_calculator.get_exploitability_score(
        comment_dictionary['AccessVector'],
        comment_dictionary['AccessComplexity'],
        comment_dictionary['Authentication'])
    return round(v2_calculator.calc_base_score(impact, exploit), 1)


def _compute_cvssv3_score(comment_dictionary):
    """ Returns the result of computing a cvss v3 score from the
        given comment dictionary.
    """
    exploitability_dict = {}
    impact_dict = {}
    scope_changed = comment_dictionary['Scope']
    exploitability_dict['scope_changed'] = scope_changed
    for key in ['Attack Vector', 'Attack Complexity',
                'Privileges Required', 'User Interaction']:
        exploitability_key = key.lower().replace(' ', '_')
        exploitability_dict[exploitability_key] = comment_dictionary[key]
    for key in ['Confidentiality', 'Integrity', 'Availability']:
        impact_dict[key.lower()] = comment_dictionary[key]
    return v3_calculator.compute_base_score_from_dicts(
        exploitability_dict, impact_dict, scope_changed)
