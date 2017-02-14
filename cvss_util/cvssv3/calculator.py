from __future__ import division
import collections
import math


def get_severity_description(score):
    """ Returns the matching qualitative severity rating for the given
        cvss v3 score.
    """
    for severity, range in get_severity_description_rating_dict().items():
        if range.bottom <= score <= range.top:
            return severity
    raise ValueError('Invalid cvss score value')


def get_severity_description_rating_dict():
    """ Returns the qualitative severity rating ranges for
        cvss v3 in a dictionary.
    """
    Range = collections.namedtuple('Range', ['bottom', 'top'])
    return collections.OrderedDict([
        ('None', Range(0.0, 0.0)),
        ('Low', Range(0.1, 3.9)),
        ('Medium', Range(4, 6.9)),
        ('High', Range(7.0, 8.9)),
        ('Critical', Range(9.0, 10.0)),
    ])


def get_scope_value(scope_changed):
    if isinstance(scope_changed, bool):
        return scope_changed
    scope_changed = scope_changed.lower()
    if scope_changed == 'changed':
        return True
    if scope_changed == 'unchanged':
        return False
    raise ValueError('Invalid value for scope changed (%s)' % scope_changed)


def get_attack_vector_value(text):
    val_map = {
        'network': 0.85,
        'adjacent network': 0.62,
        'adjacent': 0.62,
        'local': 0.55,
        'physical': 0.2,
    }
    return val_map[text.lower()]


def get_attack_complexity_value(text):
    val_map = {
        'low': 0.77,
        'high': 0.44,
    }
    return val_map[text.lower()]


def get_privileges_required_value(text, scope_changed):
    val_map = {
        'none': 0.85,
        'low': 0.62,
        'high': 0.27
    }
    scope_changed_val_map = {
        'low': 0.68,
        'high': 0.50,
    }
    if get_scope_value(scope_changed):
        val_map.update(scope_changed_val_map)
    return val_map[text.lower()]


def get_user_interaction_value(text):
    val_map = {
        'none': 0.85,
        'required': 0.62,
    }
    return val_map[text.lower()]


def get_impact_val_map():
    return {
        'high': 0.56,
        'low': 0.22,
        'none': 0
    }


def get_impact_metric_score(text):
    val_map = get_impact_val_map()
    return val_map[text.lower()]


def get_impact_sub_score_base(confidentiality, integrity, availability):
    c = get_impact_metric_score(confidentiality)
    i = get_impact_metric_score(integrity)
    a = get_impact_metric_score(availability)
    return 1 - ((1 - c) * (1 - i) * (1 - a))


def get_impact_sub_score(isc_base, scope_modified):
    if not scope_modified:
        return 6.42 * isc_base
    return (7.52 * (isc_base - 0.029)) - (3.25 * ((isc_base - 0.02) ** 15))


def _get_exploitability_sub_score(av_value, ac_value, pr_value, ui_value):
    return 8.22 * av_value * ac_value * pr_value * ui_value


def get_exploitability_sub_score(
        attack_vector,
        attack_complexity,
        privileges_required,
        user_interaction,
        scope_changed):
    return _get_exploitability_sub_score(
        get_attack_vector_value(attack_vector),
        get_attack_complexity_value(attack_complexity),
        get_privileges_required_value(privileges_required, scope_changed),
        get_user_interaction_value(user_interaction),
    )


def compute_base_score(impact_sub_score, exploit_sub_score, scope_changed):
    if impact_sub_score <= 0:
        return 0
    if not get_scope_value(scope_changed):
        value = min((impact_sub_score + exploit_sub_score), 10)
    else:
        value = min((1.08 * (impact_sub_score + exploit_sub_score)), 10)
    value = math.ceil(value * 10) / 10
    return value


def compute_base_score_from_dicts(
        exploitability_dict, impact_dict, scope_changed):
    """ returns the base score calculated from the given
        exploitability dictionary, impact dictionary and scope changed
        arguments.
    """
    scope_changed = get_scope_value(scope_changed)
    exploit_args = exploitability_dict.copy()
    exploit_args['scope_changed'] = scope_changed
    exploitability_sub_score = get_exploitability_sub_score(
        **exploit_args)
    isc_base = get_impact_sub_score_base(**impact_dict)
    impact_sub_score = get_impact_sub_score(
        isc_base,
        scope_changed,
    )
    return compute_base_score(
        impact_sub_score, exploitability_sub_score, scope_changed)


def get_base_vector_string_dict():
    """ returns the base vector string dictionary. """
    impact_dict = {
        'N': 'None',
        'L': 'Low',
        'H': 'High',
    }
    return {
        'av': {
            'N': 'Network',
            'A': 'Adjacent',
            'L': 'Local',
            'P': 'Physical',
        },
        'ac': {
            'L': 'Low',
            'H': 'High',
        },
        'pr': {
            'N': 'None',
            'L': 'Low',
            'H': 'High',
        },
        'ui': {
            'N': 'None',
            'R': 'Required',
        },
        's': {
            'U': 'Unchanged',
            'C': 'Changed',
        },
        'c': impact_dict,
        'i': impact_dict,
        'a': impact_dict,
    }
