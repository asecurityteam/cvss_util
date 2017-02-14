from __future__ import division
import collections


def get_impact_f_val(impact):
    if impact != 0:
        return 1.176
    return 0


def calc_base_score(impact, exploitability):
    return (((0.6 * impact) + (0.4 * exploitability) - 1.5) *
            get_impact_f_val(impact))


def get_access_complexity_score(text):
    text = text.lower()
    if text == "high":
        return 0.35
    if text == "medium":
        return 0.61
    if text == "low":
        return 0.71
    return None


def get_authentication_score(text):
    text = text.lower()
    if "none" in text:
        return 0.704
    if "single" in text:
        return 0.56
    if "multiple" in text:
        return 0.45
    return None


def get_access_vector_score(text):
    text = text.lower()
    val_map = {'local': 0.395,
               'adjacent network': 0.646,
               'network': 1}
    return val_map[text]


def _get_base_impact_val_map():
    return {'none': 0,
            'partial': 0.275,
            'complete': 0.660}


def _get_impact_score(text):
    val_map = _get_base_impact_val_map()
    return val_map[text.lower()]


def get_conf_impact(text):
    return _get_impact_score(text)


def get_integ_impact(text):
    return _get_impact_score(text)


def get_avail_impact(text):
    return _get_impact_score(text)


def get_impact_score(conf, integ, avail):
    c = _get_impact_score(conf)
    i = _get_impact_score(integ)
    a = _get_impact_score(avail)
    ret = 10.41 * (1 - ((1 - c) * (1 - i) * (1 - a)))
    return ret


def get_exploitability_score(access_v, access_comp, authen):
    av = get_access_vector_score(access_v)
    ac = get_access_complexity_score(access_comp)
    au = get_authentication_score(authen)
    return 20 * ac * au * av


def get_severity_description(score):
    """ returns the 'description' for the cvss score level provided. """
    for severity, range in get_severity_description_rating_dict().items():
        if range.bottom <= score <= range.top:
            return severity
    raise ValueError('Invalid cvss score value')


def get_severity_description_rating_dict():
    """ Returns the qualitative severity rating ranges for
        cvss v2 in a dictionary.
    """
    Range = collections.namedtuple('Range', ['bottom', 'top'])
    return collections.OrderedDict([
        ('Low', Range(0.0, 2.9)),
        ('Medium', Range(3.0, 5.9)),
        ('High', Range(6.0, 7.9)),
        ('Critical', Range(8.0, 10.0)),
    ])


def get_base_vector_string_dict():
    """ returns the base vector string dictionary. """
    impact_dict = {
        'N': 'None',
        'P': 'Partial',
        'C': 'Complete',
    }
    return {
        'av': {
            'L': 'Local',
            'A': 'Adjacent Network',
            'N': 'Network',
        },
        'ac': {
            'H': 'High',
            'M': 'Medium',
            'L': 'Low',
        },
        'au': {
            'M': 'Multiple',
            'S': 'Single',
            'N': 'None',
        },
        'c': impact_dict,
        'i': impact_dict,
        'a': impact_dict,
    }
