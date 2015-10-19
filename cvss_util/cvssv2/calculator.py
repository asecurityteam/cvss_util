from __future__ import division


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


def get_severity_description(cvss_score):
    """ returns the 'description' for the cvss score level provided. """
    if cvss_score <= 2.9:
        return "Low"
    if cvss_score <= 5.9:
        return "Medium"
    if cvss_score <= 7.9:
        return "High"
    if cvss_score <= 10:
        return "Critical"
    raise ValueError("Invalid cvss score value")
