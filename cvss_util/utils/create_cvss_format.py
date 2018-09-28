from ..cvssv2 import calculator as v2_calculator
from ..cvssv3 import calculator as v3_calculator


def split_vector_string(vector):
    metric_rating_dict = {}
    for vector in vector.split('/'):
        metric, rating = vector.split(':')
        metric_rating_dict[metric] = rating
    return metric_rating_dict


def cvss_v2_vector_to_jira_table(vector, score):
    base_vector_string_dict = v2_calculator.get_base_vector_string_dict()
    severity_desc = v2_calculator.get_severity_description(score)

    format_items = {}
    for k, v in split_vector_string(vector).items():
        item = base_vector_string_dict[k.lower()][v]
        format_items[k] = item

    result = """
Proposed CVSS score: {0} => *{1}* severity

*Exploitability Metrics*

|| AccessVector | {AV} |
|| AccessComplexity | {AC} |
|| Authentication | {Au} |


*Impact Metrics*

|| ConfImpact | {C} |
|| IntegImpact | {I} |
|| AvailImpact | {A} |

""".format(score, severity_desc, **format_items)
    return result


def cvss_v3_vector_to_jira_table(vector, score):
    base_vector_string_dict = v3_calculator.get_base_vector_string_dict()
    severity_desc = v3_calculator.get_severity_description(score)

    format_items = {}
    for k, v in split_vector_string(vector).items():
        item = base_vector_string_dict[k.lower()][v]
        format_items[k] = item

    result = """
Proposed CVSS v3 score: {0} => *{1}* severity

*Exploitability Metrics*

|| Attack Vector | {AV} |
|| Attack Complexity | {AC} |
|| Privileges Required | {PR} |
|| User Interaction | {UI} |

*Scope Metric*

|| Scope | {S} |

*Impact Metrics*

|| Confidentiality | {C} |
|| Integrity | {I} |
|| Availability | {A} |

""".format(score, severity_desc, **format_items)
    return result
