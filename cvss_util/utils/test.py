#!/usr/bin/python
import unittest

from . import create_cvss_format
from . import parse_cvss_format


class TestCVSSFormatter(unittest.TestCase):

    def test_format_critical_cvss_v2(self):
        """ tests creating a jira table comment for a critical cvss v2 """
        vector_string = 'AV:N/AC:L/Au:N/C:P/I:P/A:C'
        expected = """
Proposed CVSS score: 9.0 => *Critical* severity

*Exploitability Metrics*

|| AccessVector | Network |
|| AccessComplexity | Low |
|| Authentication | None |


*Impact Metrics*

|| ConfImpact | Partial |
|| IntegImpact | Partial |
|| AvailImpact | Complete |

"""
        formatted_string = create_cvss_format.cvss_v2_vector_to_jira_table(
            vector_string,
            9.0,
        )
        self.assertEqual(
            formatted_string,
            expected,
        )

        parsed = parse_cvss_format.parse_text_info_score(formatted_string)
        self.assertEqual(parsed['version'], 2.0)
        self.assertEqual(parsed['score'], 9.0)
        self.assertEqual(parsed['exploitability_sub_score'], 10.0)
        self.assertEqual(parsed['AccessVector'], 'Network')
        self.assertEqual(parsed['AccessComplexity'], 'Low')
        self.assertEqual(parsed['Authentication'], 'None')
        for key in ['ConfImpact', 'IntegImpact']:
            self.assertEqual(parsed[key], 'Partial')
        self.assertEqual(parsed['AvailImpact'], 'Complete')

    def test_format_critical_cvss_v3(self):
        """ tests creating a jira table comment for a critical cvss v3 """
        vector_string = 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
        expected = """
Proposed CVSS v3 score: 9.6 => *Critical* severity

*Exploitability Metrics*

|| Attack Vector | Network |
|| Attack Complexity | Low |
|| Privileges Required | None |
|| User Interaction | Required |

*Scope Metric*

|| Scope | Changed |

*Impact Metrics*

|| Confidentiality | High |
|| Integrity | High |
|| Availability | High |

"""
        formatted_string = create_cvss_format.cvss_v3_vector_to_jira_table(
            vector_string,
            9.6,
        )
        self.assertEqual(
            formatted_string,
            expected,
        )

        parsed = parse_cvss_format.parse_text_info_score(formatted_string)
        self.assertEqual(parsed['version'], 3.0)
        self.assertEqual(parsed['score'], 9.6)
        self.assertEqual(parsed['exploitability_sub_score'], 2.84)
        self.assertEqual(parsed['Attack Vector'], 'Network')
        self.assertEqual(parsed['Attack Complexity'], 'Low')
        self.assertEqual(parsed['Privileges Required'], 'None')
        self.assertEqual(parsed['User Interaction'], 'Required')
        for key in ['Confidentiality', 'Integrity', 'Availability']:
            self.assertEqual(parsed[key], 'High')


class TestCVSSParser(unittest.TestCase):

    @property
    def v2_text(self):
        return"""
Proposed CVSS score: 10 => *Critical* severity

*Exploitability Metrics*

|| AccessVector | Network |
|| AccessComplexity | Low |
|| Authentication | None |


*Impact Metrics*

|| ConfImpact | Complete |
|| IntegImpact | Complete |
|| AvailImpact | Complete |

"""

    @property
    def v3_text_example_4_4(self):
        return """
Proposed CVSS v3 score: 9.9 => *Critical* severity

*Exploitability Metrics*

|| Attack Vector | Network |
|| Attack Complexity | Low |
|| Privileges Required | Low |
|| User Interaction | None |

*Scope Metric*

|| Scope | Changed |

*Impact Metrics*

|| Confidentiality | High |
|| Integrity | High |
|| Availability | High |

"""

    def test_parse_critical_cvss_v2(self):
        """ tests parsing a critical cvss v2 score """
        parsed = parse_cvss_format.parse_text_info_score(self.v2_text)
        self.assertEqual(parsed['version'], 2.0)
        self.assertEqual(parsed['score'], 10)
        self.assertEqual(parsed['exploitability_sub_score'], 10.0)
        self.assertEqual(parsed['AccessVector'], 'Network')
        self.assertEqual(parsed['AccessComplexity'], 'Low')
        self.assertEqual(parsed['Authentication'], 'None')
        for key in ['ConfImpact', 'IntegImpact', 'AvailImpact']:
            self.assertEqual(parsed[key], 'Complete')

    def test_parse_cvss_v3_example_4_4(self):
        """ tests parsing & calculating the cvss v3 score of example 4.4
            (base score 9.9) from https://www.first.org/cvss/examples.
        """
        parsed = parse_cvss_format.parse_text_info_score(
            self.v3_text_example_4_4)
        self.assertEqual(parsed['version'], 3.0)
        self.assertEqual(parsed['score'], 9.9)
        self.assertEqual(parsed['exploitability_sub_score'], 3.11)
        self.assertEqual(parsed['Attack Vector'], 'Network')
        self.assertEqual(parsed['Attack Complexity'], 'Low')
        self.assertEqual(parsed['Privileges Required'], 'Low')
        for key in ['Confidentiality', 'Integrity', 'Availability']:
            self.assertEqual(parsed[key], 'High')

    def test_parse_cvss_v3_example_4_4_with_spacing(self):
        """ tests that the parsing of cvss score information
            works regardless of superfluous spacing.
        """
        text = self.v3_text_example_4_4.replace('\n', '\n ')
        parsed = parse_cvss_format.parse_text_info_score(
            text)
        self.assertEqual(parsed['version'], 3.0)
        self.assertEqual(parsed['score'], 9.9)


if __name__ == "__main__":
    unittest.main()
