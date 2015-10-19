#!/usr/bin/python
import unittest

from . import parse_cvss_format


class TestCVSSParser(unittest.TestCase):

    def test_parse_critical_cvss_v2(self):
        """ tests parsing a critical cvss v2 score """
        text = """
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
        parsed = parse_cvss_format.parse_text_info_score(text)
        self.assertEqual(parsed['version'], 2.0)
        self.assertEqual(parsed['score'], 10)
        self.assertEqual(parsed['AccessVector'], 'Network')
        self.assertEqual(parsed['AccessComplexity'], 'Low')
        self.assertEqual(parsed['Authentication'], 'None')
        for key in ['ConfImpact', 'IntegImpact', 'AvailImpact']:
            self.assertEqual(parsed[key], 'Complete')

    def test_parse_cvss_v3_example_4_4(self):
        """ tests parsing & calculating the cvss v3 score of example 4.4
            (base score 9.9) from https://www.first.org/cvss/examples.
        """
        text = """
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
        parsed = parse_cvss_format.parse_text_info_score(text)
        self.assertEqual(parsed['version'], 3.0)
        self.assertEqual(parsed['score'], 9.9)
        self.assertEqual(parsed['Attack Vector'], 'Network')
        self.assertEqual(parsed['Attack Complexity'], 'Low')
        self.assertEqual(parsed['Privileges Required'], 'Low')
        for key in ['Confidentiality', 'Integrity', 'Availability']:
            self.assertEqual(parsed[key], 'High')


if __name__ == "__main__":
    unittest.main()
