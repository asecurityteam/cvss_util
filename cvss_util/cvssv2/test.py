#!/usr/bin/python
import unittest

from . import calculator


class TestCVSSCalculator(unittest.TestCase):

    def test_high_score(self):
        """ tests scoring a persistent xss """
        impact = calculator.get_impact_score('partial',
                                             'partial', 'partial')
        exploit = calculator.get_exploitability_score('network',
                                                      'low', 'single')
        score = round(calculator.calc_base_score(impact, exploit), 1)
        severity = calculator.get_severity_description(score)
        self.assertEqual(score, 6.5)
        self.assertEqual(round(impact, 2), 6.44)
        self.assertEqual(exploit, 7.952)
        self.assertEqual(severity, 'High')

    def test_critical_score(self):
        """ tests scoring a critical issue. """
        exploit = calculator.get_exploitability_score(
            'network',
            'low',
            'single',
        )
        impact = calculator.get_impact_score(
            'Complete',
            'Complete',
            'Complete',
        )
        score = round(calculator.calc_base_score(impact, exploit), 1)
        severity = calculator.get_severity_description(score)
        self.assertEqual(score, 9)
        self.assertEqual(severity, 'Critical')

    def test_example_5_3_score(self):
        """ tests calculating the cvss score of example 5.3
            (base score 4.6) from https://www.first.org/cvss/examples.
        """
        exploit = calculator.get_exploitability_score(
            'local',
            'low',
            'none',
        )
        impact = calculator.get_impact_score(
            'partial',
            'partial',
            'partial',
        )
        score = round(calculator.calc_base_score(impact, exploit), 1)
        severity = calculator.get_severity_description(score)
        self.assertEqual(score, 4.6)
        self.assertEqual(severity, 'Medium')

    def test_low_score(self):
        """ tests calculating the cvss score of a low severity issue. """
        exploit = calculator.get_exploitability_score(
            'local',
            'low',
            'Single',
        )
        impact = calculator.get_impact_score(
            'partial',
            'none',
            'none',
        )
        score = round(calculator.calc_base_score(impact, exploit), 1)
        severity = calculator.get_severity_description(score)
        self.assertEqual(score, 1.7)
        self.assertEqual(severity, 'Low')


if __name__ == "__main__":
    unittest.main()
