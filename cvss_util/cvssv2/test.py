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

    def test_get_severity_description_low(self):
        """ tests that get_severity_description works as expected with
            the low rating.
        """
        for value in [0.0, 2.9]:
            self.assertEqual(
                calculator.get_severity_description(value), 'Low')

    def test_get_severity_description_medium(self):
        """ tests that get_severity_description works as expected with
            the medium rating.
        """
        for value in [3.0, 5.9]:
            self.assertEqual(
                calculator.get_severity_description(value), 'Medium')

    def test_get_severity_description_high(self):
        """ tests that get_severity_description works as expected with
            the high rating.
        """
        for value in [6.0, 7.9]:
            self.assertEqual(
                calculator.get_severity_description(value), 'High')

    def test_get_severity_description_critical(self):
        """ tests that get_severity_description works as expected with
            the critical rating.
        """
        for value in [8.0, 10.0]:
            self.assertEqual(
                calculator.get_severity_description(value), 'Critical')

    def test_get_base_vector_string_dict(self):
        """ tests that the get_base_vector_string_dict works as expected. """
        map = calculator.get_base_vector_string_dict()
        for key, expected in (
                ('L', 'Local'),
                ('A', 'Adjacent Network'),
                ('N', 'Network')):
            self.assertEqual(map['av'][key], expected)
        for key, expected in (
                ('H', 'High'),
                ('M', 'Medium'),
                ('L', 'Low')):
            self.assertEqual(map['ac'][key], expected)
        for key, expected in (
                ('M', 'Multiple'),
                ('S', 'Single'),
                ('N', 'None')):
            self.assertEqual(map['au'][key], expected)
        for impact in ['c', 'i', 'a']:
            for key, expected in (
                    ('N', 'None'),
                    ('P', 'Partial'),
                    ('C', 'Complete')):
                self.assertEqual(map[impact][key], expected)


if __name__ == "__main__":
    unittest.main()
