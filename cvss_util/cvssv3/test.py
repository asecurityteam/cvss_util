#!/usr/bin/python
import unittest

from . import calculator


class TestCVSS3Calculator(unittest.TestCase):

    def test_score_example_4_4(self):
        """ tests calculating the cvss score of example 4.4
            (base score 9.9) from https://www.first.org/cvss/examples.
        """
        scope = 'Changed'
        exploitability_sub_score = calculator.get_exploitability_sub_score(
            'network',
            'low',
            'low',
            'none',
            scope,
        )
        isc_base = calculator.get_impact_sub_score_base(
            'high',
            'high',
            'high')
        impact_sub_score = calculator.get_impact_sub_score(isc_base, scope)
        base_score = calculator.compute_base_score(
            impact_sub_score, exploitability_sub_score, scope)
        self.assertEqual('%s' % base_score, '9.9')

    def test_score_example_3_4(self):
        """ tests calculating the cvss score of example 3.4
            (base score 3.1) from https://www.first.org/cvss/examples.
        """
        scope = 'Unchanged'
        exploitability_dict = {
            'attack_vector': 'network',
            'attack_complexity': 'high',
            'privileges_required': 'none',
            'user_interaction': 'required',
        }
        impact_dict = {
            'confidentiality': 'Low',
            'integrity': 'none',
            'availability': 'none',
        }
        base_score = calculator.compute_base_score_from_dicts(
            exploitability_dict, impact_dict, scope)
        self.assertEqual('%s' % base_score, '3.1')

    def test_score_low_severity_example(self):
        """ tests calculating a low severity cvss v3 issue
            (base score 1.8)
        """
        scope = 'Changed'
        exploitability_dict = {
            'attack_vector': 'physical',
            'attack_complexity': 'high',
            'privileges_required': 'high',
            'user_interaction': 'required',
        }
        impact_dict = {
            'confidentiality': 'Low',
            'integrity': 'none',
            'availability': 'none',
        }
        base_score = calculator.compute_base_score_from_dicts(
            exploitability_dict, impact_dict, scope)
        self.assertEqual('%s' % base_score, '1.8')

    def test_score_high_privileges_required_unchanged_scope(self):
        """ tests calculating a low severity cvss v3 issue
            (base score 1.8)
        """
        scope = 'Unchanged'
        exploitability_dict = {
            'attack_vector': 'network',
            'attack_complexity': 'low',
            'privileges_required': 'high',
            'user_interaction': 'none',
        }
        impact_dict = {
            'confidentiality': 'Low',
            'integrity': 'Low',
            'availability': 'Low',
        }
        base_score = calculator.compute_base_score_from_dicts(
            exploitability_dict, impact_dict, scope)
        self.assertEqual('%s' % base_score, '4.7')

    def test_get_severity_description_none(self):
        """ tests that get_severity_description works as expected with
            the none rating.
        """
        self.assertEqual(
            calculator.get_severity_description(0.0), 'None')

    def test_get_severity_description_low(self):
        """ tests that get_severity_description works as expected with
            the low rating.
        """
        for value in [0.1, 3.9]:
            self.assertEqual(
                calculator.get_severity_description(value), 'Low')

    def test_get_severity_description_medium(self):
        """ tests that get_severity_description works as expected with
            the medium rating.
        """
        for value in [4.0, 6.9]:
            self.assertEqual(
                calculator.get_severity_description(value), 'Medium')

    def test_get_severity_description_high(self):
        """ tests that get_severity_description works as expected with
            the high rating.
        """
        for value in [7.0, 8.9]:
            self.assertEqual(
                calculator.get_severity_description(value), 'High')

    def test_get_severity_description_critical(self):
        """ tests that get_severity_description works as expected with
            the critical rating.
        """
        for value in [9.0, 10.0]:
            self.assertEqual(
                calculator.get_severity_description(value), 'Critical')

    def test_get_attack_vector_value_with_adjacent_keys(self):
        """ tests that the get_attack_vector_value method works as expected
            with the various adjacent vector keys.
        """
        for key in ['adjacent', 'adjacent network']:
            self.assertEqual(calculator.get_attack_vector_value(key), 0.62)

    def test_get_base_vector_string_dict(self):
        """ tests that the get_base_vector_string_dict works as expected. """
        map = calculator.get_base_vector_string_dict()
        for key, expected in (
                ('N', 'Network'),
                ('A', 'Adjacent'),
                ('L', 'Local'),
                ('P', 'Physical')):
            self.assertEqual(map['av'][key], expected)
        for key, expected in (
                ('L', 'Low'),
                ('H', 'High')):
            self.assertEqual(map['ac'][key], expected)
        for key, expected in (
                ('N', 'None'),
                ('L', 'Low'),
                ('H', 'High')):
            self.assertEqual(map['pr'][key], expected)
        for key, expected in (
                ('N', 'None'),
                ('R', 'Required')):
            self.assertEqual(map['ui'][key], expected)
        for key, expected in (
                ('U', 'Unchanged'),
                ('C', 'Changed')):
            self.assertEqual(map['s'][key], expected)
        for impact in ['c', 'i', 'a']:
            for key, expected in (
                    ('N', 'None'),
                    ('L', 'Low'),
                    ('H', 'High')):
                self.assertEqual(map[impact][key], expected)


if __name__ == "__main__":
    unittest.main()
