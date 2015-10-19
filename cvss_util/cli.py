#!/usr/bin/python
from __future__ import print_function
import argparse

from cvss_util.cvssv2 import calculator


def setup_args():
    parser = argparse.ArgumentParser(description='CVSS Calculator')
    parser.add_argument(
        '-av',
        '--AccessVector',
        dest='AccessVector',
        choices=[
            'local',
            'adjacent',
            'network'],
        required=True)
    parser.add_argument('-ac', '--AccessComplexity', dest='AccessComplexity',
                        choices=['low', 'medium', 'high'], required=True)
    parser.add_argument('-a', '--Authentication', dest='Authentication',
                        choices=['none', 'single', 'multiple'], required=True)
    _impact_choices = ('none', 'partial', 'complete')
    parser.add_argument('-c', '--ConfImpact', dest='ConfImpact',
                        choices=_impact_choices, default='none')
    parser.add_argument('-i', '--IntegImpact', dest='IntegImpact',
                        choices=_impact_choices, default='none')
    parser.add_argument('-ai', '--AvailImpact', dest='AvailImpact',
                        choices=_impact_choices, default='none')
    return parser


def main():
    parser = setup_args()
    args = parser.parse_args()
    impact_s = calculator.get_impact_score(args.ConfImpact,
                                           args.IntegImpact, args.AvailImpact)
    exploit_s = calculator.get_exploitability_score(
        args.AccessVector,
        args.AccessComplexity,
        args.Authentication)
    score = round(calculator.calc_base_score(impact_s, exploit_s), 1)
    severity = calculator.get_severity_description(score)
    print(severity, abs(score))

if __name__ == "__main__":
    main()
