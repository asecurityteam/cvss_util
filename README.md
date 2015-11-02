This package contains cvss v2 and v3 calculation utilities.
After this package has been installed the command line cvss v2 calculator
from this package can be accessed by running:

    python -m cvss_util.

For example,
```python
python -m cvss_util.cli -av network -ac high -a none -c complete
Medium 5.4
````

Run `python -m cvss_util.cli -h` to see further usage information.

```python
python -m cvss_util.cli -h
usage: cli.py [-h] -av {local,adjacent,network} -ac {low,medium,high} -a
              {none,single,multiple} [-c {none,partial,complete}]
              [-i {none,partial,complete}] [-ai {none,partial,complete}]

CVSS Calculator

optional arguments:
  -h, --help            show this help message and exit
  -av {local,adjacent,network}, --AccessVector {local,adjacent,network}
  -ac {low,medium,high}, --AccessComplexity {low,medium,high}
  -a {none,single,multiple}, --Authentication {none,single,multiple}
  -c {none,partial,complete}, --ConfImpact {none,partial,complete}
  -i {none,partial,complete}, --IntegImpact {none,partial,complete}
  -ai {none,partial,complete}, --AvailImpact {none,partial,complete}
```


[![Build Status](https://travis-ci.org/asecurityteam/cvss_util.svg?branch=master)](https://travis-ci.org/asecurityteam/cvss_util)
