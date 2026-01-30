import re

# Noncompliant: Contains multiple spaces, should trigger the rule
pattern1 = re.compile('a  b')
pattern2 = re.compile('.*  .*')
pattern3 = re.compile('word    word')

# Compliant: Contains only single spaces, should NOT trigger the rule
pattern4 = re.compile('a b')
pattern5 = re.compile('.* .*')
pattern6 = re.compile('word word')
