from datetime import datetime

# These should trigger the rule (out-of-range constructor attributes)
d1 = datetime(2022, 13, 32)  # month 13, day 32

d2 = datetime(2022, 2, -1)   # day -1

# These should NOT trigger the rule (valid constructor attributes)
d3 = datetime(2022, 2, 28)
d4 = datetime(2022, 12, 31)
