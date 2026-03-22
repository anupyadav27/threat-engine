# This should trigger the rule: using a constant as a condition
if True:
    pass

while 0:
    pass

# These should NOT trigger the rule
foo = 1
if foo:
    pass
bar = False
while bar:
    pass
