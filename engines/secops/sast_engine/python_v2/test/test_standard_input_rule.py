# Test script to trigger the 'reading_the_standard_input_is_securitysensitive' rule

def test_input():
    # Noncompliant: should trigger the rule
    x = input()
    return x

def test_raw_input():
    # Noncompliant: should trigger the rule
    y = raw_input()
    return y

def test_sys_stdin_read():
    # Noncompliant: should trigger the rule
    import sys
    z = sys.stdin.read()
    return z

# Compliant example (should NOT trigger the rule)
def test_compliant():
    import sys
    config = sys.argv[1]
    return config
