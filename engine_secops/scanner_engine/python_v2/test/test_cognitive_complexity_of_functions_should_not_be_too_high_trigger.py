# Noncompliant: should trigger cognitive_complexity_of_functions_should_not_be_too_high

def nc_function(a, b, c, d, e, f, g, h, i):
    x = a + b
    y = c * d
    z = e ** f
    w = g - h
    v = i / x ** 2
    u = x + y + z + w + v
    t = u * 2
    return w + z - v + t

# Compliant: should NOT trigger

def c_function(a, b):
    return a + b
