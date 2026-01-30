# Test for: type_aliases_should_be_declared_with_a_type_statement
# This should trigger the rule for missing type statement in type alias

# Noncompliant: should trigger the rule
T = TypeVar('T')

def function(arg: T) -> T:
    return arg + 1

# Compliant: should NOT trigger the rule
from typing import TypeVar
U: TypeVar = TypeVar('U')

def function2(arg: U) -> U:
    return arg + 1
