# Test for: results_that_depend_on_random_number_generation_should_be_reproducible
import random

# Noncompliant: No seeding, should trigger the rule
result = random.random()

# Compliant: Seeding, should NOT trigger the rule
random.seed(42)
result2 = random.random()
