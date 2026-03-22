# Noncompliant: should trigger collection_sizes_and_array_length_comparisons_should_make_sense
my_list = [1, 2, 3]
my_other_list = [4, 5]
if len(my_list) > 5 > len(my_other_list):
    pass

# Compliant: should NOT trigger
if len(my_list) > len(my_other_list):
    pass
