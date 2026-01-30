# This should trigger the rule: type constructor wrapping literal or comprehension
my_list = list([1, 2, 3])
my_dict = dict([('a', 1), ('b', 2)])
my_set = set({1, 2, 3})
my_list_comp = list([x for x in range(5)])

# These should NOT trigger the rule
my_list = [1, 2, 3]
my_dict = {'a': 1, 'b': 2}
my_set = {1, 2, 3}
my_list_comp = [x for x in range(5)]
