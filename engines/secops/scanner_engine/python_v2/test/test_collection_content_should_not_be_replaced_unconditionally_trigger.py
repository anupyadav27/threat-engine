# Noncompliant: should trigger collection_content_should_not_be_replaced_unconditionally
my_list = [1, 2, 3, 4]
for i in range(len(my_list)):
    my_list[i] = 'replacement'

# Compliant: should NOT trigger
condition = True
if condition:
    for i in range(len(my_list)):
        my_list[i] = 'replacement'
