# Test file to trigger 'a_field_should_not_duplicate_the_name_of_its_containing_class' rule

class Guest:
    Guest = 1  # This should trigger the rule

class NotGuest:
    something_else = 2  # This should not trigger the rule
