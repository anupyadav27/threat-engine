"""
Test for: fields_of_a_django_modelfom_should_be_defined_explicitly rule
This should trigger the rule when 'fields_specified' is assigned inside Meta class of a ModelForm.
"""
from django import forms

class MyForm(forms.ModelForm):
    class Meta:
        fields_specified = ['field1', 'field2']
        model = None
