from django import forms

class MyForm(forms.ModelForm):
    class Meta:
        model = None
        fields_specified = ('field1', 'field2')  # This should trigger the rule

def show_fields():
    print(MyForm.Meta.fields_specified)

if __name__ == "__main__":
    show_fields()
