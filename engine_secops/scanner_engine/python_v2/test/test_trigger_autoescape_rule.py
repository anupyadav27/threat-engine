# Noncompliant example: disabling autoescaping
from jinja2 import Template

template = Template('Hello {{ name }}')
template.autoescape = False

# Compliant example: enabling autoescaping
template2 = Template('Hello {{ name }}')
template2.autoescape = True
