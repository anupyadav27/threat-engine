# Noncompliant: vulnerable XML parser usage
from xml.etree.ElementTree import parse

data = parse('data.xml')

# Compliant: safer XML parser usage
from lxml import etree
safe_data = etree.XML('<root></root>')
