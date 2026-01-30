# Noncompliant: insecure XML signature validation
from xml.etree.ElementTree import parse

signature = parse('insecure.xml').getroot()
signature.verify(key_file='insecure_key.pem')

# Compliant: secure XML signature validation
from xml.lib.xmlsignatures import validate
signature2 = parse('secure.xml').getroot()
validate(signature2, key_file='secure_key.pem')
