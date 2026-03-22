import ssl
# Noncompliant: uses weak protocol
context1 = ssl.create_default_context(ssl.PROTOCOL_TLSv1_1)
context2 = ssl.create_default_context(ssl.PROTOCOL_SSLv3)

# Compliant: uses strong protocol
context3 = ssl.create_default_context(ssl.PROTOCOL_TLSv1_2)
context4 = ssl.create_default_context(ssl.PROTOCOL_TLSv1_3)
