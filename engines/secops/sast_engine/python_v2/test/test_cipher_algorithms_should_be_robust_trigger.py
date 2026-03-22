# Noncompliant: triggers cipher_algorithms_should_be_robust
from Crypto.Cipher import DES, RC4, Blowfish, AES

des_cipher = DES.new(b"abcdefgh")  # Should trigger the rule
rc4_cipher = RC4.new(b"abcdefgh")  # Should trigger the rule
blowfish_cipher = Blowfish.new(b"abcdefgh")  # Should trigger the rule

aes_cipher = AES.new(b"abcdefghabcdefgh")  # Compliant, should not trigger
