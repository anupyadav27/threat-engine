# Noncompliant: triggers cipher_block_chaining_ivs_should_be_unpredictable
iv = 0x00  # Should trigger the rule
for i in range(16):
    block = None  # placeholder for block object
    # block.encrypt(iv)
    iv += 1

# Compliant: does not trigger
import os
iv_random = os.urandom(16)

from datetime import datetime
iv_time = datetime.now().timetuple() + (datetime.now().microsecond // 8) * 2
