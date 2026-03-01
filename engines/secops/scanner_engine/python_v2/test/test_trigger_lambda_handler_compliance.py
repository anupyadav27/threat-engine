# Test to trigger lambda_handler_compliance_check rule

import tempfile
import os

async def lambda_handler(event, context):
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file.write(b'some data')
    os.system("rm -f /tmp/*")
    return [1, 2, 3]  # Not JSON serializable
