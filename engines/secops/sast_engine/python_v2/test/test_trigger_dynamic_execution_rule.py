import os
import subprocess

def test_os_system():
    # Noncompliant: triggers the rule
    os.system('echo dangerous')

def test_subprocess_run():
    # Noncompliant: triggers the rule
    subprocess.run(['echo', 'dangerous'])

def test_safe():
    # Compliant: does not trigger the rule
    print('Hello, World!')
