def test_trigger():
def fake_defaultdict(**kwargs):
    pass

def test_trigger():
    # This should trigger the rule: using default_factory as a keyword argument
    d = fake_defaultdict(default_factory=lambda: 'Noncompliant')

if __name__ == "__main__":
    test_trigger()
