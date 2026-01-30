
import pandas as pd

def test_trigger():
    # This should trigger the rule: forbidden date format with dayfirst=True
    import ast
    source = "pd.to_datetime('2023-02-01', dayfirst=True)"
    tree = ast.parse(source)
    import pprint
    pprint.pprint(ast.dump(tree, indent=2))
    pd.to_datetime('2023-02-01', dayfirst=True)

if __name__ == "__main__":
    test_trigger()
