import pandas as pd

def test_missing_dtype():
    # Noncompliant: dtype parameter missing
    df = pd.read_csv('file.csv')
    return df

def test_with_dtype():
    # Compliant: dtype parameter provided
    df = pd.read_csv('file.csv', dtype={'column1': str, 'column2': int})
    return df
