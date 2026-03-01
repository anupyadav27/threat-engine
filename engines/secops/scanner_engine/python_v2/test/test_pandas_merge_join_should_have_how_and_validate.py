import pandas as pd
df1 = pd.DataFrame({'a': [1, 2]})
df2 = pd.DataFrame({'a': [3, 4]})

# Noncompliant: missing 'how' and 'validate'
df1.merge(df2)
df1.join(df2)

# Compliant: both parameters provided
df1.merge(df2, how='inner', validate='one_to_one')
df1.join(df2, how='left', validate='one_to_many')
