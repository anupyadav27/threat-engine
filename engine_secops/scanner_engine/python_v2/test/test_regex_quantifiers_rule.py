import re

# Noncompliant: Unbounded quantifier
pattern1 = re.compile(r"abc{3,}")

# Noncompliant: Redundant character class [\w\W]
pattern2 = re.compile(r"[\w\W]+text")

# Noncompliant: Repeated character classes
pattern3 = re.compile(r"[a-zA-Z]+[a-zA-Z]+[a-zA-Z]+")

# Noncompliant: Multiple negated classes
pattern4 = re.compile(r"[^\w\s]+[^\w\s]+")

# Noncompliant: Adjacent similar classes
pattern5 = re.compile(r"[\w][\w]+")

# Noncompliant: Multiple consecutive quantifiers
pattern6 = re.compile(r"(\w+?)++")

# Noncompliant: Excessive character classes
pattern7 = re.compile(r"[\w\s\d]+[^\d\w\s]+[\p{Punct}\p{Zs}]+")

# Compliant examples
pattern8 = re.compile(r"abc{3}")  # Fixed quantifier
pattern9 = re.compile(r".+text")  # Simple dot instead of [\w\W]
pattern10 = re.compile(r"[a-zA-Z]{3}")  # Single character class with count
pattern11 = re.compile(r"[^\w\s]")  # Single negated class
pattern12 = re.compile(r"\w+")  # Simple word characters
pattern13 = re.compile(r"(\w+)")  # Simple capturing group
pattern14 = re.compile(r"[\w\s]+")  # Single character class