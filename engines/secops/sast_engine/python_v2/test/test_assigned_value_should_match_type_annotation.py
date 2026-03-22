# Noncompliant: type annotation does not match assigned value
x: int = "hello"  # should trigger
name: str = 123    # should trigger
y: float = True    # should trigger
flag: bool = 0     # should trigger

# Compliant: type annotation matches assigned value
z: int = 42
s: str = "world"
f: float = 3.14
b: bool = False
