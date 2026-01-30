# Noncompliant: self-assignment
x = x

def main():
    print(foo())  # foo not defined yet
    def foo():
        return 42

# Noncompliant: undeclared variable usage
y = z + 1  # z not defined

# Compliant: proper definition before usage
def foo():
    return 42

def main2():
    print(foo())

# Compliant: use of built-in
print(len([1,2,3]))
