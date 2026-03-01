# Noncompliant: unused private nested class
class Outer:
    class _Inner:
        pass

# _Inner is never used

def main():
    pass

if __name__ == "__main__":
    main()
