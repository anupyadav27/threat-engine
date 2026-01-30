def create_set_with_duplicates():
    # This will trigger the rule: set with duplicate values
    s = {1, 1, 2, 3}
    print(s)

if __name__ == "__main__":
    create_set_with_duplicates()
