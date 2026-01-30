def create_dict_with_duplicate_keys():
    # This will trigger the rule: duplicate keys in dictionary creation
    data = {'key1': 1, 'key1': 2}
    print(data)

if __name__ == "__main__":
    create_dict_with_duplicate_keys()
