# Minimal test to trigger: any_should_not_be_used_as_a_type_hint

def func(arg: any) -> str:
    return str(arg)

# Keep the file minimal to avoid triggering unrelated rules
