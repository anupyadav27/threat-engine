# Test script to trigger only the break_continue_and_return_statements_should_not_occur_in_finally_blocks rule
def test_return_in_finally():
    try:
        pass
    finally:
        return  # Should trigger: return in finally block

def test_break_in_finally():
    while True:
        try:
            pass
        finally:
            break  # Should trigger: break in finally block
        break

def test_continue_in_finally():
    for i in range(1):
        try:
            pass
        finally:
            continue  # Should trigger: continue in finally block

if __name__ == "__main__":
    test_return_in_finally()
    test_break_in_finally()
    test_continue_in_finally()
