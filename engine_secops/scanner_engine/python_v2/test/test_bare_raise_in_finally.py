# Test script to trigger bare_raise_statements_should_not_be_used_in_finally_blocks rule only

def foo():
    try:
        pass
    finally:
        raise
