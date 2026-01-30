# This should trigger the rule: cookie created without HttpOnly flag
cookies.set('cookie_name', 'vulnerable_value', httponly=False)

# These should NOT trigger the rule
cookies.set('cookie_name', 'safe_value', httponly=True)
cookies.set('cookie_name', 'other_value')
