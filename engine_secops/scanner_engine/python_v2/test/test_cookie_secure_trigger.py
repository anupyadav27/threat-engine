import http.cookies

# This should trigger the rule: cookie created without secure flag
session_cookie = http.cookies.SimpleCookie()
session_cookie['user'] = 'John Doe'
session_cookie['user'].secure = False
session.set_cookie(session_cookie)

# These should NOT trigger the rule
session_cookie['user'].secure = True
session.set_cookie(session_cookie)
