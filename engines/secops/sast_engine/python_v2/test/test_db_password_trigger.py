import psycopg2

def test_hardcoded_password():
    # This should trigger the rule
    db = psycopg2.connect(dbname='mydb', user='myuser', password='password123')
    return db

def test_weak_password():
    # This should also trigger the rule
    db = psycopg2.connect(dbname='mydb', user='myuser', password='myweakpassword')
    return db

def test_secure_password():
    # This should NOT trigger the rule
    import os
    db = psycopg2.connect(dbname='mydb', user='myuser', password=os.environ['DB_PASSWORD'])
    return db
