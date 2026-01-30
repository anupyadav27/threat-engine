def test():
    try:
        raise ValueError('Test error')
    except ValueError:
        raise ValueError('Test error')
