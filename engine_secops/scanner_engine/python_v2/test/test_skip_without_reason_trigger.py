import pytest

def test_should_trigger_skip_without_reason():
    @pytest.mark.skip
    def inner():
        pass
    inner()

def test_should_not_trigger_skip_with_reason():
    @pytest.mark.skip(reason="Known issue")
    def inner():
        pass
    inner()
