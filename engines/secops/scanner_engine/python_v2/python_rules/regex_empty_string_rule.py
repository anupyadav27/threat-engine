"""Rule to check for regex patterns that can match empty strings."""
from .. import logic_implementations
from ..python_generic_rule import PythonGenericRule

class RegexEmptyStringRule(PythonGenericRule):
    """Rule class for detecting regex patterns that can match empty strings."""

    def _visit_Call(self, node):
        """Visit Call nodes to check for regex patterns."""
        if logic_implementations.has_repeated_empty_match_pattern(node):
            self.add_violation('Regular expression should not contain patterns that can match empty strings', node)
        return True