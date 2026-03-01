
# Ensure re is imported for regex usage
import re

def collect_leaf_properties(obj, parent_path=None):
    """
    Recursively collect all leaf properties in a dict/list, returning a dict of {full_path: value}.
    Handles dicts, lists, and primitive values.
    """
    if parent_path is None:
        parent_path = []
    leaves = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            leaves.update(collect_leaf_properties(v, parent_path + [k]))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            leaves.update(collect_leaf_properties(item, parent_path + [f"[{idx}]"]))
    else:
        # Primitive value
        path_str = '.'.join(parent_path).replace('.[', '[')
        leaves[path_str] = obj
    return leaves



class GenericRule:
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")

    @staticmethod
    def normalize_path(path):
        # Normalize property path: logging.0, logging[0], logging all become logging[0]
        if isinstance(path, list):
            norm = []
            for p in path:
                if isinstance(p, str) and re.match(r"^\d+$", p):
                    norm.append(f"[{p}]")
                elif isinstance(p, str) and re.match(r"^.+\[(\d+)\]$", p):
                    norm.append(p)
                else:
                    norm.append(str(p))
            return norm
        elif isinstance(path, str):
            # Convert 'foo.0.bar' to ['foo', '[0]', 'bar']
            parts = []
            for part in path.split('.'):
                if re.match(r"^\d+$", part):
                    parts.append(f"[{part}]")
                else:
                    parts.append(part)
            return parts
        return path

    def _get_properties_with_wildcard(self, obj, prop_path):
        """
        Recursively traverse obj following prop_path, supporting '*' as a wildcard for lists.
        Returns a list of (full_path, value) tuples found at the end of the path.
        """
        def helper(current, path, acc):
            if not path:
                return [(acc, current)]
            key = path[0]
            rest = path[1:]
            results = []
            if key == "*":
                if isinstance(current, list):
                    for idx, item in enumerate(current):
                        results.extend(helper(item, rest, acc + [f"[{idx}]"]))
            elif isinstance(current, dict) and key in current:
                results.extend(helper(current[key], rest, acc + [key]))
            elif isinstance(current, list):
                for idx, item in enumerate(current):
                    results.extend(helper(item, path, acc + [f"[{idx}]"]))
            return results
        return helper(obj, prop_path, [])

    def is_applicable(self, ast_tree):
        logic = self.logic
        resource_types = logic.get("resource_type", [])
        property_paths = logic.get("property_path", [])
        if resource_types == "*" or property_paths == "*":
            return True
        check_type = self.logic.get("check_type", "")
        for block in ast_tree.get('resource', []):
            for resource_type, resources in block.items():
                if resource_type in resource_types:
                    # For required_present, always applicable if resource_type matches
                    if check_type == "required_present":
                        return True
                    for resource_name, resource_body in resources.items():
                        for prop_path in property_paths:
                            prop_path_list = prop_path
                            matches = self._get_properties_with_wildcard(resource_body, prop_path_list)
                            if matches:
                                return True
        return False

    def check(self, ast_tree, filename):
        findings = []
        logic = self.logic
        resource_types = logic.get("resource_type", [])
        property_paths = logic.get("property_path", [])
        check_type = logic.get("check_type", "")
        forbidden_values = logic.get("forbidden_values", [])
        required_values = logic.get("required_values", [])
        regex_pattern = logic.get("regex", None)

        # Use the class's normalize_path method instead of a local function

        for block in ast_tree.get('resource', []):
            for resource_type, resources in block.items():
                for resource_name, resource_body in resources.items():
                    file_context = resource_body.get('_tf_file', filename)
                    # print(f"[rule_debug] Scanning resource: {resource_type}.{resource_name} in {file_context}")
                    if resource_types != "*" and resource_type not in resource_types:
                        continue
                    if check_type == "custom":
                        custom_func = logic.get("custom_function")
                        if custom_func == "flag_todo_comments":
                            for k, v in self._walk_dict(resource_body):
                                if isinstance(v, str) and "todo" in v.lower():
                                    findings.append(self._make_finding(file_context, resource_type, resource_name, [k], v, "TODO comment found"))
                            continue
                        elif custom_func == "check_tag_key_naming_convention":
                            for prop_path in property_paths:
                                prop_path_list = prop_path if isinstance(prop_path, list) else [prop_path]
                                matches = self._get_properties_with_wildcard(resource_body, prop_path_list)
                                for found_path, tags in matches:
                                    if isinstance(tags, dict):
                                        for tag_key in tags.keys():
                                            import re
                                            if not re.match(r'^[a-z][a-z0-9-]*$', tag_key):
                                                findings.append(self._make_finding(
                                                    file_context, resource_type, resource_name, found_path + [tag_key], tag_key,
                                                    f"Tag key '{tag_key}' does not comply with naming convention (lowercase, hyphens, no spaces/special chars, no leading numbers)"
                                                ))
                            continue
                    for prop_path in property_paths:
                        prop_path_list = self.normalize_path(prop_path)
                        # print(f"[rule_debug] Checking property_path: {prop_path_list}")
                        matches = self._get_properties_with_wildcard(resource_body, prop_path_list)
                        if not matches:
                            # print(f"[rule_debug] MISSING property: {prop_path_list}")
                            if check_type == "required_present":
                                findings.append(self._make_finding(file_context, resource_type, resource_name, prop_path_list, None, "Required property missing"))
                            continue
                        for found_path, value in matches:
                            # Unresolved reference check
                            if isinstance(value, str) and value.startswith("UNRESOLVED:"):
                                # print(f"[rule_debug] UNRESOLVED reference: {value}")
                                pass
                            # Rule logic
                            passed = True
                            fail_reason = None
                            if check_type == "equals":
                                if value not in required_values:
                                    passed = False
                                    fail_reason = f"Value {value} not in required_values {required_values}"
                            elif check_type == "not_contains":
                                if value in forbidden_values:
                                    passed = False
                                    fail_reason = f"Value {value} in forbidden_values {forbidden_values}"
                            elif check_type in ("in", "contains"):
                                forbidden_values_lower = [str(f).lower() for f in forbidden_values]
                                if isinstance(value, list):
                                    value_lower = [str(v).lower() for v in value]
                                    for forbidden in forbidden_values_lower:
                                        if forbidden in value_lower:
                                            passed = False
                                            fail_reason = f"Value {value} contains forbidden {forbidden}"
                                else:
                                    value_lower = str(value).lower()
                                    for forbidden in forbidden_values_lower:
                                        if value_lower == forbidden:
                                            passed = False
                                            fail_reason = f"Value {value} equals forbidden {forbidden}"
                            elif check_type == "min_value":
                                try:
                                    if float(value) < float(required_values[0]):
                                        passed = False
                                        fail_reason = f"Value {value} < min {required_values[0]}"
                                except Exception:
                                    passed = False
                                    fail_reason = "Value not numeric"
                            elif check_type == "required_present":
                                if value is None or value == "":
                                    passed = False
                                    fail_reason = "Required property missing"
                            elif check_type == "required_nonempty":
                                if value is None or value == "" or (isinstance(value, list) and not value):
                                    passed = False
                                    fail_reason = "Property is empty or missing"
                            elif check_type == "forbidden_empty":
                                if value is None or value == [] or value == "":
                                    passed = False
                                    fail_reason = "Property is empty or missing"
                            elif check_type == "regex" and regex_pattern:
                                if not re.match(regex_pattern, str(value)):
                                    passed = False
                                    fail_reason = f"Value {value} does not match regex {regex_pattern}"
                            # Log pass/fail
                            if passed:
                                # print(f"[rule_debug] Rule PASSED for {resource_type}.{resource_name} at {found_path}")
                                pass
                            else:
                                # print(f"[rule_debug] Rule FAILED for {resource_type}.{resource_name} at {found_path}: {fail_reason}")
                                findings.append(self._make_finding(file_context, resource_type, resource_name, found_path, value, fail_reason))
        return findings

    def _walk_dict(self, d, parent_key=None):
        # Recursively yield (key, value) for all string values in a dict
        if isinstance(d, dict):
            for k, v in d.items():
                full_key = k if parent_key is None else f"{parent_key}.{k}"
                if isinstance(v, dict):
                    yield from self._walk_dict(v, full_key)
                elif isinstance(v, list):
                    for idx, item in enumerate(v):
                        if isinstance(item, dict):
                            yield from self._walk_dict(item, f"{full_key}[{idx}]")
                        else:
                            yield f"{full_key}[{idx}]", item
                else:
                    yield full_key, v
        else:
            yield parent_key, d

    def _get_property(self, resource_body, prop_path):
        # prop_path can be a string or a list
        if isinstance(prop_path, str):
            prop_path = [prop_path]
        current = resource_body
        found_path = []
        for key in prop_path:
            if isinstance(current, dict) and key in current:
                current = current[key]
                found_path.append(key)
            elif isinstance(current, list):
                # If current is a list, try each item
                found = False
                for idx, item in enumerate(current):
                    if isinstance(item, dict) and key in item:
                        current = item[key]
                        found_path.append(f"{key}[{idx}]")
                        found = True
                        break
                if not found:
                    return None, found_path
            else:
                return None, found_path
        return current, found_path

    def _make_finding(self, filename, resource_type, resource_name, property_path, value, message=None):
        finding = {
            "rule_id": self.rule_id,
            "message": message or self.message,
            "resource": f"{resource_type}.{resource_name}",
            "file": filename,
            "property_path": property_path,
            "value": value,
            "status": "violation"
        }
        # Add severity if present in metadata
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        return finding
    @staticmethod
    def normalize_path(path):
        # Normalize property path: logging.0, logging[0], logging all become logging[0]
        if isinstance(path, list):
            norm = []
            for p in path:
                if isinstance(p, str) and re.match(r"^\d+$", p):
                    norm.append(f"[{p}]")
                elif isinstance(p, str) and re.match(r"^.+\[(\d+)\]$", p):
                    norm.append(p)
                else:
                    norm.append(str(p))
            return norm
        elif isinstance(path, str):
            # Convert 'foo.0.bar' to ['foo', '[0]', 'bar']
            parts = []
            for part in path.split('.'):
                if re.match(r"^\d+$", part):
                    parts.append(f"[{part}]")
                else:
                    parts.append(part)
            return parts
        return path

# Unit tests for normalize_path
def _test_normalize_path():
    np = GenericRule.normalize_path
    assert np("ingress.0.cidr_blocks") == ["ingress", "[0]", "cidr_blocks"], f"Failed: {np('ingress.0.cidr_blocks')}"
    assert np(["ingress", "*", "cidr_blocks"]) == ["ingress", "*", "cidr_blocks"], f"Failed: {np(['ingress', '*', 'cidr_blocks'])}"
    assert np(["ingress", "0", "cidr_blocks"]) == ["ingress", "[0]", "cidr_blocks"], f"Failed: {np(['ingress', '0', 'cidr_blocks'])}"
    assert np("foo.1.bar") == ["foo", "[1]", "bar"], f"Failed: {np('foo.1.bar')}"
    assert np("foo.bar") == ["foo", "bar"], f"Failed: {np('foo.bar')}"
    # print("normalize_path unit tests passed.")

if __name__ == "__main__":
    _test_normalize_path()

    def _get_properties_with_wildcard(self, obj, prop_path):
        """
        Recursively traverse obj following prop_path, supporting '*' as a wildcard for lists.
        Returns a list of (full_path, value) tuples found at the end of the path.
        """
        def helper(current, path, acc):
            if not path:
                return [(acc, current)]
            key = path[0]
            rest = path[1:]
            results = []
            if key == "*":
                if isinstance(current, list):
                    for idx, item in enumerate(current):
                        results.extend(helper(item, rest, acc + [f"[{idx}]"]))
            elif isinstance(current, dict) and key in current:
                results.extend(helper(current[key], rest, acc + [key]))
            elif isinstance(current, list):
                for idx, item in enumerate(current):
                    results.extend(helper(item, path, acc + [f"[{idx}]"]))
            return results
        return helper(obj, prop_path, [])
    def __init__(self, metadata):
        self.metadata = metadata
        self.logic = metadata.get("logic", {})
        self.rule_id = metadata.get("rule_id", "unknown_rule")
        self.message = metadata.get("title", "Rule violation")

    def is_applicable(self, ast_tree):
    # print(f"[DEBUG] Checking applicability for rule: {self.rule_id}")
        logic = self.logic
        resource_types = logic.get("resource_type", [])
        property_paths = logic.get("property_path", [])
    # print(f"[DEBUG] Resource types: {resource_types}")
    # print(f"[DEBUG] Property paths: {property_paths}")
        """
        Returns True if the AST contains at least one resource of the rule's resource_type
        and at least one property_path exists in any such resource, using wildcard-aware traversal.
        If resource_type or property_path is '*', treat as always applicable.
        """
        logic = self.logic
        resource_types = logic.get("resource_type", [])
        property_paths = logic.get("property_path", [])
        if resource_types == "*" or property_paths == "*":
            return True
        check_type = self.logic.get("check_type", "")
        for block in ast_tree.get('resource', []):
            for resource_type, resources in block.items():
                if resource_type in resource_types:
                    # For required_present, always applicable if resource_type matches
                    if check_type == "required_present":
                        return True
                    for resource_name, resource_body in resources.items():
                        for prop_path in property_paths:
                            prop_path_list = prop_path
                            matches = self._get_properties_with_wildcard(resource_body, prop_path_list)
                            if matches:
                                return True
        return False


    def check(self, ast_tree, filename):
        findings = []
        logic = self.logic
        resource_types = logic.get("resource_type", [])
        property_paths = logic.get("property_path", [])
        check_type = logic.get("check_type", "")
        forbidden_values = logic.get("forbidden_values", [])
        required_values = logic.get("required_values", [])
        regex_pattern = logic.get("regex", None)

        def normalize_path(path):
            # Normalize property path: logging.0, logging[0], logging all become logging[0]
            if isinstance(path, list):
                norm = []
                for p in path:
                    if isinstance(p, str) and re.match(r"^\d+$", p):
                        norm.append(f"[{p}]")
                    elif isinstance(p, str) and re.match(r"^.+\[(\d+)\]$", p):
                        norm.append(p)
                    else:
                        norm.append(str(p))
                return norm
            elif isinstance(path, str):
                return [path]
            return path

        for block in ast_tree.get('resource', []):
            for resource_type, resources in block.items():
                for resource_name, resource_body in resources.items():
                    file_context = resource_body.get('_tf_file', filename)
                    print(f"[rule_debug] Scanning resource: {resource_type}.{resource_name} in {file_context}")
                    if resource_types != "*" and resource_type not in resource_types:
                        continue
                    if check_type == "custom":
                        custom_func = logic.get("custom_function")
                        if custom_func == "flag_todo_comments":
                            for k, v in self._walk_dict(resource_body):
                                if isinstance(v, str) and "todo" in v.lower():
                                    findings.append(self._make_finding(file_context, resource_type, resource_name, [k], v, "TODO comment found"))
                            continue
                        elif custom_func == "check_tag_key_naming_convention":
                            for prop_path in property_paths:
                                prop_path_list = prop_path if isinstance(prop_path, list) else [prop_path]
                                matches = self._get_properties_with_wildcard(resource_body, prop_path_list)
                                for found_path, tags in matches:
                                    if isinstance(tags, dict):
                                        for tag_key in tags.keys():
                                            import re
                                            if not re.match(r'^[a-z][a-z0-9-]*$', tag_key):
                                                findings.append(self._make_finding(
                                                    file_context, resource_type, resource_name, found_path + [tag_key], tag_key,
                                                    f"Tag key '{tag_key}' does not comply with naming convention (lowercase, hyphens, no spaces/special chars, no leading numbers)"
                                                ))
                            continue
                    for prop_path in property_paths:
                        prop_path_list = normalize_path(prop_path)
                        print(f"[rule_debug] Checking property_path: {prop_path_list}")
                        matches = self._get_properties_with_wildcard(resource_body, prop_path_list)
                        if not matches:
                            print(f"[rule_debug] MISSING property: {prop_path_list}")
                            if check_type == "required_present":
                                findings.append(self._make_finding(file_context, resource_type, resource_name, prop_path_list, None, "Required property missing"))
                            continue
                        for found_path, value in matches:
                            # Unresolved reference check
                            if isinstance(value, str) and value.startswith("UNRESOLVED:"):
                                print(f"[rule_debug] UNRESOLVED reference: {value}")
                            # Rule logic
                            passed = True
                            fail_reason = None
                            if check_type == "equals":
                                if value not in required_values:
                                    passed = False
                                    fail_reason = f"Value {value} not in required_values {required_values}"
                            elif check_type == "not_contains":
                                if value in forbidden_values:
                                    passed = False
                                    fail_reason = f"Value {value} in forbidden_values {forbidden_values}"
                            elif check_type in ("in", "contains"):
                                forbidden_values_lower = [str(f).lower() for f in forbidden_values]
                                if isinstance(value, list):
                                    value_lower = [str(v).lower() for v in value]
                                    for forbidden in forbidden_values_lower:
                                        if forbidden in value_lower:
                                            passed = False
                                            fail_reason = f"Value {value} contains forbidden {forbidden}"
                                else:
                                    value_lower = str(value).lower()
                                    for forbidden in forbidden_values_lower:
                                        if value_lower == forbidden:
                                            passed = False
                                            fail_reason = f"Value {value} equals forbidden {forbidden}"
                            elif check_type == "min_value":
                                try:
                                    if float(value) < float(required_values[0]):
                                        passed = False
                                        fail_reason = f"Value {value} < min {required_values[0]}"
                                except Exception:
                                    passed = False
                                    fail_reason = "Value not numeric"
                            elif check_type == "required_present":
                                if value is None or value == "":
                                    passed = False
                                    fail_reason = "Required property missing"
                            elif check_type == "required_nonempty":
                                if value is None or value == "" or (isinstance(value, list) and not value):
                                    passed = False
                                    fail_reason = "Property is empty or missing"
                            elif check_type == "forbidden_empty":
                                if value is None or value == [] or value == "":
                                    passed = False
                                    fail_reason = "Property is empty or missing"
                            elif check_type == "regex" and regex_pattern:
                                if not re.match(regex_pattern, str(value)):
                                    passed = False
                                    fail_reason = f"Value {value} does not match regex {regex_pattern}"
                            # Log pass/fail
                            if passed:
                                print(f"[rule_debug] Rule PASSED for {resource_type}.{resource_name} at {found_path}")
                            else:
                                print(f"[rule_debug] Rule FAILED for {resource_type}.{resource_name} at {found_path}: {fail_reason}")
                                findings.append(self._make_finding(file_context, resource_type, resource_name, found_path, value, fail_reason))
        return findings

    def _walk_dict(self, d, parent_key=None):
        # Recursively yield (key, value) for all string values in a dict
        if isinstance(d, dict):
            for k, v in d.items():
                full_key = k if parent_key is None else f"{parent_key}.{k}"
                if isinstance(v, dict):
                    yield from self._walk_dict(v, full_key)
                elif isinstance(v, list):
                    for idx, item in enumerate(v):
                        if isinstance(item, dict):
                            yield from self._walk_dict(item, f"{full_key}[{idx}]")
                        else:
                            yield f"{full_key}[{idx}]", item
                else:
                    yield full_key, v
        else:
            yield parent_key, d

    def _get_property(self, resource_body, prop_path):
        # prop_path can be a string or a list
        if isinstance(prop_path, str):
            prop_path = [prop_path]
        current = resource_body
        found_path = []
        for key in prop_path:
            if isinstance(current, dict) and key in current:
                current = current[key]
                found_path.append(key)
            elif isinstance(current, list):
                # If current is a list, try each item
                found = False
                for idx, item in enumerate(current):
                    if isinstance(item, dict) and key in item:
                        current = item[key]
                        found_path.append(f"{key}[{idx}]")
                        found = True
                        break
                if not found:
                    return None, found_path
            else:
                return None, found_path
        return current, found_path

    def _make_finding(self, filename, resource_type, resource_name, property_path, value, message=None):
        finding = {
            "rule_id": self.rule_id,
            "message": message or self.message,
            "resource": f"{resource_type}.{resource_name}",
            "file": filename,
            "property_path": property_path,
            "value": value,
            "status": "violation"
        }
        # Add severity if present in metadata
        if "severity" in self.metadata:
            finding["severity"] = self.metadata["severity"]
        return finding
