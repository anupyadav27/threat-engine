import os
import uuid
import yaml
from datetime import datetime
from typing import Any, Dict, List, Optional

ALLOWED_EFFECTS = {"mark_skipped", "exempt_results", "skip_check", "skip_service"}


def _config_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))


def _load_yaml(path: str) -> Any:
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def _save_yaml(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)
    os.replace(tmp, path)


def add_service_exception(
    service_name: str,
    effect: str,
    selector: Dict[str, Any],
    reason: str,
    expires_at: Optional[str] = None,
    ex_id: Optional[str] = None,
) -> Dict[str, Any]:
    if effect not in ALLOWED_EFFECTS:
        raise ValueError(f"effect must be one of {sorted(ALLOWED_EFFECTS)}")
    exception_entry: Dict[str, Any] = {
        "id": ex_id or f"svc-{uuid.uuid4().hex[:8]}",
        "effect": effect,
        "selector": selector or {},
        "reason": reason,
    }
    if expires_at:
        # validate iso format
        datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        exception_entry["expires_at"] = expires_at

    path = os.path.join(_config_dir(), "service_list.yaml")
    data = _load_yaml(path)
    updated = False
    for svc in data.get("services", []) or []:
        if svc.get("name") == service_name:
            svc.setdefault("exceptions", [])
            svc["exceptions"].append(exception_entry)
            updated = True
            break
    if not updated:
        raise ValueError(f"service not found: {service_name}")
    _save_yaml(path, data)
    return exception_entry


def add_check_exception(
    check_id: str,
    effect: str,
    selector: Dict[str, Any],
    reason: str,
    expires_at: Optional[str] = None,
    ex_id: Optional[str] = None,
) -> Dict[str, Any]:
    if effect not in ALLOWED_EFFECTS:
        raise ValueError(f"effect must be one of {sorted(ALLOWED_EFFECTS)}")
    exception_entry: Dict[str, Any] = {
        "id": ex_id or f"chk-{uuid.uuid4().hex[:8]}",
        "check_id": check_id,
        "effect": effect,
        "selector": selector or {},
        "reason": reason,
    }
    if expires_at:
        datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        exception_entry["expires_at"] = expires_at

    path = os.path.join(_config_dir(), "check_exceptions.yaml")
    data = _load_yaml(path)
    data.setdefault("exceptions", [])
    data["exceptions"].append(exception_entry)
    _save_yaml(path, data)
    return exception_entry


def list_service_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "service_list.yaml")
    data = _load_yaml(path)
    output: List[Dict[str, Any]] = []
    for svc in data.get("services", []) or []:
        for ex in svc.get("exceptions", []) or []:
            output.append({**ex, "service": svc.get("name")})
    return output


def list_check_exceptions() -> List[Dict[str, Any]]:
    path = os.path.join(_config_dir(), "check_exceptions.yaml")
    data = _load_yaml(path)
    return list(data.get("exceptions", []) or [])


# I am adding an update_exception function to modify existing exceptions in place.
def update_exception(
    ex_id: str,
    *,
    effect: Optional[str] = None,
    selector: Optional[Dict[str, Any]] = None,
    reason: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    if effect is not None and effect not in ALLOWED_EFFECTS:
        raise ValueError(f"effect must be one of {sorted(ALLOWED_EFFECTS)}")

    # Try service_list.yaml
    svc_path = os.path.join(_config_dir(), "service_list.yaml")
    svc = _load_yaml(svc_path)
    for s in svc.get("services", []) or []:
        for ex in s.get("exceptions", []) or []:
            if ex.get("id") == ex_id:
                if effect is not None:
                    ex["effect"] = effect
                if selector is not None:
                    ex["selector"] = selector
                if reason is not None:
                    ex["reason"] = reason
                if expires_at is not None:
                    if expires_at == "":
                        ex.pop("expires_at", None)
                    else:
                        datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                        ex["expires_at"] = expires_at
                _save_yaml(svc_path, svc)
                return {**ex, "service": s.get("name")}

    # Try check_exceptions.yaml
    chk_path = os.path.join(_config_dir(), "check_exceptions.yaml")
    chk = _load_yaml(chk_path)
    for ex in chk.get("exceptions", []) or []:
        if ex.get("id") == ex_id:
            if effect is not None:
                ex["effect"] = effect
            if selector is not None:
                ex["selector"] = selector
            if reason is not None:
                ex["reason"] = reason
            if expires_at is not None:
                if expires_at == "":
                    ex.pop("expires_at", None)
                else:
                    datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    ex["expires_at"] = expires_at
            _save_yaml(chk_path, chk)
            return ex

    raise ValueError(f"exception not found: {ex_id}")


def remove_exception(ex_id: str) -> bool:
    # Try to remove from service_list.yaml
    svc_path = os.path.join(_config_dir(), "service_list.yaml")
    svc = _load_yaml(svc_path)
    changed = False
    for s in svc.get("services", []) or []:
        before = len(s.get("exceptions", []) or [])
        if before:
            s["exceptions"] = [e for e in s["exceptions"] if e.get("id") != ex_id]
            changed = changed or (len(s["exceptions"]) != before)
    if changed:
        _save_yaml(svc_path, svc)
        return True

    # Then try to remove from check_exceptions.yaml
    chk_path = os.path.join(_config_dir(), "check_exceptions.yaml")
    chk = _load_yaml(chk_path)
    before = len(chk.get("exceptions", []) or [])
    if before:
        chk["exceptions"] = [e for e in chk["exceptions"] if e.get("id") != ex_id]
        if len(chk["exceptions"]) != before:
            _save_yaml(chk_path, chk)
            return True
    return False 