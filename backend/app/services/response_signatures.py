import hashlib
import json
from dataclasses import dataclass
from html.parser import HTMLParser

from app.scanner.base import ResponseSnapshot
from app.services.analysis import sanitize_resource


@dataclass(frozen=True)
class StructuralSnapshot:
    fingerprint: str | None
    metadata: dict[str, object]


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


class _HtmlStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.nodes: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        names = ",".join(sorted(name.casefold() for name, _value in attrs))
        self.nodes.append(f"{tag.casefold()}[{names}]")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def structural_snapshot(response: ResponseSnapshot) -> StructuralSnapshot:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
    structure: list[str] = []
    sort_structure = False
    if response.body and "json" in content_type:
        sort_structure = True
        try:
            document = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            document = None

        def walk(value: object, path: str) -> None:
            current_path = path or "$"
            value_type = _json_type(value)
            if isinstance(value, (dict, list)) and not value:
                structure.append(f"{current_path}:{value_type}(empty)")
            else:
                structure.append(f"{current_path}:{value_type}")
            if isinstance(value, dict):
                for key in sorted(value, key=lambda item: str(item).casefold()):
                    walk(value[key], f"{current_path}.{str(key)[:128]}")
            elif isinstance(value, list) and value:
                walk(value[0], f"{current_path}[]")

        walk(document, "")
    elif response.body and content_type in {"text/html", "application/xhtml+xml"}:
        parser = _HtmlStructureParser()
        try:
            parser.feed(response.body.decode("utf-8", errors="replace"))
        except ValueError:
            pass
        structure = parser.nodes

    normalized_structure = sorted(set(structure)) if sort_structure else structure
    representation = "\n".join(normalized_structure)
    fingerprint = hashlib.sha256(representation.encode()).hexdigest() if representation else None
    safe_headers: dict[str, str] = {}
    for name in ("content-type", "content-length", "cache-control", "content-language"):
        value = response.headers.get(name)
        if value:
            safe_headers[name] = value[:255]
    location = response.headers.get("location")
    if location:
        safe_headers["location"] = sanitize_resource(location)
    return StructuralSnapshot(
        fingerprint=fingerprint,
        metadata={
            "status_code": response.status_code,
            "content_type": content_type[:255],
            "approximate_size": len(response.body or b""),
            "field_paths": normalized_structure,
            "headers": safe_headers,
        },
    )


def persisted_response_signature(response: ResponseSnapshot) -> dict[str, object]:
    snapshot = structural_snapshot(response)
    return {
        "status_code": response.status_code,
        "content_type": snapshot.metadata["content_type"],
        "approximate_size": snapshot.metadata["approximate_size"],
        "structural_fingerprint": snapshot.fingerprint,
    }
