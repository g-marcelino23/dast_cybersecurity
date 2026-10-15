from collections.abc import Iterable

from app.models import Target


def component_urls(components: Iterable[dict[str, str]]) -> list[str]:
    return [item["url"] for item in components if item.get("url")]


def target_urls(target: Target) -> list[str]:
    values = [target.base_url]
    if target.api_url:
        values.append(target.api_url)
    values.extend(component_urls(target.components or []))
    return list(dict.fromkeys(values))


def target_web_component_urls(target: Target) -> list[str]:
    return [
        item["url"]
        for item in (target.components or [])
        if item.get("kind") == "WEB" and item.get("url")
    ]
