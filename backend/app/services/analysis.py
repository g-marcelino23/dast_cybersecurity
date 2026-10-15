"""Public facade for application-security analysis and reporting."""

from app.services.insights import (
    TargetHealthService,
    TargetUnavailableError,
    access_profile_surface,
    access_surface,
    authorization_preview,
    create_role_surface_snapshot,
    cwe_coverage,
    generate_authorization_candidates,
    login_suggestions,
    privacy_analysis,
    role_comparison,
    sanitize_resource,
    scan_summary,
    sensitive_surface,
    suggest_rules,
)

__all__ = [
    "TargetHealthService",
    "TargetUnavailableError",
    "access_profile_surface",
    "access_surface",
    "authorization_preview",
    "create_role_surface_snapshot",
    "cwe_coverage",
    "generate_authorization_candidates",
    "login_suggestions",
    "privacy_analysis",
    "role_comparison",
    "sanitize_resource",
    "scan_summary",
    "sensitive_surface",
    "suggest_rules",
]
