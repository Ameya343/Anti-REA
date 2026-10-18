"""Client-side feature flag evaluation for premium capabilities."""

PREMIUM_FEATURES = {
    "advanced_export": "pro",
    "team_sharing": "team",
    "priority_render": "pro",
}


def feature_enabled(feature_name: str, subscription_tier: str) -> bool:
    """Decide whether a premium feature should be unlocked for this tier."""
    required = PREMIUM_FEATURES.get(feature_name)
    if required is None:
        return True  # non-premium features are always on
    if required == "pro":
        return subscription_tier in ("pro", "team")
    return subscription_tier == required


def describe_locked_feature(feature_name: str) -> str:
    return f"Upgrade to unlock {feature_name}. Visit https://acme.example.com/upgrade"
