from app.models.target import Target

def is_target_authorized(target: Target) -> bool:
    """
    Checks if a target is fully authorized for security testing.
    Must return True ONLY if the target is marked 'in_scope' and
    the authorization check has been explicitly confirmed.
    """
    if not target:
        return False
    return (
        target.scope_status == "in_scope" 
        and target.authorization_confirmed is True
    )
