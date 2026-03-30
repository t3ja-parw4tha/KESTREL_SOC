"""LDAP user sync service (optional dependency)."""

from __future__ import annotations


from app.config import get_settings


def fetch_ldap_users() -> list[dict[str, str]]:
    """Fetch LDAP users from configured directory.

    Returns simple dictionaries: username, email, display_name.
    If ldap3 is unavailable or config missing, returns empty list.
    """
    settings = get_settings()
    ldap_url = getattr(settings, "ldap_server_url", "")
    bind_dn = getattr(settings, "ldap_bind_dn", "")
    bind_password = getattr(settings, "ldap_bind_password", None)
    search_base = getattr(settings, "ldap_search_base", "")
    search_filter = getattr(settings, "ldap_search_filter", "(objectClass=person)")

    if not ldap_url or not bind_dn or not bind_password or not search_base:
        return []

    try:
        from ldap3 import ALL, Connection, Server  # type: ignore[import-not-found]
    except Exception:
        return []

    users: list[dict[str, str]] = []
    server = Server(ldap_url, get_info=ALL)
    conn = Connection(server, user=bind_dn, password=bind_password.get_secret_value() if hasattr(bind_password, "get_secret_value") else str(bind_password), auto_bind=True)
    try:
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=["uid", "mail", "displayName", "cn", "sAMAccountName"],
        )
        for entry in conn.entries:
            data = entry.entry_attributes_as_dict
            username = (
                (data.get("uid") or [None])[0]
                or (data.get("sAMAccountName") or [None])[0]
                or (data.get("cn") or [None])[0]
            )
            email = (data.get("mail") or [None])[0]
            display_name = (data.get("displayName") or [None])[0] or username
            if username and email:
                users.append(
                    {
                        "username": str(username).lower(),
                        "email": str(email).lower(),
                        "display_name": str(display_name),
                    }
                )
    finally:
        conn.unbind()

    return users
