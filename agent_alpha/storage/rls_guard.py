# agent_alpha/storage/rls_guard.py
# Fail-closed guard: refuse to operate any Postgres store under a role that
# bypasses Row-Level Security (superuser or BYPASSRLS).
#
# ONE canonical guard — called from every Postgres store __init__, never
# duplicated (Lyndon #6/#10). RLS is inert under a superuser/BYPASSRLS
# role; the policies still exist but the engine skips them silently,
# making tenant isolation void without any visible error. This module
# makes that failure loud and immediate.

from __future__ import annotations

import typing

if typing.TYPE_CHECKING:
    # psycopg is imported lazily by the stores; we only need the type for
    # the Callable signature.
    from psycopg import Connection


class RlsNotEnforcedError(RuntimeError):
    """The connected Postgres role can bypass Row-Level Security.

    Raised at store construction time so the application fails closed
    rather than silently operating without tenant isolation.
    """


def assert_role_cannot_bypass_rls(
    connect: typing.Callable[[], Connection[typing.Any]],
) -> None:
    """Verify the DSN role cannot bypass RLS. Call once per store __init__.

    Checks two independent Postgres flags that each individually disable
    RLS enforcement:

    1. ``is_superuser`` — superusers bypass ALL RLS policies.
    2. ``rolbypassrls`` — the BYPASSRLS attribute on the role.

    Raises :class:`RlsNotEnforcedError` if either flag is set, naming
    ``current_user`` and both flag values in the message.
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT current_user, "
            "current_setting('is_superuser'), "
            "(SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user)"
        )
        row = cur.fetchone()
        assert row is not None, "SELECT current_user returned no rows"

        role_name: str = row[0]
        is_superuser: str = row[1]  # 'on' | 'off'
        bypass_rls: bool = row[2]  # True | False

    if is_superuser == "on" or bypass_rls is True:
        raise RlsNotEnforcedError(
            f"Postgres role {role_name!r} can bypass Row-Level Security "
            f"(is_superuser={is_superuser!r}, rolbypassrls={bypass_rls!r}). "
            f"Tenant isolation is NOT enforced by the database. "
            f"Use a dedicated NOSUPERUSER NOBYPASSRLS role for the app DSN."
        )
