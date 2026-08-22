from agent_alpha.security.leak_extraction import canonical_leak_vuln_suffix


def test_canonical_leak_vuln_suffix() -> None:
    assert (
        canonical_leak_vuln_suffix("/wp-config.php.bak", default="backup_file_leak")
        == "wp_config_leak"
    )
    assert (
        canonical_leak_vuln_suffix("/old/wp-config.php", default="backup_file_leak")
        == "wp_config_leak"
    )
    assert canonical_leak_vuln_suffix("/.git/config", default="backup_file_leak") == "git_exposure"
    assert canonical_leak_vuln_suffix("/.git/", default="backup_file_leak") == "git_exposure"
    assert canonical_leak_vuln_suffix("/.env", default="backup_file_leak") == "backup_file_leak"
    assert (
        canonical_leak_vuln_suffix("/actuator/env", default="actuator_exposure")
        == "actuator_exposure"
    )


def test_cvss_for_leak_suffix_single_source() -> None:
    """BUG1: every canonical leak suffix maps to a HIGH cvss (single source, #7);
    an unknown suffix falls to the conservative info-disclosure floor, never 0.0."""
    from agent_alpha.security.leak_extraction import cvss_for_leak_suffix

    assert cvss_for_leak_suffix("wp_config_leak") == 7.5
    assert cvss_for_leak_suffix("git_exposure") == 7.5
    assert cvss_for_leak_suffix("backup_file_leak") == 7.5
    assert cvss_for_leak_suffix("actuator_exposure") == 7.5
    assert cvss_for_leak_suffix("something_unlisted") == 5.3  # floor, not 0.0


def test_extract_from_codeigniter_database() -> None:
    """CI database.php parser handles array, short array, per-key, escaped quotes,
    comments, and short/empty values."""
    from agent_alpha.security.leak_extraction import _extract_from_codeigniter_database

    array_body = (
        "<?php $db['default'] = array("
        "'username' => 'ci_user', "
        "'password' => 'ci_pass', "
        "'database' => 'ci_db', "
        "'hostname' => 'db.internal');"
    )
    assert _extract_from_codeigniter_database(array_body) == {
        "DB_USER": "ci_user",
        "DB_PASSWORD": "ci_pass",
        "DB_NAME": "ci_db",
        "DB_HOST": "db.internal",
    }

    short_body = (
        "<?php $db['default'] = ["
        "'username' => 'ci_user', "
        "'password' => 'ci_pass', "
        "'database' => 'ci_db', "
        "'hostname' => 'db.internal'];"
    )
    assert _extract_from_codeigniter_database(short_body) == {
        "DB_USER": "ci_user",
        "DB_PASSWORD": "ci_pass",
        "DB_NAME": "ci_db",
        "DB_HOST": "db.internal",
    }

    per_key_body = (
        "<?php $db['default']['username'] = 'ci_user'; "
        "$db['default']['password'] = 'ci_pass'; "
        "$db['default']['database'] = 'ci_db'; "
        "$db['default']['hostname'] = 'db.internal';"
    )
    assert _extract_from_codeigniter_database(per_key_body) == {
        "DB_USER": "ci_user",
        "DB_PASSWORD": "ci_pass",
        "DB_NAME": "ci_db",
        "DB_HOST": "db.internal",
    }

    escaped = (
        "<?php $db['default'] = array("
        "'password' => 'value" + chr(92) + "'with_quote');"
    )
    assert _extract_from_codeigniter_database(escaped) == {
        "DB_PASSWORD": "value'with_quote"
    }

    commented = (
        "<?php // $db['default']['username'] = 'wrong';\n"
        "$db['default']['password'] = 'real';"
    )
    assert _extract_from_codeigniter_database(commented) == {"DB_PASSWORD": "real"}

    block_comment = (
        "<?php /* $db['default']['username'] = 'wrong'; */ "
        "$db['default']['password'] = 'real';"
    )
    assert _extract_from_codeigniter_database(block_comment) == {"DB_PASSWORD": "real"}

    empty_password = (
        "<?php $db['default'] = array('username' => 'u', 'password' => '', 'database' => 'd');"
    )
    assert _extract_from_codeigniter_database(empty_password) == {
        "DB_USER": "u",
        "DB_NAME": "d",
    }

    not_php = "<html>$db['default'] = array('username' => 'u')</html>"
    assert _extract_from_codeigniter_database(not_php) == {}
