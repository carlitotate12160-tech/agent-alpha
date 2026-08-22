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

    escaped = "<?php $db['default'] = array('password' => 'value" + chr(92) + "'with_quote');"
    assert _extract_from_codeigniter_database(escaped) == {"DB_PASSWORD": "value'with_quote"}

    # Double-quoted string containing an escaped single quote: the backslash must
    # be preserved because \\' is NOT a valid escape in double-quoted PHP strings.
    escaped_single_in_double = '<?php $db["default"] = array("password" => "value\\\'with_quote");'
    assert _extract_from_codeigniter_database(escaped_single_in_double) == {
        "DB_PASSWORD": "value\\'with_quote"
    }

    # Single-quoted string containing an escaped double quote: the backslash must
    # be preserved because \\" is NOT a valid escape in single-quoted PHP strings.
    escaped_double_in_single = "<?php $db['default'] = array('password' => 'value\\\"with_quote');"
    assert _extract_from_codeigniter_database(escaped_double_in_single) == {
        "DB_PASSWORD": 'value\\"with_quote'
    }

    commented = (
        "<?php // $db['default']['username'] = 'wrong';\n$db['default']['password'] = 'real';"
    )
    assert _extract_from_codeigniter_database(commented) == {"DB_PASSWORD": "real"}

    block_comment = (
        "<?php /* $db['default']['username'] = 'wrong'; */ $db['default']['password'] = 'real';"
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


def test_strip_php_comments_behavior_preserving() -> None:
    """Locks _strip_php_comments behavior across the CC<10 decomposition
    (DeepSource PY-R1000). These assertions hold on BOTH the pre- and
    post-decomposition implementation — that equality is the whole point.
    Comments go; string literals, ://-prefixes, and escaped quotes inside
    strings stay untouched."""
    from agent_alpha.security.leak_extraction import _strip_php_comments

    # line comment removed, code (and the newline) kept
    assert _strip_php_comments("$a = 1; // trailing\n$b = 2;") == "$a = 1; \n$b = 2;"
    # hash comment removed
    assert _strip_php_comments("$a = 1; # note\n$b = 2;") == "$a = 1; \n$b = 2;"
    # block comment removed (single-line and multi-line)
    assert _strip_php_comments("$a /* x */ = 1;") == "$a  = 1;"
    assert _strip_php_comments("$a = 1;/* multi\nline */$b=2;") == "$a = 1;$b=2;"
    # // inside a string literal is NOT a comment
    assert _strip_php_comments("$u = 'http://h/p';\n") == "$u = 'http://h/p';\n"
    # bare :// prefix outside quotes is not stripped (guard on preceding ':')
    assert _strip_php_comments("a://b") == "a://b"
    # escaped quote inside a single-quoted string does not end the string,
    # so a trailing // after it is still recognised as a comment
    assert _strip_php_comments(r"$p = 'a\'// b'; // real") == r"$p = 'a\'// b'; "
    # # inside a string literal is preserved
    assert _strip_php_comments("$p = 'a#b'; # c") == "$p = 'a#b'; "
    # unterminated block comment stops stripping (mirrors original break)
    assert _strip_php_comments("$a=1; /* never closed") == "$a=1; "
    # trailing backslash at EOF inside a string is tolerated (no index error)
    assert _strip_php_comments("$p = 'a\\") == "$p = 'a\\"


def test_unescape_php_string_double_quoted_escapes() -> None:
    """CodeRabbit PR #470: double-quoted PHP escapes must resolve for payable
    secret accuracy (a wrong secret is not reusable). Single-quoted stays
    minimal (only \\' and \\\\)."""
    from agent_alpha.security.leak_extraction import _unescape_php_string

    dq = lambda v: _unescape_php_string(v, '"')  # noqa: E731 — terse test alias
    sq = lambda v: _unescape_php_string(v, "'")  # noqa: E731

    # C-style + \$ + delimiters
    assert dq(r"a\$b") == "a$b"
    assert dq(r"a\nb\tc") == "a\nb\tc"
    assert dq(r"a\vb\fc\ed") == "a\vb\fc\x1bd"
    assert dq(r"a\"b\\c") == 'a"b\\c'
    # numeric escapes
    assert dq(r"\x41\x42") == "AB"
    assert dq(r"\101\102") == "AB"  # octal 0o101=65, 0o102=66
    assert dq(r"\u{41}") == "A"
    assert dq(r"\u{1F600}") == "\U0001f600"
    # malformed numeric escapes stay literal (PHP-lenient)
    assert dq(r"\xZZ") == r"\xZZ"
    assert dq(r"\u{ZZ}") == r"\u{ZZ}"
    # unrecognised escape keeps its backslash
    assert dq(r"a\qb") == r"a\qb"
    # single-quoted: only \' and \\ are escapes; \n stays literal
    assert sq(r"a\'b") == "a'b"
    assert sq(r"a\\b") == "a\\b"
    assert sq(r"a\nb") == r"a\nb"
    assert sq(r"a\"b") == r"a\"b"
