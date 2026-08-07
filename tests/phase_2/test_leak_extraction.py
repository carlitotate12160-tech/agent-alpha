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
