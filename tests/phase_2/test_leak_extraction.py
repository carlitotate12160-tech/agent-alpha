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
