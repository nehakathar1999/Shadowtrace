try:
    import paramiko
except Exception:
    paramiko = None


DEFAULT_SSH_CREDENTIALS = [
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "password"),
    ("ubuntu", "ubuntu"),
]


def attempt_ssh_login(host: str, port: int = 22, credentials: list[tuple[str, str]] | None = None, timeout: int = 4) -> list[dict]:
    findings = []
    if paramiko is None:
        return findings

    for username, password in credentials or DEFAULT_SSH_CREDENTIALS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=int(port),
                username=username,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=timeout,
                auth_timeout=timeout,
            )
            findings.append({
                "type": "ssh_default_credential",
                "port": int(port),
                "username": username,
                "password": password,
                "status": "success",
                "severity": "CRITICAL",
                "title": "SSH login succeeded with supplied credentials",
                "description": f"Credential-based SSH validation succeeded for {username} on port {port}.",
                "remediation": "Disable default credentials, rotate the account password, and restrict SSH exposure.",
            })
            client.close()
            break
        except Exception:
            client.close()
            continue

    return findings
