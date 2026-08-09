import asyncio
import aiohttp

class NucleiEngine:
    @staticmethod
    async def execute_nuclei_stream(target, severity=None, concurrency=20):
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target
        target = target.rstrip("/")

        vulnerability_checks = [
            {"id": "git-head-leak", "name": "Exposed Git Repository", "path": "/.git/HEAD", "severity": "high", "match": "ref: refs/"},
            {"id": "env-file-disclosure", "name": "Exposed Environment File (.env)", "path": "/.env", "severity": "critical", "match": ["DB_", "SECRET", "PASSWORD", "KEY="]},
            {"id": "wordpress-config-leak", "name": "Exposed WordPress Config Backup", "path": "/wp-config.php.bak", "severity": "critical", "match": "DB_PASSWORD"},
            {"id": "phpinfo-disclosure", "name": "Exposed PHPInfo Diagnostic Page", "path": "/phpinfo.php", "severity": "medium", "match": "PHP Version"},
            {"id": "swagger-api-docs", "name": "Exposed Swagger API Documentation", "path": "/swagger-ui.html", "severity": "info", "match": "swagger"},
            {"id": "spring-boot-actuator", "name": "Exposed Spring Boot Actuator Endpoint", "path": "/actuator/env", "severity": "high", "match": "activeProfiles"}
        ]

        yield {"type": "TERMINAL_LINE", "text": f"[*] Starting aiohttp vulnerability assessment against {target}...\n"}

        semaphore = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=4)
        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # 1. Test Base Security Headers
            try:
                async with session.get(target) as res:
                    headers = res.headers
                    if "X-Frame-Options" not in headers:
                        yield {
                            "type": "NUCLEI_FINDING",
                            "data": {
                                "template_id": "missing-clickjacking-header",
                                "name": "Missing Clickjacking Protection (X-Frame-Options)",
                                "severity": "low",
                                "matched_at": target
                            }
                        }
                    if "X-Content-Type-Options" not in headers:
                        yield {
                            "type": "NUCLEI_FINDING",
                            "data": {
                                "template_id": "missing-mime-header",
                                "name": "Missing MIME-Sniffing Protection (X-Content-Type-Options)",
                                "severity": "info",
                                "matched_at": target
                            }
                        }
            except Exception:
                pass

            # 2. Async Endpoint Vulnerability Checks
            async def run_check(check):
                if severity and severity not in check["severity"]:
                    return None

                full_url = f"{target}{check['path']}"
                async with semaphore:
                    try:
                        async with session.get(full_url) as res:
                            if res.status == 200:
                                text = await res.text()
                                matched = False
                                if isinstance(check["match"], list):
                                    matched = any(pattern in text for pattern in check["match"])
                                else:
                                    matched = check["match"] in text

                                if matched:
                                    return {
                                        "template_id": check["id"],
                                        "name": check["name"],
                                        "severity": check["severity"],
                                        "matched_at": full_url
                                    }
                    except Exception:
                        pass
                return None

            tasks = [asyncio.create_task(run_check(c)) for c in vulnerability_checks]
            for task in asyncio.as_completed(tasks):
                finding = await task
                if finding:
                    yield {
                        "type": "NUCLEI_FINDING",
                        "data": finding
                    }

        yield {"type": "TERMINAL_LINE", "text": "[+] Async vulnerability scan complete.\n"}
        yield {"type": "NUCLEI_COMPLETE", "payload": {"status": "success"}}