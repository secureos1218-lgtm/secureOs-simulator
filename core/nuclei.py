import asyncio
import aiohttp
from urllib.parse import urlparse

class NucleiEngine:
    @staticmethod
    def _matches_severity(rule_sev: str, requested_sev) -> bool:
        if not requested_sev:
            return True
        if isinstance(requested_sev, (list, tuple, set)):
            req_list = [str(s).strip().lower() for s in requested_sev if s]
            if any(item in ["all", "cves,vulnerabilities", "*", "any", "default"] for item in req_list):
                return True
            return rule_sev.lower() in req_list
        req_str = str(requested_sev).strip().lower()
        if req_str in ["all", "cves,vulnerabilities", "*", "any", "default"]:
            return True
        req_list = [s.strip().lower() for s in req_str.split(",") if s.strip()]
        return rule_sev.lower() in req_list

    @classmethod
    async def execute_nuclei_stream(cls, target: str, severity: str = None, concurrency: int = 25):
        """
        High-Speed Vulnerability Scanner Engine:
        Executes parallel security checks across HTTP headers, Web routes, Cloud exposures, and API endpoints.
        """
        target = target.strip()
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target
        target = target.rstrip("/")

        vulnerability_checks = [
            # 1. Critical Information & Credential Disclosures
            {
                "id": "git-head-leak",
                "name": "Exposed Git Version Control Repository",
                "path": "/.git/HEAD",
                "severity": "critical",
                "description": "Source code repository metadata (.git/HEAD) is publicly accessible.",
                "match": "ref: refs/"
            },
            {
                "id": "env-file-disclosure",
                "name": "Exposed Environment Configuration File (.env)",
                "path": "/.env",
                "severity": "critical",
                "description": "Production credentials, API tokens, or database keys may be exposed in .env.",
                "match": ["DB_", "SECRET", "PASSWORD", "KEY=", "API_KEY", "APP_ENV"]
            },
            {
                "id": "env-local-disclosure",
                "name": "Exposed Local Environment File (.env.local)",
                "path": "/.env.local",
                "severity": "critical",
                "description": "Local environment overrides containing sensitive secrets are publicly accessible.",
                "match": ["DB_", "SECRET", "PASSWORD", "KEY="]
            },
            {
                "id": "wordpress-config-leak",
                "name": "Exposed WordPress Configuration Backup",
                "path": "/wp-config.php.bak",
                "severity": "critical",
                "description": "Database credentials exposed in plaintext WordPress config backup file.",
                "match": "DB_PASSWORD"
            },
            {
                "id": "exposed-docker-daemon",
                "name": "Exposed Docker Engine REST API",
                "path": "/version",
                "severity": "critical",
                "description": "Unauthenticated Docker daemon API socket allows remote container execution.",
                "match": "ApiVersion"
            },
            {
                "id": "database-sql-dump",
                "name": "Exposed Database SQL Dump Archive",
                "path": "/backup.sql",
                "severity": "critical",
                "description": "Plaintext SQL database dump containing table schemas and user records exposed.",
                "match": ["INSERT INTO", "CREATE TABLE", "Dump completed"]
            },

            # 2. High Severity Cloud & Framework Misconfigurations
            {
                "id": "spring-actuator-heapdump",
                "name": "Exposed Spring Boot JVM Heapdump",
                "path": "/actuator/heapdump",
                "severity": "high",
                "description": "Full JVM memory heapdump exposed, allowing extraction of memory secrets and session tokens.",
                "match": "JAVA PROFILE"
            },
            {
                "id": "spring-boot-actuator",
                "name": "Exposed Spring Boot Actuator Environment",
                "path": "/actuator/env",
                "severity": "high",
                "description": "Spring Boot actuator environment endpoint exposes configuration properties.",
                "match": "activeProfiles"
            },
            {
                "id": "spring-actuator-health",
                "name": "Exposed Spring Boot Actuator Health",
                "path": "/actuator/health",
                "severity": "low",
                "description": "Application health metrics and dependency versions exposed publicly.",
                "match": "UP"
            },
            {
                "id": "apache-server-status",
                "name": "Exposed Apache Server Status Page",
                "path": "/server-status",
                "severity": "medium",
                "description": "Apache mod_status exposes active client IPs, requests, and internal endpoints.",
                "match": "Apache Server Status"
            },

            # 3. Medium / Low API & Diagnostics Disclosures
            {
                "id": "phpinfo-disclosure",
                "name": "Exposed PHPInfo System Diagnostic Page",
                "path": "/phpinfo.php",
                "severity": "medium",
                "description": "Full PHP compilation flags, environment variables, and module paths revealed.",
                "match": "PHP Version"
            },
            {
                "id": "swagger-api-docs",
                "name": "Exposed Swagger UI Interactive API Documentation",
                "path": "/swagger-ui.html",
                "severity": "low",
                "description": "Unprotected API documentation reveals backend attack surface and parameters.",
                "match": ["swagger", "Swagger UI"]
            },
            {
                "id": "openapi-spec-json",
                "name": "Exposed OpenAPI / Swagger JSON Specification",
                "path": "/api/docs",
                "severity": "low",
                "description": "Complete REST API contract specification exposed.",
                "match": ["openapi", "swagger"]
            },
            {
                "id": "s3-bucket-directory",
                "name": "Exposed Amazon S3 Bucket Directory Listing",
                "path": "/?format=xml",
                "severity": "medium",
                "description": "Unauthenticated XML bucket listing allows downloading private assets.",
                "match": "ListBucketResult"
            },
            {
                "id": "graphql-introspection",
                "name": "GraphQL Introspection Endpoint Active",
                "path": "/graphql",
                "severity": "low",
                "description": "GraphQL schema introspection query enabled, exposing all types and fields.",
                "match": "__schema"
            },
            {
                "id": "robots-txt-disclosure",
                "name": "Sensitive Paths in robots.txt",
                "path": "/robots.txt",
                "severity": "info",
                "description": "Robots.txt discloses hidden administrative directories and internal paths.",
                "match": "Disallow:"
            }
        ]

        yield {"type": "TERMINAL_LINE", "text": f"[*] Initializing SecurOS Nuclei DAST Pipeline against: {target}\n"}
        yield {"type": "TERMINAL_LINE", "text": f"[*] Target validated. Active vulnerability checks: {len(vulnerability_checks)}\n"}

        semaphore = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=8, connect=3)
        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)

        finding_count = 0

        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # 1. Base Security Headers & CORS Inspection
                try:
                    async with session.get(target, allow_redirects=True) as res:
                        headers = res.headers

                        # Missing X-Frame-Options
                        if cls._matches_severity("low", severity) and "X-Frame-Options" not in headers:
                            finding_count += 1
                            yield {
                                "type": "NUCLEI_FINDING",
                                "data": {
                                    "template_id": "missing-clickjacking-header",
                                    "name": "Missing Clickjacking Protection (X-Frame-Options)",
                                    "severity": "low",
                                    "matched_at": target,
                                    "description": "Target response lacks X-Frame-Options header, leaving users vulnerable to clickjacking UI redress attacks."
                                }
                            }
                            yield {"type": "TERMINAL_LINE", "text": f"[Nuclei ⚠️ LOW] {target} -> Missing Clickjacking Protection (X-Frame-Options)\n"}

                        # Missing X-Content-Type-Options
                        if cls._matches_severity("info", severity) and "X-Content-Type-Options" not in headers:
                            finding_count += 1
                            yield {
                                "type": "NUCLEI_FINDING",
                                "data": {
                                    "template_id": "missing-mime-header",
                                    "name": "Missing MIME-Sniffing Protection (X-Content-Type-Options)",
                                    "severity": "info",
                                    "matched_at": target,
                                    "description": "Missing nosniff header allows browsers to incorrectly detect MIME type from payload content."
                                }
                            }
                            yield {"type": "TERMINAL_LINE", "text": f"[Nuclei ℹ️ INFO] {target} -> Missing MIME-Sniffing Protection (X-Content-Type-Options)\n"}

                        # Overly Permissive CORS Wildcard
                        cors_origin = headers.get("Access-Control-Allow-Origin")
                        if cls._matches_severity("medium", severity) and cors_origin == "*":
                            finding_count += 1
                            yield {
                                "type": "NUCLEI_FINDING",
                                "data": {
                                    "template_id": "cors-wildcard-origin",
                                    "name": "Overly Permissive CORS (Wildcard Access-Control-Allow-Origin: *)",
                                    "severity": "medium",
                                    "matched_at": target,
                                    "description": "Access-Control-Allow-Origin is set to wildcard (*), permitting cross-origin requests from arbitrary untrusted domains."
                                }
                            }
                            yield {"type": "TERMINAL_LINE", "text": f"[Nuclei ⚠️ MEDIUM] {target} -> Overly Permissive CORS (Wildcard * Origin)\n"}

                        # Server Version Banner Leak
                        server_banner = headers.get("Server")
                        if cls._matches_severity("info", severity) and server_banner and any(c.isdigit() for c in server_banner):
                            finding_count += 1
                            yield {
                                "type": "NUCLEI_FINDING",
                                "data": {
                                    "template_id": "server-banner-disclosure",
                                    "name": f"Server Software & Version Disclosure ({server_banner})",
                                    "severity": "info",
                                    "matched_at": target,
                                    "description": f"Detailed server software version banner exposed in HTTP headers: {server_banner}"
                                }
                            }
                            yield {"type": "TERMINAL_LINE", "text": f"[Nuclei ℹ️ INFO] {target} -> Server Banner Disclosure: {server_banner}\n"}

                except Exception as e:
                    yield {"type": "TERMINAL_LINE", "text": f"[!] Base endpoint probe note: {str(e)}\n"}

                # 2. Asynchronous Endpoint Probes
                async def run_check(check):
                    if not cls._matches_severity(check["severity"], severity):
                        return None

                    full_url = f"{target}{check['path']}"
                    async with semaphore:
                        try:
                            async with session.get(full_url, allow_redirects=False) as res:
                                if res.status == 200:
                                    text = await res.text(errors='ignore')
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
                                            "matched_at": full_url,
                                            "description": check.get("description", "Exposed endpoint detected.")
                                        }
                        except Exception:
                            pass
                    return None

                tasks = [asyncio.create_task(run_check(c)) for c in vulnerability_checks]
                total_tasks = len(tasks)
                completed_tasks = 0

                for task in asyncio.as_completed(tasks):
                    completed_tasks += 1
                    finding = await task
                    if finding:
                        finding_count += 1
                        sev_upper = finding["severity"].upper()
                        yield {
                            "type": "NUCLEI_FINDING",
                            "data": finding
                        }
                        yield {
                            "type": "TERMINAL_LINE",
                            "text": f"[Nuclei 🎯 {sev_upper}] {finding['matched_at']} -> {finding['name']} ({finding['template_id']})\n"
                        }

        except Exception as e:
            yield {"type": "TERMINAL_LINE", "text": f"[!] Nuclei Session Exception: {str(e)}\n"}

        yield {"type": "TERMINAL_LINE", "text": f"\n[+] Vulnerability scan complete. Total vulnerabilities discovered: {finding_count}.\n"}
        yield {"type": "NUCLEI_COMPLETE", "payload": {"status": "success", "count": finding_count}}
