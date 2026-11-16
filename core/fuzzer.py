import asyncio
import os
import time
import secrets
import aiohttp

class FfufEngine:
    @staticmethod
    async def execute_fuzz_stream(target, wordlist_path=None, concurrency=50):
        """
        Advanced High-Performance Async Web Fuzzer Engine:
        Executes parallel directory, parameter, and extension brute-forcing via aiohttp.
        Includes wildcard 404 calibration, latency tracking, and status classification.
        """
        # Format target URL
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target

        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"

        # Resolve wordlist: check specified path, then local wordlists/common.txt
        words = []
        resolved_path = wordlist_path
        if not resolved_path or not os.path.exists(resolved_path):
            default_path = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common.txt")
            if os.path.exists(default_path):
                resolved_path = default_path

        if resolved_path and os.path.exists(resolved_path):
            try:
                with open(resolved_path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception as e:
                yield {"type": "TERMINAL_LINE", "text": f"[!] Error reading wordlist: {str(e)}\n"}

        if not words:
            words = [
                "admin", "login", "api", "dashboard", "config", ".env", "backup",
                "robots.txt", "uploads", "images", "assets", "static", "user",
                "v1", "v2", "db", "database", "steg", "wireshark", "fuzzer", "nuclei",
                "swagger", "metrics", "actuator", "console", "phpinfo", "graphiql",
                "graphql", "server-status", "health", "info", "wp-admin", "debug"
            ]

        # Multi-extension probing matrix for dotless words
        extensions = ["", ".php", ".json", ".bak", ".env", ".log"]

        yield {"type": "TERMINAL_LINE", "text": f"[*] SecurOS Fuzzer Engine initializing against: {target}\n"}
        yield {"type": "TERMINAL_LINE", "text": f"[*] Loaded {len(words)} base keywords across {len(extensions)} extension permutations.\n"}

        semaphore = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=5, connect=2)
        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # 1. Wildcard & Catch-All Baseline Calibration Probe
            wildcard_size = None
            try:
                rand_token = f"securos_probe_{secrets.token_hex(6)}"
                rand_url = target.replace("FUZZ", rand_token)
                async with session.get(rand_url, allow_redirects=False) as probe_res:
                    if probe_res.status == 200:
                        body = await probe_res.read()
                        wildcard_size = len(body)
                        yield {"type": "TERMINAL_LINE", "text": f"[!] Wildcard 200 Handler Detected: Calibrating baseline filter ({wildcard_size} bytes).\n"}
            except Exception:
                pass

            async def test_word_ext(word, ext):
                # Don't append extensions if word already has an extension
                if "." in word and ext:
                    return None
                payload_word = f"{word}{ext}"
                url = target.replace("FUZZ", payload_word)
                t0 = time.time()
                async with semaphore:
                    try:
                        async with session.get(url, allow_redirects=False) as response:
                            if response.status != 404:
                                content = await response.read()
                                length = len(content)
                                # Suppress catch-all wildcard matches
                                if wildcard_size is not None and length == wildcard_size:
                                    return None

                                elapsed_ms = int((time.time() - t0) * 1000)
                                text = content.decode('utf-8', errors='ignore')
                                return {
                                    "url": url,
                                    "status": response.status,
                                    "length": length,
                                    "words": len(text.split()),
                                    "latency": elapsed_ms
                                }
                    except Exception:
                        pass
                    return None

            tasks = []
            for w in words:
                for ext in extensions:
                    if "." in w and ext:
                        continue
                    tasks.append(asyncio.create_task(test_word_ext(w, ext)))

            total_tasks = len(tasks)
            completed = 0
            discovered_count = 0

            for task in asyncio.as_completed(tasks):
                match = await task
                completed += 1
                if completed % 25 == 0 or completed == total_tasks:
                    pct = round((completed / total_tasks) * 100, 1)
                    yield {"type": "PROGRESS_UPDATE", "percent": pct, "label": f"Fuzzing ({int(pct)}%)"}

                if match:
                    discovered_count += 1
                    status = match["status"]
                    indicator = "🟢" if status in [200, 201] else ("🟡" if status in [301, 302, 307] else ("🔴" if status in [401, 403] else "⚪"))
                    yield {
                        "type": "FUZZ_RESULT",
                        "data": match
                    }
                    yield {
                        "type": "TERMINAL_LINE",
                        "text": f"[{indicator} HTTP {status}] {match['url']} - Size: {match['length']}B | Latency: {match['latency']}ms\n"
                    }

        yield {"type": "TERMINAL_LINE", "text": f"\n[+] High-speed fuzzing cycle completed. Total exposed paths discovered: {discovered_count}.\n"}
        yield {"type": "FUZZ_COMPLETE", "payload": {"status": "success", "count": discovered_count}}
