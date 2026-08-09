import asyncio
import os
import aiohttp

class FfufEngine:
    @staticmethod
    async def execute_fuzz_stream(target, wordlist_path=None, concurrency=50):
        # Format target URL
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target

        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"

        # Resolve wordlist
        words = []
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception as e:
                yield {"type": "TERMINAL_LINE", "text": f"[!] Error reading wordlist: {str(e)}\n"}

        if not words:
            words = [
                "admin", "login", "api", "dashboard", "config", ".env", "backup",
                "robots.txt", "uploads", "images", "assets", "static", "user",
                "v1", "v2", "db", "database", "steg", "wireshark", "fuzzer", "nuclei"
            ]

        yield {"type": "TERMINAL_LINE", "text": f"[*] Launching aiohttp async engine against {target} ({len(words)} payloads, max {concurrency} workers)...\n"}

        semaphore = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=4)
        
        # Configure connector to disable SSL verification for security testing
        connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async def test_word(word):
                url = target.replace("FUZZ", word)
                async with semaphore:
                    try:
                        async with session.get(url, allow_redirects=False) as response:
                            if response.status != 404:
                                content = await response.read()
                                text = content.decode('utf-8', errors='ignore')
                                return {
                                    "url": url,
                                    "status": response.status,
                                    "length": len(content),
                                    "words": len(text.split())
                                }
                    except Exception:
                        pass
                    return None

            tasks = [asyncio.create_task(test_word(w)) for w in words]
            
            for task in asyncio.as_completed(tasks):
                match = await task
                if match:
                    yield {
                        "type": "FUZZ_RESULT",
                        "data": match
                    }

        yield {"type": "TERMINAL_LINE", "text": "[+] High-speed fuzzing cycle completed.\n"}
        yield {"type": "FUZZ_COMPLETE", "payload": {"status": "success"}}