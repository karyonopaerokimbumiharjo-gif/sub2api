"""Official CLI -> official endpoint, with native SSE traces read only in memory.

Uses existing Codex OAuth auth; no relay, Pi runtime, or gateway. The built-in
provider forbids overrides, so a named provider selects the official URL and
SSE explicitly. No user config/auth files are modified or raw traces printed.
"""
import datetime
import json
import os
import pathlib
import re
import subprocess
import tempfile


def main():
    model = os.environ.get("SUB2API_MODEL", "gpt-6-astra")
    binary = os.environ.get("CODEX_BIN", "codex")
    version = subprocess.check_output([binary, "--version"], text=True).strip()
    env = os.environ.copy()
    for key in ("OPENAI_BASE_URL", "OPENAI_API_KEY", "CODEX_API_KEY"):
        env.pop(key, None)
    env["RUST_LOG"] = "codex_api=trace"
    with tempfile.TemporaryDirectory(prefix="codex-direct-baseline-") as directory:
        os.chmod(directory, 0o700)
        answer = pathlib.Path(directory) / "answer.txt"
        config = {
            "model_provider": "official-direct-baseline",
            "model_reasoning_effort": "low",
            "model_providers.official-direct-baseline.name": "OpenAI direct baseline",
            "model_providers.official-direct-baseline.base_url": "https://chatgpt.com/backend-api/codex",
            "model_providers.official-direct-baseline.wire_api": "responses",
            "model_providers.official-direct-baseline.requires_openai_auth": True,
            "model_providers.official-direct-baseline.supports_websockets": False,
            "model_providers.official-direct-baseline.request_max_retries": 0,
            "model_providers.official-direct-baseline.stream_max_retries": 0,
        }
        args = [binary, "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
                "--skip-git-repo-check", "--sandbox", "read-only", "--cd", directory,
                "--model", model, "--output-last-message", str(answer)]
        for key, value in config.items():
            args += ["-c", f"{key}={json.dumps(value)}"]
        args += ["Reply with exactly CODEX_DIRECT_OK. Do not call tools or inspect files."]
        try:
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            print(json.dumps({"baseline": "official-codex-direct", "result": "FAIL", "timeout": True}))
            return 1
        models, terminals = set(), set()
        # Only SDK response-event traces qualify, never the CLI's selected-model
        # banner or an assistant's model self-description.
        for line in result.stderr.splitlines():
            if "SSE event:" not in line:
                continue
            event = line.split("SSE event:", 1)[1].strip().replace('\\"', '"')
            if not re.search(r'"type"\s*:\s*"response\.(created|in_progress|completed|failed|incomplete)"', event):
                continue
            models.update(re.findall(r'"model"\s*:\s*"([A-Za-z0-9_.-]{1,80})"', event))
            terminals.update(re.findall(r'"type"\s*:\s*"response\.(completed|failed|incomplete)"', event))
        final_matches = answer.exists() and answer.read_text().strip() == "CODEX_DIRECT_OK"
        protocol = result.returncode == 0 and final_matches and terminals == {"completed"}
        expected = {"gpt-6", "gpt-6-astra"} if model in {"gpt-6", "gpt-6-astra"} else {model}
        model_passed = bool(models) and models <= expected
        print(json.dumps({"baseline": "official-codex-direct", "version": version,
                          "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          "transport": "sse", "provider": "explicit-official-endpoint",
                          "requestedModel": model, "exitCode": result.returncode,
                          "finalTextMatches": final_matches, "terminalEvents": sorted(terminals),
                          "observedModels": sorted(models), "protocolPassed": protocol,
                          "modelPassed": model_passed}))
        return 0 if protocol and model_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
