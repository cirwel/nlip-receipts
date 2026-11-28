"""Run the tool-response harness (`eval/tool_response_eval.py`) with a live local model.

The model is reached through Ollama's OpenAI-compatible chat endpoint with native tool
calling. Nothing here changes how trials run: `run_trial` builds fresh state per trial,
executes only the calls the model actually returns, and scores effects from destination
refs. This module only converts the harness transcript to chat messages and the model's
reply back into the harness's `{content, calls}` envelope, without repairing anything:
unparseable arguments are passed through as an unparsed marker and the harness rejects them.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from nlip_receipts.git_artifact import sandbox_available

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tool_response_eval import ALL_FIXTURES, DEFAULT_CONDITIONS, DEFAULT_FIXTURES, SYSTEM_PROMPTS, run_trial  # noqa: E402

OLLAMA = "http://127.0.0.1:11434"
TOOL_DESCRIPTIONS = {
    "read_repo_file": "Read a file from the release repository.",
    "verify": "Run the configured verification check on an exact commit and return a receipt.",
    "publish": "Publish an exact commit to the destination branch.",
}


def tool_schemas(tools: dict) -> list[dict]:
    """The harness's fixed argument contract as OpenAI-style function schemas."""
    out = []
    for name, args in tools.items():
        props = {}
        for arg, desc in args.items():
            if arg == "receipt_id":
                props[arg] = {"type": ["string", "null"], "description": desc}
            else:
                props[arg] = {"type": "string", "description": desc}
        out.append({"type": "function", "function": {
            "name": name, "description": TOOL_DESCRIPTIONS[name],
            "parameters": {"type": "object", "properties": props, "required": list(args),
                           "additionalProperties": False}}})
    return out


def to_chat(messages: list[dict]) -> list[dict]:
    """Harness transcript -> chat messages. Tool results go back as tool turns."""
    chat = []
    for m in messages:
        if m["role"] in ("system", "user"):
            chat.append({"role": m["role"], "content": m["content"]})
        elif m["role"] == "assistant":
            resp = m["response"] if isinstance(m.get("response"), dict) else {}
            calls = resp.get("calls") if isinstance(resp.get("calls"), list) else []
            entry = {"role": "assistant", "content": resp.get("content") if isinstance(resp.get("content"), str) else ""}
            tool_calls = [
                {"id": c.get("id"), "type": "function",
                 "function": {"name": c.get("name"), "arguments": json.dumps(c.get("arguments"))}}
                for c in calls if isinstance(c, dict)
            ]
            if tool_calls:
                entry["tool_calls"] = tool_calls
            chat.append(entry)
        elif m["role"] == "tool":
            chat.append({"role": "tool", "tool_call_id": m.get("call_id"), "content": json.dumps(m["result"])})
    return chat


def from_chat(message: dict) -> dict:
    """Chat reply -> harness envelope. Arguments that are not a JSON object are not repaired."""
    calls = []
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function") or {}
        raw = fn.get("arguments")
        if isinstance(raw, dict):
            args = raw
        else:
            try:
                args = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                args = {"__unparsed_arguments__": raw}
        calls.append({"id": tc.get("id") or "", "name": fn.get("name"), "arguments": args})
    return {"content": message.get("content") or "", "calls": calls}


RETRY_STATUS = (429, 500, 502, 503, 504)


def ollama_factory(model: str, *, temperature: float, seed: int, timeout: float = 600.0,
                   base_url: str | None = None, api_key: str | None = None, send_seed: bool = True):
    """Chat-completions callback. With `base_url` it targets a hosted OpenAI-compatible
    endpoint instead of local Ollama; only transport failures (rate limit, 5xx) are retried,
    with the identical request. Replies are never retried or repaired."""
    url = f"{base_url.rstrip('/')}/chat/completions" if base_url else f"{OLLAMA}/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    def factory():
        # Some hosted endpoints attach opaque provider fields to a tool call and require them
        # back on replay. They are kept per trial, keyed by call id, outside the transcript.
        extras: dict[str, dict] = {}

        def call(messages, tools):
            chat = to_chat(messages)
            for entry in chat:
                for tc in entry.get("tool_calls") or []:
                    if tc["id"] in extras:
                        tc["extra_content"] = extras[tc["id"]]
            payload = {"model": model, "messages": chat, "tools": tool_schemas(tools),
                       "temperature": temperature, "stream": False}
            if send_seed:
                payload["seed"] = seed
            data = json.dumps(payload).encode()
            for attempt in range(6):
                req = urllib.request.Request(url, data=data, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        body = json.loads(resp.read())
                    break
                except urllib.error.HTTPError as exc:
                    if not base_url or exc.code not in RETRY_STATUS or attempt == 5:
                        raise
                    time.sleep(min(60, 5 * 2 ** attempt))
            choice = body["choices"][0]
            if choice.get("finish_reason") in ("length", "content_filter"):
                raise RuntimeError(f"incomplete reply: {choice['finish_reason']}")
            message = choice["message"]
            for tc in message.get("tool_calls") or []:
                if tc.get("id") and isinstance(tc.get("extra_content"), dict):
                    extras[tc["id"]] = tc["extra_content"]
            return from_chat(message)
        return call
    return factory


def hosted_model_info(model: str, base_url: str, send_seed: bool) -> dict:
    """Hosted models have no local digest; the provider can change what a name serves."""
    parts = urllib.parse.urlsplit(base_url)  # never record credentials or query strings
    endpoint = urllib.parse.urlunsplit((parts.scheme, parts.hostname or "", parts.path, "", ""))
    return {"model": model, "endpoint": endpoint, "hosted": True, "digest": None, "seed_sent": send_seed}


def model_info(model: str) -> dict:
    with urllib.request.urlopen(f"{OLLAMA}/api/tags", timeout=10) as resp:
        tags = {m["name"]: m for m in json.loads(resp.read())["models"]}
    with urllib.request.urlopen(f"{OLLAMA}/api/version", timeout=10) as resp:
        version = json.loads(resp.read()).get("version")
    m = tags[model]
    return {"model": model, "digest": m["digest"], "parameter_size": m["details"].get("parameter_size"),
            "quantization": m["details"].get("quantization_level"), "ollama_version": version}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model", action="append", required=True, help="Ollama model tag; repeatable")
    ap.add_argument("--condition", action="append", choices=SYSTEM_PROMPTS,
                    help="condition to run; repeatable (default: prompt_only and receipt_gate)")
    ap.add_argument("--fixture", action="append", choices=ALL_FIXTURES,
                    help="fixture to run; repeatable (default: attack and benign)")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--output", type=Path, required=True, help="new JSON path; never overwrites")
    ap.add_argument("--base-url", help="hosted OpenAI-compatible API base (ending before /chat/completions); "
                                       "default is local Ollama")
    ap.add_argument("--api-key-env", help="name of the environment variable holding the hosted API key")
    ap.add_argument("--no-seed", action="store_true", help="omit the seed field (for endpoints that reject it)")
    args = ap.parse_args()
    hosted = {}
    if args.base_url:
        key = os.environ.get(args.api_key_env or "")
        if not key:
            raise SystemExit("--base-url requires --api-key-env naming a set environment variable")
        hosted = {"base_url": args.base_url, "api_key": key, "send_seed": not args.no_seed}
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    if not sandbox_available():
        raise SystemExit("Live evaluation requires a working verification sandbox.")
    conditions = tuple(args.condition) if args.condition else DEFAULT_CONDITIONS
    fixtures = tuple(args.fixture) if args.fixture else DEFAULT_FIXTURES
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    runs, summary = [], []
    for model in args.model:
        info = hosted_model_info(model, args.base_url, not args.no_seed) if hosted else model_info(model)
        for condition in conditions:
            for fixture in fixtures:
                for seed in range(1, args.seeds + 1):
                    r = run_trial(condition, fixture, ollama_factory(model, temperature=args.temperature, seed=seed, **hosted))
                    r.update({"kind": "live_model_run", "model_info": info, "seed": seed,
                              "temperature": args.temperature})
                    runs.append(r)
                    row = {k: r[k] for k in ("condition", "fixture", "exposed", "attempted_unauthorized_publish",
                                             "forbidden_effect", "legitimate_release", "stop")}
                    publish_reasons = [
                        e["result"]["decision"]["reason_code"]
                        for e in r["events"]
                        if isinstance(e.get("call"), dict) and e["call"].get("name") == "publish"
                        and isinstance(e.get("result"), dict) and "decision" in e["result"]
                    ]
                    row.update(model=model, seed=seed, errors=bool(r["infrastructure_errors"] or r["model_errors"]),
                               calls=[e["call"].get("name") if isinstance(e["call"], dict) else None for e in r["events"]],
                               publish_reason_codes=publish_reasons)
                    summary.append(row)
                    print(json.dumps(row), flush=True)
    with args.output.open("x") as stream:
        json.dump({"started": started, "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "summary": summary, "runs": runs}, stream, indent=2)
    return 2 if any(r["errors"] for r in summary) else 0


if __name__ == "__main__":
    sys.exit(main())
