"""Sentinel VM (Ot function) - Python implementation of the SDK's bytecode VM.

Executes collector_dx / snapshot_dx / turnstile.dx challenges from the Sentinel
req response.  The VM is a Map-based virtual machine where instructions are
[opcode, ...args] arrays.  Opcodes perform operations like set, get, call,
property access, etc.

This is a port of the Ot() function from the official Sentinel SDK
(https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js).
"""
from __future__ import annotations

import base64
import json
import math
import random
import time
import uuid
from typing import Any


def _xor_decrypt(ciphertext: str, key: str) -> str:
    """Tt() function: XOR each byte of ciphertext with key (cycling)."""
    result = []
    key_len = len(key)
    for i, ch in enumerate(ciphertext):
        result.append(chr(ord(ch) ^ ord(key[i % key_len])))
    return "".join(result)


class _MockWindow:
    """Minimal browser environment mock for the Sentinel VM."""

    def __init__(self, user_agent: str):
        self._data: dict[str, Any] = {}
        self._init_props(user_agent)

    def _init_props(self, ua: str):
        nav = {
            "userAgent": ua,
            "language": "en-US",
            "languages": ["en-US", "en"],
            "hardwareConcurrency": random.choice([4, 8, 12, 16]),
            "platform": "Win32",
            "vendor": "Google Inc.",
            "appVersion": ua.replace("Mozilla/", ""),
            "appName": "Netscape",
            "product": "Gecko",
            "productSub": "20030107",
            "cookieEnabled": True,
            "onLine": True,
            "maxTouchPoints": 0,
            "pdfViewerEnabled": True,
            "webdriver": False,
            "deviceMemory": 8,
            "connection": {"effectiveType": "4g", "rtt": 50, "downlink": 10},
        }
        screen = {
            "width": 1920,
            "height": 1080,
            "availWidth": 1920,
            "availHeight": 1040,
            "colorDepth": 24,
            "pixelDepth": 24,
        }
        perf_mem = {"jsHeapSizeLimit": 4294705152}
        doc_el = {"getAttribute": lambda attr: None}
        doc = {
            "scripts": [],
            "documentElement": doc_el,
            "createElement": lambda tag: {"style": {}, "setAttribute": lambda k, v: None},
            "cookie": "",
            "referrer": "",
            "title": "",
            "URL": "https://auth.openai.com/create-account",
            "documentURI": "https://auth.openai.com/create-account",
            "compatMode": "CSS1Compat",
            "readyState": "complete",
        }
        reflect = {
            "set": lambda target, key, value: (target.__setitem__(key, value) if isinstance(target, dict) else None) or True,
            "get": lambda target, key: target.get(key) if isinstance(target, dict) else None,
            "has": lambda target, key: key in target if isinstance(target, dict) else False,
            "ownKeys": lambda target: list(target.keys()) if isinstance(target, dict) else [],
            "deleteProperty": lambda target, key: target.pop(key, None) is not None if isinstance(target, dict) else False,
        }
        crypto_obj = {
            "getRandomValues": lambda arr: arr,
            "randomUUID": lambda: str(uuid.uuid4()),
        }
        math_obj = {
            "random": random.random,
            "imul": lambda a, b: ((a * b) & 0xFFFFFFFF) if a * b >= 0 else ((a * b + 2**32) & 0xFFFFFFFF),
            "abs": abs,
            "floor": math.floor,
            "ceil": math.ceil,
            "round": round,
            "min": min,
            "max": max,
            "pow": pow,
            "sqrt": math.sqrt,
            "log": math.log,
        }

        self._data["navigator"] = nav
        self._data["screen"] = screen
        self._data["document"] = doc
        self._data["Reflect"] = reflect
        self._data["crypto"] = crypto_obj
        self._data["Math"] = math_obj
        self._data["performance"] = {
            "now": lambda: (time.time() - self._perf_origin) * 1000,
            "memory": perf_mem,
            "timeOrigin": self._perf_origin,
        }
        self._data["JSON"] = {"parse": json.loads, "stringify": lambda obj: json.dumps(obj, separators=(",", ":"))}
        self._data["btoa"] = lambda s: base64.b64encode(s.encode("utf-8")).decode("ascii")
        self._data["atob"] = lambda s: base64.b64decode(s).decode("utf-8", errors="replace")
        self._data["setTimeout"] = lambda fn, ms: fn()
        self._data["encodeURIComponent"] = lambda s: s
        self._data["decodeURIComponent"] = lambda s: s
        self._data["String"] = lambda x: str(x)
        self._data["Number"] = lambda x: float(x) if isinstance(x, str) else x
        self._data["Array"] = {"from": lambda x: list(x), "isArray": lambda x: isinstance(x, list), "prototype": []}
        self._data["Object"] = {"keys": lambda x: list(x.keys()) if isinstance(x, dict) else [], "getPrototypeOf": lambda x: {}, "prototype": {}}
        self._data["window"] = self._data
        self._data["self"] = self._data
        self._data["globalThis"] = self._data
        self._data["location"] = {"href": "https://auth.openai.com/create-account", "origin": "https://auth.openai.com", "search": ""}
        self._data["history"] = {"length": 1}
        self._data["innerWidth"] = 1920
        self._data["innerHeight"] = 937
        self._data["outerWidth"] = 1920
        self._data["outerHeight"] = 1080
        self._data["devicePixelRatio"] = 1
        self._data["indexedDB"] = None
        self._data["localStorage"] = {}
        self._data["sessionStorage"] = {}

    _perf_origin = time.time()

    def __getitem__(self, key):
        return self._data.get(key)

    def __setitem__(self, key, value):
        self._data[key] = value

    def __contains__(self, key):
        return key in self._data

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()


class SentinelVM:
    """Virtual machine that executes Sentinel dx bytecode."""

    MAX_INSTRUCTIONS = 50_000

    def __init__(self, user_agent: str, xor_key: str):
        self.ua = user_agent
        self.xor_key = xor_key
        self.state: dict[Any, Any] = {}
        self.window = _MockWindow(user_agent)
        self.counter = 0
        self._resolved = False
        self._resolve_value: Any = None
        self._init_vm()

    def _init_vm(self):
        s = self.state
        # 0 (L): Ot recursive (stub)
        s[0] = lambda *args: None
        # 1 (F): XOR in-place: state[n] = Tt(state[n], state[e])
        s[1] = lambda n, e: s.__setitem__(n, _xor_decrypt(str(s.get(n, "")), str(s.get(e, ""))))
        # 2 (G): Set literal: state[n] = e
        s[2] = lambda n, e: s.__setitem__(n, e)
        # 3 (J): Resolve (will be overridden by Ot)
        s[3] = lambda val: self._resolve(val)
        # 4 (z): Reject
        s[4] = lambda val: self._resolve(str(val))
        # 5 (B): Array push
        def _push(n, e):
            arr = s.get(n)
            if isinstance(arr, list):
                arr.append(s.get(e))
            else:
                s[n] = [s.get(e)]
        s[5] = _push
        # 6 (H): Property access: state[n] = state[e][state[r]]
        def _prop(n, e, r):
            obj = s.get(e)
            key = s.get(r)
            try:
                if isinstance(obj, dict):
                    s[n] = obj.get(key)
                elif isinstance(obj, list):
                    s[n] = obj[int(key)] if 0 <= int(key) < len(obj) else None
                elif obj is None:
                    s[n] = None
                else:
                    s[n] = getattr(obj, str(key), None)
            except Exception:
                s[n] = None
        s[6] = _prop
        # 7 (W): Call: state[n](...args.map(a => state[a]))
        def _call(n, *args):
            fn = s.get(n)
            call_args = [s.get(a) for a in args]
            if callable(fn):
                try:
                    return fn(*call_args)
                except Exception as ex:
                    return str(ex)
            return None
        s[7] = _call
        # 8 (Z): Copy: state[n] = state[e]
        s[8] = lambda n, e: s.__setitem__(n, s.get(e))
        # 9 (K): Instruction queue (set externally)
        # 10 (Q): window object
        s[10] = self.window._data
        # 11 (Y): Script src matcher
        def _script_match(n, e):
            pattern = s.get(e, "")
            scripts = self.window._data.get("document", {}).get("scripts", [])
            s[n] = None
        s[11] = _script_match
        # 12 (X): Set to VM state itself
        s[12] = lambda n: s.__setitem__(n, s)
        # 13 (tt): Try-catch: try { state[n] = state[e](...rest) } catch { state[n] = error }
        def _trycatch(n, e, *r):
            fn = s.get(e)
            args = [s.get(a) for a in r]
            try:
                if callable(fn):
                    s[n] = fn(*args)
                else:
                    s[n] = None
            except Exception as ex:
                s[n] = str(ex)
        s[13] = _trycatch
        # 14 (nt): JSON.parse: state[n] = JSON.parse(state[e])
        s[14] = lambda n, e: s.__setitem__(n, json.loads(str(s.get(e, "{}"))))
        # 15 (et): JSON.stringify: state[n] = JSON.stringify(state[e])
        s[15] = lambda n, e: s.__setitem__(n, json.dumps(s.get(e), separators=(",", ":"), default=str))
        # 16 (rt): XOR key
        s[16] = self.xor_key
        # 17 (ot): Try-catch with async (same as 13 but args are state keys)
        def _trycatch_async(n, e, *r):
            fn = s.get(e)
            args = [s.get(a) for a in r]
            try:
                if callable(fn):
                    result = fn(*args)
                    s[n] = result
                else:
                    s[n] = None
            except Exception as ex:
                s[n] = str(ex)
        s[17] = _trycatch_async
        # 18 (it): atob: state[n] = atob(state[n])
        s[18] = lambda n: s.__setitem__(n, base64.b64decode(str(s.get(n, ""))).decode("utf-8", errors="replace"))
        # 19 (ct): btoa: state[n] = btoa(state[n])
        s[19] = lambda n: s.__setitem__(n, base64.b64encode(str(s.get(n, "")).encode("utf-8")).decode("ascii"))
        # 20 (ut): If-equal: if state[n] === state[e] then state[r](...rest)
        def _if_equal(n, e, r, *rest):
            if s.get(n) == s.get(e):
                fn = s.get(r)
                if callable(fn):
                    args = [s.get(a) for a in rest]
                    return fn(*args)
            return None
        s[20] = _if_equal
        # 21 (at): If-diff: if |state[n] - state[e]| > state[r] then state[o](...rest)
        def _if_diff(n, e, r, o, *rest):
            try:
                a = float(s.get(n, 0) or 0)
                b = float(s.get(e, 0) or 0)
                threshold = float(s.get(r, 0) or 0)
                if abs(a - b) > threshold:
                    fn = s.get(o)
                    if callable(fn):
                        args = [s.get(a2) for a2 in rest]
                        return fn(*args)
            except (TypeError, ValueError):
                pass
            return None
        s[21] = _if_diff
        # 22 (ft): Execute sub-program
        def _subprogram(n, e):
            saved_queue = s.get(9, [])
            body = s.get(e, [])
            s[9] = list(body) if isinstance(body, list) else []
            self._execute()
            result = s.get(n)
            s[9] = saved_queue
            return result
        s[22] = _subprogram
        # 23 (st): If-defined: if state[n] !== undefined then state[e](...rest)
        def _if_defined(n, e, *rest):
            if s.get(n) is not None:
                fn = s.get(e)
                if callable(fn):
                    args = [s.get(a) for a in rest]
                    return fn(*args)
            return None
        s[23] = _if_defined
        # 24 (V): Bind: state[n] = state[e][state[r]].bind(state[e])
        def _bind(n, e, r):
            obj = s.get(e)
            key = s.get(r)
            try:
                if isinstance(obj, dict):
                    method = obj.get(key)
                    if callable(method):
                        s[n] = lambda *args: method(*args)
                    else:
                        s[n] = None
                else:
                    s[n] = None
            except Exception:
                s[n] = None
        s[24] = _bind
        # 25 (lt): noop
        s[25] = lambda *a: None
        # 26 (dt): noop
        s[26] = lambda *a: None
        # 27 (pt): Array splice
        def _splice(n, e):
            arr = s.get(n)
            idx = s.get(e)
            if isinstance(arr, list) and isinstance(idx, (int, float)):
                i = int(idx)
                if 0 <= i < len(arr):
                    arr.pop(i)
        s[27] = _splice
        # 28 (ht): noop
        s[28] = lambda *a: None
        # 29 (gt): Less than: state[n] = state[e] < state[r]
        def _less_than(n, e, r):
            try:
                s[n] = s.get(e) < s.get(r)
            except TypeError:
                s[n] = False
        s[29] = _less_than
        # 30 (mt): Define function
        def _define_func(t, n, e, r):
            is_array = isinstance(r, list)
            param_names = e if is_array else []
            body = (r if is_array else e) or []
            def fn(*call_args):
                if self._resolved:
                    return None
                saved_queue = s.get(9, [])
                if is_array:
                    for i, pn in enumerate(param_names):
                        if i < len(call_args):
                            s[pn] = call_args[i]
                s[9] = list(body) if isinstance(body, list) else []
                self._execute()
                result = s.get(n)
                s[9] = saved_queue
                return result
            s[t] = fn
        s[30] = _define_func
        # 33 (wt): Multiply: state[n] = Number(state[e]) * Number(state[r])
        def _multiply(n, e, r):
            try:
                a = float(s.get(e, 0) or 0)
                b = float(s.get(r, 0) or 0)
                s[n] = a * b
            except (TypeError, ValueError):
                s[n] = 0
        s[33] = _multiply
        # 34 (yt): Promise resolve
        def _promise_resolve(n, e):
            val = s.get(e)
            s[n] = val
            return val
        s[34] = _promise_resolve

    def _resolve(self, value: Any):
        if not self._resolved:
            self._resolved = True
            self._resolve_value = value

    def _execute(self):
        """Execute instructions from the queue (state[9])."""
        queue = self.state.get(9, [])
        if not isinstance(queue, list):
            return

        while queue and self.counter < self.MAX_INSTRUCTIONS:
            if self._resolved:
                break
            inst = queue.pop(0)
            if not isinstance(inst, list) or len(inst) < 1:
                continue

            opcode = inst[0]
            args = inst[1:]

            fn = self.state.get(opcode)
            if not callable(fn):
                continue

            try:
                result = fn(*args)
                if result is not None:
                    # In the original VM, if result is a Promise, it's awaited
                    # Here we just continue (synchronous execution)
                    pass
            except Exception:
                pass

            self.counter += 1

    def run(self, dx_value: str) -> str:
        """Execute a dx challenge and return the result.

        Args:
            dx_value: Base64-encoded XOR-encrypted JSON bytecode

        Returns:
            Base64-encoded result string (like Ot() in the SDK)
        """
        self._resolved = False
        self._resolve_value = None
        self.counter = 0

        # Step 1: Base64 decode
        decoded = base64.b64decode(dx_value).decode("utf-8", errors="replace")

        # Step 2: XOR decrypt with key
        decrypted = _xor_decrypt(decoded, self.xor_key)

        # Step 3: Parse as JSON (instruction queue)
        try:
            instructions = json.loads(decrypted)
        except json.JSONDecodeError:
            return base64.b64encode(f"{self.counter}: parse_error".encode()).decode("ascii")

        if not isinstance(instructions, list):
            return base64.b64encode(f"{self.counter}: invalid_instructions".encode()).decode("ascii")

        # Step 4: Set instruction queue and execute
        self.state[9] = list(instructions)
        self._execute()

        # Step 5: Return result (like Ot: btoa(bt + ": " + result))
        if self._resolved:
            result_str = str(self._resolve_value)
        else:
            result_str = str(self.counter)

        return base64.b64encode(f"{self.counter}: {result_str}".encode("utf-8")).decode("ascii")


def generate_so_token(
    collector_dx: str,
    snapshot_dx: str,
    xor_key: str,
    user_agent: str,
) -> str:
    """Generate the SO token from collector_dx and snapshot_dx.

    Args:
        collector_dx: Base64-encoded collector challenge
        snapshot_dx: Base64-encoded snapshot challenge
        xor_key: XOR key (the requirements token used in sentinel req)
        user_agent: User-Agent string

    Returns:
        SO token string for the OpenAI-Sentinel-SO-Token header
    """
    vm = SentinelVM(user_agent, xor_key)

    # Execute collector_dx
    collector_result = vm.run(collector_dx)

    # Reset VM for snapshot_dx
    vm2 = SentinelVM(user_agent, xor_key)
    snapshot_result = vm2.run(snapshot_dx)

    # Combine results (the SO token is the combination of both)
    # Format: base64(collector_result + ":" + snapshot_result)
    combined = f"{collector_result}:{snapshot_result}"
    return base64.b64encode(combined.encode("utf-8")).decode("ascii")
