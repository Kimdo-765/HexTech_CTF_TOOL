# -*- coding: utf-8 -*-
# Print cross-references to a target symbol or address as structured JSON.
# @category Export
# @runtime Jython
#
# Usage (via headless -postScript):
#   analyzeHeadless ... -process <bin> -postScript Xrefs.py <target> <out_path> [limit]
#
# <target> can be:
#   - a symbol name (e.g. "main", "vuln", "printf")
#   - a hex address (e.g. "0x401120", "401120")
#
# Output: <out_path> is overwritten with one JSON object on a single line:
#   { "target": "<resolved>",
#     "kind":   "symbol" | "address",
#     "address": "0x...",
#     "found":  N,
#     "shown":  M,             # may be < found if capped
#     "xrefs": [ { ... }, ... ] }
#
# Each xref entry:
#   { "from":          "0x...",          # ref source address
#     "ref_type":      "UNCONDITIONAL_CALL" | "DATA_READ" | ...,
#     "function":      "<containing func name or null>",
#     "function_addr": "0x..." | null }

import json


def parse_address(text):
    """Try to interpret `text` as a hex address. Returns Ghidra Address or None."""
    s = text.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    try:
        return currentProgram.getAddressFactory().getAddress(s)
    except Exception:
        return None


def resolve_target(text):
    """Resolve user-supplied target to a (kind, address). Tries symbol lookup
    first (covers `main`, `vuln`, etc.), then hex-address parse. Returns
    (None, None) on miss.
    """
    # 1. Symbol lookup -- the global namespace first, then any matching name.
    sym_table = currentProgram.getSymbolTable()
    syms = sym_table.getSymbols(text)
    matches = []
    if syms is not None:
        while syms.hasNext():
            matches.append(syms.next())
    if matches:
        # Prefer a non-thunk function symbol; fall back to first match.
        chosen = None
        for s in matches:
            obj = s.getObject()
            try:
                if hasattr(obj, "isThunk") and obj.isThunk():
                    continue
            except Exception:
                pass
            chosen = s
            break
        if chosen is None:
            chosen = matches[0]
        return ("symbol", chosen.getAddress())

    # 2. Address parse fallback.
    addr = parse_address(text)
    if addr is not None:
        return ("address", addr)

    return (None, None)


def func_at(addr):
    """Return the Function whose body contains `addr`, or None."""
    fm = currentProgram.getFunctionManager()
    f = fm.getFunctionContaining(addr)
    return f


def fmt_addr(addr):
    """Render a Ghidra Address as `0x<hex>` when it has a numeric offset.
    Some special addresses (Entry Point pseudo-thunks, external refs)
    don't toString() to a hex value; in those cases we keep the raw
    label unchanged so the agent can see it.
    """
    if addr is None:
        return None
    s = addr.toString()
    # Hex test: every char is 0-9 / a-f / A-F.
    is_hex = bool(s) and all(
        c in "0123456789abcdefABCDEF" for c in s
    )
    if is_hex:
        return "0x{}".format(s.lstrip("0") or "0")
    return s


def main():
    args = getScriptArgs()
    if len(args) < 2:
        print("Xrefs: missing args; usage: <target> <out_path> [limit]")
        return

    target_text = args[0]
    out_path = args[1]
    try:
        limit = int(args[2]) if len(args) >= 3 else 50
    except ValueError:
        limit = 50

    kind, addr = resolve_target(target_text)
    if kind is None:
        payload = {
            "target": target_text,
            "kind": None,
            "address": None,
            "found": 0,
            "shown": 0,
            "xrefs": [],
            "error": "target not resolved as symbol or address",
        }
        with open(out_path, "w") as fp:
            fp.write(json.dumps(payload))
        print("Xrefs: target {!r} not resolved".format(target_text))
        return

    refs = []
    ref_iter = getReferencesTo(addr)
    for ref in ref_iter:
        if len(refs) >= limit + 1:  # +1 so we know if we capped
            break
        refs.append(ref)

    out_xrefs = []
    for r in refs[:limit]:
        from_addr = r.getFromAddress()
        ref_type = str(r.getReferenceType())
        f = func_at(from_addr)
        out_xrefs.append({
            "from": fmt_addr(from_addr),
            "ref_type": ref_type,
            "function": f.getName() if f is not None else None,
            "function_addr": fmt_addr(f.getEntryPoint()) if f is not None else None,
        })

    payload = {
        "target": target_text,
        "kind": kind,
        "address": fmt_addr(addr),
        "found": len(refs) if len(refs) <= limit else (limit + 1),
        "shown": len(out_xrefs),
        "xrefs": out_xrefs,
    }
    if len(refs) > limit:
        payload["truncated"] = True

    with open(out_path, "w") as fp:
        fp.write(json.dumps(payload))
    print("Xrefs: {} -> {} refs (shown {})".format(
        target_text, payload["found"], payload["shown"]))


main()
