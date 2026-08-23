#!/usr/bin/env bash
# Drive the two-process race. $1 = USE_LOCK (1 or 0).
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)/run"
rm -rf "$D"; mkdir -p "$D"
export PROOF_DIR="$D" USE_LOCK="$1"
GiB=$((1024*1024*1024))
echo '{"simslot-1": 67108864, "simslot-2": 67108864}' > "$D/state.json"
: > "$D/lock"
mkfifo "$D/go"

python3 "$(dirname "$0")/proof.py" A $((7*GiB)) &
APID=$!
# wait for A to be parked INSIDE the critical section, after its snapshot
for _ in $(seq 100); do [ -f "$D/A_READ" ] && break; sleep 0.05; done
[ -f "$D/A_READ" ] || { echo "SETUP FAIL: A never reached its snapshot"; exit 2; }

python3 "$(dirname "$0")/proof.py" B $((7*GiB)) &
BPID=$!
sleep 1.5                       # generous: A is parked indefinitely, not asleep
if [ -f "$D/res_B" ]; then
  echo "B COMPLETED WHILE A HELD THE SECTION -> $(cat "$D/res_B")"
else
  echo "B is still blocked (no res_B) while A holds the section"
fi

echo go > "$D/go"               # release A
wait "$APID"; wait "$BPID"
echo "A: $(cat "$D/res_A")"
echo "B: $(cat "$D/res_B")"
python3 - "$D" <<'PY'
import json, sys
from pathlib import Path
d = Path(sys.argv[1])
a = json.loads((d/"res_A").read_text()); b = json.loads((d/"res_B").read_text())
st = json.loads((d/"state.json").read_text())
total = sum(st.values())
print("final state:", st, "total=%.2f GiB" % (total/2**30))
print("VERDICT: applied A=%s B=%s | over-budget=%s"
      % (a["applied"], b["applied"], total > 11_737_192_857))
PY
