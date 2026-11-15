#!/usr/bin/env bash
# Regenerate docs/media/securelakehouse-demo.mp4 from the real project.
# Needs: the project's Python env (requirements.txt), Java, Node + playwright, ffmpeg.
# Run from anywhere:  bash demo/video/make_video.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PORT="${PORT:-8599}"
OUT="$ROOT/docs/media"
TMP="$(mktemp -d)"
export SECURELAKEHOUSE_PASSPHRASE="${SECURELAKEHOUSE_PASSPHRASE:-video-demo-passphrase}"
PY="${PYTHON:-python}"

cleanup() {
  [[ -n "${APP_PID:-}" ]] && kill "$APP_PID" 2>/dev/null || true
  rm -rf "$TMP" "$ROOT/demo_output" "$ROOT/app_workspace"
}
trap cleanup EXIT

echo "1/4 collecting real data (demo run + test suite)..."
"$PY" "$HERE/build_assets.py"

echo "2/4 starting the Streamlit app (dark theme) on :$PORT..."
rm -rf "$ROOT/app_workspace"
(cd "$ROOT" && "$PY" -m streamlit run app.py --server.headless true --server.port "$PORT" \
   --browser.gatherUsageStats false --theme.base dark --client.toolbarMode minimal \
   > "$TMP/streamlit.log" 2>&1) &
APP_PID=$!
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$PORT/_stcore/health" >/dev/null && break; sleep 1; done
# Warm-up visit: starts Spark and opens the keystore (cached), so the recording has no cold start.
NODE_PATH="$(npm root -g)" node -e "
  const {chromium}=require('playwright');(async()=>{const b=await chromium.launch();const p=await b.newPage();
  await p.goto('http://127.0.0.1:$PORT');await p.getByText('Reset workspace').first().waitFor({timeout:180000});
  await b.close();})()"

echo "3/4 recording..."
NODE_PATH="$(npm root -g)" node "$HERE/record.js" "$HERE/storyboard.html" "http://127.0.0.1:$PORT" "$TMP" | tee "$TMP/record.log"
WEBM="$(grep '^VIDEO=' "$TMP/record.log" | cut -d= -f2-)"

echo "4/4 encoding MP4..."
mkdir -p "$OUT"
ffmpeg -hide_banner -loglevel error -y -ss 0.3 -i "$WEBM" \
  -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -r 25 -movflags +faststart \
  "$OUT/securelakehouse-demo.mp4"
ffmpeg -hide_banner -loglevel error -y -ss 4 -i "$OUT/securelakehouse-demo.mp4" -frames:v 1 \
  "$OUT/securelakehouse-demo-poster.png"
echo "wrote $OUT/securelakehouse-demo.mp4"
