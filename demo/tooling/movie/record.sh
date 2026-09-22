#!/bin/bash
# Record narration take by take, one continuous take per task.
#
#   ./record.sh            every task not yet recorded (resumes where you stopped)
#   ./record.sh 1 2 3      just those tasks — good for a 3-task trial run
#   ./record.sh 1-3        the same, as a range
#   ./record.sh 7          re-record task 7
#   ./record.sh --from 12  task 12 to the end
#   ./record.sh --list     what is recorded so far, then exit
#   ./record.sh i0         a slide (single take, no task/summary split)
#   ./record.sh slides     every slide not yet recorded
#
# q at any prompt quits (everything already saved is kept).
#
# Both lines stay on screen; the one being read is highlighted. The TASK line and
# the SUMMARY are recorded separately (tNNa / tNNb) so either can be re-done on its
# own, and the build joins them with a short gap. See ../movie.md.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUNDLE=$(python3 -c "import json;print(json.load(open('$HERE/bundle.json'))['bundle'])")
VOICE="$BUNDLE/movie/voice"; mkdir -p "$VOICE"
SCRIPT="$BUNDLE/movie/RECORDING-SCRIPT.md"

MIC=${MIC:-:1}   # [1] = MacBook Pro Microphone. Override: MIC=:2 ./record.sh (dock)
                 # list inputs: ffmpeg -f avfoundation -list_devices true -i ""

# Print a clip's duration and peak level, so a silent or clipped take is caught
# before moving on (the [0] Webex input records silence).
report() {
  local f="$VOICE/t$1.wav" d peak
  [ -e "$f" ] || { printf '  %s  MISSING\n' "$(basename "$f")"; return; }
  d=$(ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$f" 2>/dev/null)
  peak=$(ffmpeg -hide_banner -nostats -i "$f" -af volumedetect -f null /dev/null 2>&1 \
         | sed -n 's/.*max_volume: \(.*\) dB/\1/p')
  printf '  %s  %.1fs  peak %s dB' "$(basename "$f")" "${d:-0}" "${peak:--inf}"
  case "$peak" in
    ""|-inf|-9[0-9].*) printf '   <- SILENT? check MIC (=%s)' "$MIC" ;;
    0.0|0.*)           printf '   <- clipping' ;;
  esac
  printf '\n'
}

# Block until SPACE. Any other key is ignored, so a stray keypress can neither
# start nor stop a take.
wait_space() {
  local k
  while :; do
    IFS= read -r -s -n1 k || return 0
    [ "$k" = " " ] && return 0
  done
}

# Block until SPACE (returns 0), s (1 = skip) or q (quits the whole session).
wait_space_or() {
  local k
  while :; do
    IFS= read -r -s -n1 k || return 0
    case "$k" in
      " ")   return 0 ;;
      s|S)   return 1 ;;
      q|Q)   quit_now ;;
    esac
  done
}

# Read one line of the script block: part a (the task line) or b (the summary).
line_of() {
  awk -v pat="^## $1 " -v want="^\\*\\*$2 — " '
    $0 ~ pat {f=1} f && /^---$/ {exit}
    f && $0 ~ want {g=1; next}
    g && /^> / {sub(/^> /,""); print; exit}' "$SCRIPT"
}

# One continuous take, split at the SPACE press.
# Record ONE part of a task: a = the task line, b = the summary.
# Each part is its own recording, so either can be re-done alone.
record_part() {
  local n=$1 part=$2 what pid start
  [ "$part" = a ] && what=TASK || what=SUMMARY

  printf '  \033[36m● REC\033[0m  read the %s — SPACE to stop\n' "$what"
  ffmpeg -hide_banner -loglevel error -f avfoundation -i "$MIC" \
         -ac 1 -ar 44100 -y "$VOICE/t$n$part.wav" </dev/null &
  pid=$!
  wait_space          # only SPACE stops the take, so a stray key cannot cut it short
  kill -INT "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  sleep 0.15
  report "$n$part"
}

# Show both lines, highlighting the one being read now.
show() {
  local n=$1 now=$2 cap sum
  cap=$(line_of "$n" a); sum=$(line_of "$n" b)
  printf '\n'
  if [ "$now" = a ]; then
    printf '  \033[36m▶ TASK\033[0m     %s\n' "$cap"
    printf '  \033[2m  SUMMARY  %s\033[0m\n\n' "$sum"
  elif [ "$now" = b ]; then
    printf '  \033[2m  TASK     %s\033[0m\n' "$cap"
    printf '  \033[36m▶ SUMMARY\033[0m  %s\n\n' "$sum"
  else
    printf '  \033[36mTASK\033[0m     %s\n' "$cap"
    printf '  \033[36mSUMMARY\033[0m  %s\n\n' "$sum"
  fi
}

# A slide: a single take, no task/summary split. $1 is the slide id (i0, s2, o1...).
take_slide() {
  local id=$1 cap
  cap=$(awk -v pat="^## $id " '
    $0 ~ pat {f=1} f && /^---$/ {exit}
    f && /^\*\*/ {gsub(/\*\*/,""); t=$0}
    f && /^> / {sub(/^> /,""); print t"\n\n  "$0; exit}' "$SCRIPT")
  printf '\n  \033[36m%s\033[0m\n' "$(echo "$cap" | head -1)"
  echo "$cap" | tail -n +2 | fold -s -w 104 | sed 's/^/  /'
  printf '\n  SPACE to record  (s skip · q quit) '
  wait_space_or || { echo "skipped"; return 1; }
  echo
  printf '  \033[36m● REC\033[0m  read it — SPACE to stop\n'
  ffmpeg -hide_banner -loglevel error -f avfoundation -i "$MIC" \
         -ac 1 -ar 44100 -y "$VOICE/$id.wav" </dev/null &
  local pid=$!
  wait_space
  kill -INT "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  sleep 0.15
  report "$id"
}

# A full pass over a task: the task line, then a separate prompt for the summary.
take() {
  local n=$1

  show "$n" a
  printf '  SPACE to record the TASK line   (s skip · q quit) '
  wait_space_or || { echo "skipped"; return 1; }
  echo
  record_part "$n" a

  # explicit prompt before the summary — the task line is finished and saved
  show "$n" b
  printf '  SPACE to record the SUMMARY     (s skip · q quit) '
  wait_space_or || { echo "skipped"; return 0; }
  echo
  record_part "$n" b
}

quit_now() {
  printf '\n  quit — %s part(s) saved. ./record.sh resumes\n' \
    "$(ls "$VOICE"/t??[ab].wav 2>/dev/null | wc -l | tr -d ' ')"
  exit 0
}

# A task counts as recorded only when BOTH parts exist.
done_task() { [ -e "$VOICE/t${1}a.wav" ] && [ -e "$VOICE/t${1}b.wav" ]; }

if [ "${1:-}" = "--list" ]; then
  n_done=0
  for n in $(seq -f '%02g' 1 21); do
    if done_task "$n"; then
      printf '  %s  task+summary\n' "$n"; n_done=$((n_done+1))
    elif [ -e "$VOICE/t${n}a.wav" ]; then
      printf '  %s  task line only  (no summary)\n' "$n"
    elif [ -e "$VOICE/t${n}b.wav" ]; then
      printf '  %s  summary only  (no task line)\n' "$n"
    else
      printf '  %s  -\n' "$n"
    fi
  done
  echo "  $n_done/21 complete"
  exit 0
fi

from=0
if [ "${1:-}" = "--from" ]; then
  [ $# -ge 2 ] || { echo "--from needs a task number, e.g. ./record.sh --from 7"; exit 1; }
  from=$((10#$2)); shift 2
fi

# slide targets are handled separately: ids are alphabetic (i0, i1, s2, o1)
slides=()
rest=()
for a in "$@"; do
  case "$a" in
    slides) for s in $(python3 -c "
import sys;sys.path.insert(0,'$HERE')
from slides import SLIDES
print(' '.join(x['id'] for x in SLIDES))"); do
              [ -e "$VOICE/$s.wav" ] || slides+=("$s"); done ;;
    [a-z][0-9]*) slides+=("$a") ;;
    *) rest+=("$a") ;;
  esac
done
if [ ${#slides[@]} -gt 0 ]; then
  echo "mic $MIC · ${#slides[@]} slide(s): ${slides[*]}"
  for id in "${slides[@]}"; do
    echo; echo "════════════════════════════════════════════════════════════"
    echo "  SLIDE $id"
    echo "════════════════════════════════════════════════════════════"
    take_slide "$id" || continue
    while :; do
      read -r -p "  ENTER next · h hear · r redo · q quit " k
      case "$k" in
        h|H) afplay "$VOICE/$id.wav" ;;
        r|R) take_slide "$id" || break ;;
        q|Q) quit_now ;;
        "")  break ;;
        *)   echo "  ENTER · h · r · q" ;;
      esac
    done
  done
  [ ${#rest[@]} -eq 0 ] && { echo; echo "done. next:  python3 mix_voice.py && node render.mjs && python3 mux.py"; exit 0; }
fi
set -- ${rest[@]+"${rest[@]}"}

targets=()
if [ $# -eq 0 ]; then
  # resume: every task not yet fully recorded, from --from onward
  for n in $(seq -f '%02g' 1 21); do
    [ $((10#$n)) -lt "${from:-0}" ] && continue
    done_task "$n" || targets+=("$n")
  done
else
  for raw in "$@"; do
    case "$raw" in
      *-*) a=${raw%%-*}; b=${raw##*-}
           for i in $(seq "$((10#$a))" "$((10#$b))"); do targets+=("$(printf '%02d' "$i")"); done ;;
      *)   targets+=("$(printf '%02d' "$((10#$raw))")") ;;
    esac
  done
fi

if [ ${#targets[@]} -eq 0 ]; then
  echo "nothing to record — all 21 done (./record.sh --list to check, ./record.sh 7 to redo one)"
  exit 0
fi

echo "mic $MIC · ${#targets[@]} task(s): ${targets[*]}"
echo "two recordings per task: TASK line, then SUMMARY · q quits (saved work is kept)"
for n in "${targets[@]}"; do
  echo
  echo "════════════════════════════════════════════════════════════"
  echo "  TASK $n of 21"
  echo "════════════════════════════════════════════════════════════"
  take "$n" || { echo "  skipped"; continue; }
  # (2) hear or redo either part on its own
  while :; do
    echo
    read -r -p "  ENTER next · h hear both · 1 hear task · 2 hear summary · a redo task · b redo summary · q quit " k
    case "$k" in
      h|H) [ -e "$VOICE/t${n}a.wav" ] && afplay "$VOICE/t${n}a.wav"
           sleep 0.3
           [ -e "$VOICE/t${n}b.wav" ] && afplay "$VOICE/t${n}b.wav" ;;
      1)   [ -e "$VOICE/t${n}a.wav" ] && afplay "$VOICE/t${n}a.wav" || echo "  no task line recorded" ;;
      2)   [ -e "$VOICE/t${n}b.wav" ] && afplay "$VOICE/t${n}b.wav" || echo "  no summary recorded" ;;
      a|A) show "$n" a
           printf '  SPACE to re-record the TASK line '
           wait_space; echo
           record_part "$n" a ;;
      b|B) show "$n" b
           printf '  SPACE to re-record the SUMMARY '
           wait_space; echo
           record_part "$n" b ;;
      q|Q) quit_now ;;
      "")  # warn rather than silently leaving a half-recorded task
           miss=""
           [ -e "$VOICE/t${n}a.wav" ] || miss="task line"
           [ -e "$VOICE/t${n}b.wav" ] || miss="${miss:+$miss and }summary"
           [ -n "$miss" ] && echo "  note: task $n has no $miss — './record.sh $n' redoes it"
           break ;;
      *)   echo "  ENTER · h · 1 · 2 · a · b · q" ;;
    esac
  done
done

echo
echo "done. next:  python3 mix_voice.py && node render.mjs && python3 mux.py"
