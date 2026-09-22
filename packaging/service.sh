#!/system/bin/sh

MODDIR="$(dirname "$0")"
STATE_DIR=/data/adb/appoptr-plus
PID_FILE="$STATE_DIR/AppOpt.pid"
LOG_FILE="$STATE_DIR/AppOpt.log"
BIN="$MODDIR/bin/AppOpt"

umask 077

is_our_pid() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ -r "/proc/$1/cmdline" ] || return 1
  cmdline="$(tr '\000' ' ' < "/proc/$1/cmdline" 2>/dev/null)"
  case "$cmdline" in
    *"$BIN"*) return 0 ;;
    *) return 1 ;;
  esac
}

mkdir -p "$STATE_DIR" || exit 1
chmod 0700 "$STATE_DIR"

if [ -r "$PID_FILE" ]; then
  old_pid="$(cat "$PID_FILE" 2>/dev/null)"
  if is_our_pid "$old_pid"; then
    exit 0
  fi
  rm -f "$PID_FILE"
fi

if [ -f "$LOG_FILE" ]; then
  log_size="$(wc -c < "$LOG_FILE" 2>/dev/null)"
  case "$log_size" in
    *[!0-9]*|'') ;;
    *) [ "$log_size" -gt 1048576 ] && mv -f "$LOG_FILE" "$LOG_FILE.1" ;;
  esac
fi

[ -x "$BIN" ] || exit 1
[ -f "$MODDIR/bin/AppOpt-ebpf" ] || exit 1

export APPOPT_STATE_DIR="$STATE_DIR"
cd "$STATE_DIR" || exit 1
printf '%s AppOptR Plus service starting\n' "$(date '+%F %T')" >> "$LOG_FILE"
if command -v nohup >/dev/null 2>&1; then
  nohup "$BIN" -w >> "$LOG_FILE" 2>&1 &
else
  "$BIN" -w >> "$LOG_FILE" 2>&1 &
fi
echo "$!" > "$PID_FILE"
