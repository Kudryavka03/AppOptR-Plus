#!/system/bin/sh

MODDIR="$(dirname "$0")"
STATE_DIR=/data/adb/appoptr-plus
PID_FILE="$STATE_DIR/AppOpt.pid"
BIN="$MODDIR/bin/AppOpt"

if [ -r "$PID_FILE" ]; then
  pid="$(cat "$PID_FILE" 2>/dev/null)"
  case "$pid" in
    ''|*[!0-9]*) ;;
    *)
      if [ -r "/proc/$pid/cmdline" ]; then
        cmdline="$(tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        case "$cmdline" in
          *"$BIN"*) kill "$pid" 2>/dev/null ;;
        esac
      fi
      ;;
  esac
fi

# Keep the user's web-edited configuration in /data/adb/appoptr-plus so a
# reinstall can recover it. Only the live daemon and its PID marker are removed.
rm -f "$PID_FILE"
