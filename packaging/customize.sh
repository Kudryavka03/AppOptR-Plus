#!/system/bin/sh

ui_print "- AppOptR Plus 2.3.0"
ui_print "- Per-app CPU, memory and scheduler tuning"

case "$ARCH" in
  arm64) ;;
  *) abort "! This package supports arm64 devices only (detected: $ARCH)" ;;
esac

[ -f "$MODPATH/bin/AppOpt" ] || abort "! AppOpt binary is missing from the package"
[ -f "$MODPATH/bin/AppOpt-ebpf" ] || abort "! AppOpt-ebpf object is missing from the package"

set_perm "$MODPATH/bin/AppOpt" 0 0 0755
set_perm "$MODPATH/bin/AppOpt-ebpf" 0 0 0644
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

ui_print "- arm64 payload installed"
ui_print "- Web console will listen on http://127.0.0.1:8889/"
