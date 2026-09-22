#!/system/bin/sh

URL=http://127.0.0.1:8889/

if [ -x /system/bin/am ]; then
  /system/bin/am start -a android.intent.action.VIEW -d "$URL" >/dev/null 2>&1
fi

echo "AppOptR Plus Web: $URL"
