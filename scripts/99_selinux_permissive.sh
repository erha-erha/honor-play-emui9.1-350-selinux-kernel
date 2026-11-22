#!/system/bin/sh
# Magisk service.d script for Honor Play (COR-AL10) EMUI 9.1.0.350
# Boots safely in Enforcing mode to pass EMUI /data FBE decryption,
# then automatically switches SELinux to Permissive after boot completes.

until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 2
done
sleep 3
setenforce 0
