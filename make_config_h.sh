#!/bin/sh

set -e

TEMP_SRC=$( mktemp --suffix=.c )
TEMP_OUT=$( mktemp )
CONFIG_H="config.h"

cat > $TEMP_SRC <<_END
#include <maxminddb.h>
int main () {
    int have = MMDB_SUCCESS;
}
_END

trap "rm -f $TEMP_SRC $TEMP_OUT" EXIT
gcc -lmaxminddb $TEMP_SRC -shared -o $TEMP_OUT 2> /dev/null
rm -f $CONFIG_H
touch $CONFIG_H
