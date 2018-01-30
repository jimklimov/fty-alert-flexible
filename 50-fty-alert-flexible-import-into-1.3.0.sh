#!/bin/sh

#
#   Copyright (c) 2018 Eaton
#
#   This file is part of the Eaton 42ity project.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#! \file    50-fty-alert-flexible-import-into-1.3.0.sh
#  \brief   Convert fty-alert-flexible configs from format used in release
#           IPM_Infra-1.2.0 into the next (current) version 1.3.0
#  \author  Jiri Kukacka <JiriKukacka@Eaton.com>
#  \author  Michal Marek <MichalMarek1@Eaton.com>
#  \author  Arnaud Quette <ArnaudQuette@Eaton.com>
#  \author  Jim Klimov <EvgenyKlimov@Eaton.com>
#
# Note: If format changes again, follow up by a similar scriptlet named
# with the corresponding release version, so it is alphabetically later.
# Remember that ipc-meta-setup scriptlets generally run once in a lifetime.

### The static rules/templates come with R/O OS image and should not
### be changed - or they would overlay any subsequent distributed files
#STATIC_RULES_DIR="/usr/share/fty-alert-flexible/rules"
GENERATED_RULES_DIR="/var/lib/fty/fty-alert-flexible/rules"

### Extension for the backup files made by this format-version bumper
BACKUPEXT="bak-import-pre-1.3.0"

die() {
    echo "FATAL: $*" >&2
    exit 1
}

skip() {
    echo "SKIP: $*" >&2
    exit 0
}

[ -d "$GENERATED_RULES_DIR" -a -w "$GENERATED_RULES_DIR" ] || die "Can not manipulate $GENERATED_RULES_DIR directory"
if [ "`ls -1 "$GENERATED_RULES_DIR"/*.rule | wc -l`" = 0 ] ; then
    skip "This script does not apply on this deployment: no local rules were generated yet"
fi

for F in "$GENERATED_RULES_DIR"/*.rule ; do
    [ -s "$F" ] || { echo "SKIP FILE: $F : is empty or missing" ; continue; }
    [ -s "$F.$BACKUPEXT" ] && { echo "SKIP FILE: $F : was already processed earlier" ; continue; }

    cp -f "$F" "$F.$BACKUPEXT" \
    || die "FAILED to copy '$F' into backup '$F.$BACKUPEXT'"

    chmod --reference="$F" "$F.$BACKUPEXT"
    chown --reference="$F" "$F.$BACKUPEXT"

    sed -r \
        -e 's/"action" *: *\[ *"([^"]*)" *\]/"action": \[\{"action": "\1"\}\]/' \
        -e 's/"action" *: *\[ *"([^"]*)", *"([^"]*)" *\]/"action": \[\{"action": "\1"\}, {"action": "\2"}\]/' \
        < "$F.$BACKUPEXT" > "$F" \
    || die "FAILED to convert '$F' from 1.2.0 format into 1.3.0"
done
