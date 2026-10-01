#!/bin/sh
# Print PLUGIN_VERSION from plugin/net/if-pppoe/Makefile, or fail if it's
# missing. Shared by release.yml (tag == PLUGIN_VERSION check) and
# auto-release.yml (the next tag to cut).
set -eu

plugin=$(sed -n 's/^PLUGIN_VERSION=[[:space:]]*//p' plugin/net/if-pppoe/Makefile)
[ -n "$plugin" ] || { echo "plugin-version.sh: no PLUGIN_VERSION in plugin/net/if-pppoe/Makefile" >&2; exit 1; }
echo "$plugin"
