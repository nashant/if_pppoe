#!/usr/bin/env bash
# Installs build deps + builds/installs accel-ppp on the lab host.
# Run on the target host (copied there and executed via ssh/scp, see README.md).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/accel-ppp-src"
TAG="1.14.0"

PKGS=(build-essential cmake libpcre2-dev libssl-dev liblua5.1-0-dev git qemu-system-x86 qemu-utils bridge-utils iproute2 iperf3 pppoe)

# Another agent on this host may also be running apt-get (qemu-system-x86 install).
# apt/dpkg serialize via the dpkg lock; retry on lock contention instead of failing.
apt_install() {
	local attempt
	for attempt in 1 2 3 4 5 6; do
		if sudo apt-get install -y "${PKGS[@]}"; then
			return 0
		fi
		echo "install-accel-ppp.sh: apt-get install failed (attempt $attempt), retrying in 30s..." >&2
		sleep 30
	done
	echo "install-accel-ppp.sh: apt-get install failed after retries" >&2
	return 1
}

apt_update() {
	local attempt
	for attempt in 1 2 3 4 5 6; do
		if sudo apt-get update; then
			return 0
		fi
		echo "install-accel-ppp.sh: apt-get update failed (attempt $attempt), retrying in 30s..." >&2
		sleep 30
	done
	echo "install-accel-ppp.sh: apt-get update failed after retries" >&2
	return 1
}

echo "== apt-get update =="
apt_update

echo "== apt-get install =="
apt_install

echo "== accel-ppp source =="
if [ ! -d "$SRC_DIR/.git" ]; then
	git clone https://github.com/accel-ppp/accel-ppp "$SRC_DIR"
fi
cd "$SRC_DIR"
git fetch --tags origin

if git ls-remote --tags origin "refs/tags/${TAG}" | grep -q "refs/tags/${TAG}$"; then
	git checkout "$TAG"
	echo "install-accel-ppp.sh: checked out tag $TAG"
else
	git checkout master
	git pull --ff-only origin master
	echo "install-accel-ppp.sh: tag $TAG not found upstream, using master"
fi

BUILT_COMMIT="$(git rev-parse HEAD)"
echo "install-accel-ppp.sh: building commit $BUILT_COMMIT"

echo "== cmake/build =="
mkdir -p build
cd build
cmake -DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE -DRADIUS=FALSE -DSHAPER=FALSE -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j"$(nproc)"

echo "== make install =="
sudo make install
sudo ldconfig

echo "install-accel-ppp.sh: done. Built commit $BUILT_COMMIT"
echo "$BUILT_COMMIT" > "$SCRIPT_DIR/.accel-ppp-commit"
