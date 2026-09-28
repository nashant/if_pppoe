# if-pppoe-kmod packaging Makefile (not opnsense/plugins' Mk/plugins.mk).
# See README.md in this directory for the design and BUILD_ID semantics.

.include "../../maintainer.mk"

KMOD_NAME=	if-pppoe-kmod
KMOD_VERSION?=	0.1
KMOD_COMMENT=	if_pppoe(4) kernel module and pppoectl(8) for if-pppoe
KMOD_MAINTAINER?=${MAINTAINER}
KMOD_WWW?=	https://github.com/nashant/if_pppoe
KMOD_LICENSE?=	BSD2CLAUSE
KMOD_ABI?=	FreeBSD:14:amd64

REPO_ROOT!=	cd ${.CURDIR}/../../.. && pwd
SYS_MOD_DIR=	${REPO_ROOT}/sys/modules/if_pppoe
PPPOECTL_DIR=	${REPO_ROOT}/sbin/pppoectl

LOCALBASE?=	/usr/local
PKG?=		pkg

WRKDIR?=	${.CURDIR}/work
WRKSRC=		${WRKDIR}/src
PKGDIR?=	${WRKDIR}/pkg
# Extra make arguments for the module build (build-all.sh passes
# WERROR=-Werror in kernels-json mode, as CI always built it).
KMOD_MAKE_ARGS?=
# Discovery output (plugin/build/discover-kernels.sh); package ships the
# entries of the staged build_ids as share/if_pppoe/kernels.json.
KERNELS_JSON?=
JQ?=		jq

# --- stage-one: build + stage a single BUILD_ID's .ko -----------------------
# Requires BUILD_ID, KERNBUILDDIR and SYSDIR (see header comment). Leaves
# any previously staged BUILD_IDs in WRKSRC alone, so a caller can loop this
# target once per supported kernel before a single final `package`.
.if make(stage-one)
.if empty(BUILD_ID) || empty(KERNBUILDDIR) || empty(SYSDIR)
.error "stage-one needs BUILD_ID, KERNBUILDDIR and SYSDIR (see this Makefile's header comment)"
.endif
.endif
.if make(stage-prebuilt)
.if empty(BUILD_ID) || empty(KO)
.error "stage-prebuilt needs BUILD_ID and KO (see README.md)"
.endif
.endif

stage-one:
	@echo ">>> Verifying BUILD_ID=${BUILD_ID} against ${KERNBUILDDIR}/kernel's own build-id"
	@KERNEL_BID=$$( \
	    if command -v readelf >/dev/null 2>&1; then \
	        readelf -n ${KERNBUILDDIR}/kernel 2>/dev/null | awk '/Build ID:/{print $$NF}'; \
	    elif command -v elfdump >/dev/null 2>&1; then \
	        elfdump -n ${KERNBUILDDIR}/kernel 2>/dev/null | awk '/Build ID:/{print $$NF}'; \
	    fi); \
	if [ -z "$$KERNEL_BID" ]; then \
		echo "stage-one: could not read a GNU build-id note from ${KERNBUILDDIR}/kernel (need elfdump(1) or readelf(1)); refusing to trust the passed BUILD_ID unverified" >&2; \
		exit 1; \
	fi; \
	if [ "$$KERNEL_BID" != "${BUILD_ID}" ]; then \
		echo "stage-one: BUILD_ID=${BUILD_ID} does not match ${KERNBUILDDIR}/kernel's own build-id ($$KERNEL_BID) -- fix the manifest entry, see README.md" >&2; \
		exit 1; \
	fi
	@echo ">>> Cleaning ${SYS_MOD_DIR} before build (MAKEOBJDIRPREFIX does NOT relocate"
	@echo "    this out-of-tree kmod's .OBJDIR -- it always resolves under ${SYS_MOD_DIR}"
	@echo "    itself, shared across every stage-one call -- see build-check.sh's header"
	@echo "    and README.md; without this clean a second --target-kernel's build can be"
	@echo "    a silent bmake no-op that just re-stages the previous target's .ko, and a"
	@echo "    leftover PPPOE_TEST_REFLECT object from a manual build-module.sh run can"
	@echo "    ship in a release package)"
	@env MAKEOBJDIRPREFIX=${WRKDIR}/obj-${BUILD_ID} \
	    make -C ${SYS_MOD_DIR} KERNBUILDDIR=${KERNBUILDDIR} SYSDIR=${SYSDIR} clean
	@echo ">>> Building if_pppoe.ko for BUILD_ID=${BUILD_ID}"
	@env MAKEOBJDIRPREFIX=${WRKDIR}/obj-${BUILD_ID} \
	    make -C ${SYS_MOD_DIR} KERNBUILDDIR=${KERNBUILDDIR} SYSDIR=${SYSDIR} ${KMOD_MAKE_ARGS}
	@KO=$$(env MAKEOBJDIRPREFIX=${WRKDIR}/obj-${BUILD_ID} \
	    make -C ${SYS_MOD_DIR} KERNBUILDDIR=${KERNBUILDDIR} SYSDIR=${SYSDIR} \
	    -V .OBJDIR -V KMOD | { read -r objdir; read -r kmod; echo "$$objdir/$$kmod.ko"; }); \
	[ -f "$$KO" ] || { echo "stage-one: expected .ko not found at $$KO" >&2; exit 1; }; \
	mkdir -p ${WRKSRC}${LOCALBASE}/lib/if_pppoe/${BUILD_ID}; \
	cp "$$KO" ${WRKSRC}${LOCALBASE}/lib/if_pppoe/${BUILD_ID}/if_pppoe.ko; \
	echo "${BUILD_ID}" > ${WRKSRC}${LOCALBASE}/lib/if_pppoe/${BUILD_ID}/build_id
	@${MAKE} -C ${.CURDIR} stage-pppoectl
	@echo ">>> Staged BUILD_ID=${BUILD_ID}"

# --- stage-prebuilt: stage an already built .ko for BUILD_ID ---------------
# For kernels that share a kernel build dir with one stage-one'd kernel
# (same config_hash, no header drift -- plugin/build/build-all.sh), and for
# the package phase that stages the .kos a separate build produced. The
# bid is only checked for shape here: build-all.sh took it from the
# kernel's own ELF note during discovery. pppoectl is built once.
stage-prebuilt:
	@echo "${BUILD_ID}" | grep -Eqx '[0-9a-f]{16,}' || \
	    { echo "stage-prebuilt: BUILD_ID=${BUILD_ID} is not a lowercase hex build-id" >&2; exit 1; }
	@[ -f "${KO}" ] || { echo "stage-prebuilt: KO=${KO} not found" >&2; exit 1; }
	@mkdir -p ${WRKSRC}${LOCALBASE}/lib/if_pppoe/${BUILD_ID}
	@cp "${KO}" ${WRKSRC}${LOCALBASE}/lib/if_pppoe/${BUILD_ID}/if_pppoe.ko
	@echo "${BUILD_ID}" > ${WRKSRC}${LOCALBASE}/lib/if_pppoe/${BUILD_ID}/build_id
	@[ -f ${WRKSRC}${LOCALBASE}/sbin/pppoectl ] || ${MAKE} -C ${.CURDIR} stage-pppoectl
	@echo ">>> Staged prebuilt BUILD_ID=${BUILD_ID} from ${KO}"

stage-pppoectl:
	@echo ">>> Building pppoectl"
	@mkdir -p ${WRKDIR}/obj-pppoectl
	@env MAKEOBJDIRPREFIX=${WRKDIR}/obj-pppoectl make -C ${PPPOECTL_DIR} clean
	@env MAKEOBJDIRPREFIX=${WRKDIR}/obj-pppoectl make -C ${PPPOECTL_DIR}
	@mkdir -p ${WRKSRC}${LOCALBASE}/sbin ${WRKSRC}${LOCALBASE}/share/man/man8
	@PROGOBJDIR=$$(env MAKEOBJDIRPREFIX=${WRKDIR}/obj-pppoectl make -C ${PPPOECTL_DIR} -V .OBJDIR); \
	cp "$$PROGOBJDIR/pppoectl" ${WRKSRC}${LOCALBASE}/sbin/pppoectl; \
	gzip -cn ${PPPOECTL_DIR}/pppoectl.8 > ${WRKSRC}${LOCALBASE}/share/man/man8/pppoectl.8.gz

# --- build_ids manifest: derived from whatever is actually staged ----------
# Never hand-maintained -- it always matches the .ko directories this
# specific package build produced, so it can't drift from what's really
# shipped (hookctl/engine read it to know which kernels this package covers).
build-ids-file:
	@mkdir -p ${WRKSRC}${LOCALBASE}/share/if_pppoe
	@(cd ${WRKSRC}${LOCALBASE}/lib/if_pppoe 2> /dev/null && ls -1) | sort \
	    > ${WRKSRC}${LOCALBASE}/share/if_pppoe/build_ids
	@echo ">>> build_ids:"
	@cat ${WRKSRC}${LOCALBASE}/share/if_pppoe/build_ids

# --- features file: what this driver revision declares via FEATURE(9) ------
# Derived from the driver source (compile-time constant, so one file covers
# every BUILD_ID this package stages -- unlike build_ids, not per-BUILD_ID).
# See README.md.
features-file:
	@mkdir -p ${WRKSRC}${LOCALBASE}/share/if_pppoe
	@grep -ohE '^FEATURE\(if_pppoe_[A-Za-z0-9_]+' ${REPO_ROOT}/sys/net/*.c \
	    | sed 's/^FEATURE(//' | sort -u \
	    > ${WRKSRC}${LOCALBASE}/share/if_pppoe/features
	@echo ">>> features:"
	@cat ${WRKSRC}${LOCALBASE}/share/if_pppoe/features

# --- kernels.json: version <-> build_id for the staged build_ids -----------
# KERNELS_JSON's entries filtered to build_ids (every staged bid must have
# one, or the Services page could not name it). Without KERNELS_JSON (lab
# --target-kernel builds) an empty list: the plugin shows "unknown".
kernels-json-file: build-ids-file
.if !empty(KERNELS_JSON)
	@${JQ} --rawfile ids ${WRKSRC}${LOCALBASE}/share/if_pppoe/build_ids -f ${.CURDIR}/kernels-json.jq \
	    ${KERNELS_JSON} > ${WRKSRC}${LOCALBASE}/share/if_pppoe/kernels.json
.else
	@echo '[]' > ${WRKSRC}${LOCALBASE}/share/if_pppoe/kernels.json
.endif
	@echo ">>> kernels.json:"
	@${JQ} -r '.[] | "\(.version) \(.build_id)"' ${WRKSRC}${LOCALBASE}/share/if_pppoe/kernels.json 2>/dev/null || \
	    cat ${WRKSRC}${LOCALBASE}/share/if_pppoe/kernels.json

manifest:
	@echo "name: ${KMOD_NAME}"
	@echo "version: \"${KMOD_VERSION}\""
	@echo "origin: if_pppoe/${KMOD_NAME}"
	@echo "comment: \"${KMOD_COMMENT}\""
	@echo "maintainer: \"${KMOD_MAINTAINER}\""
	@echo "categories: [ \"kmod\" ]"
	@echo "www: \"${KMOD_WWW}\""
	@echo "prefix: \"${LOCALBASE}\""
	@echo "licenselogic: \"single\""
	@echo "licenses: [ \"${KMOD_LICENSE}\" ]"
	@echo "arch: \"${KMOD_ABI}\""
	@echo "abi: \"${KMOD_ABI}\""
	@echo "desc: \"${KMOD_COMMENT}\""

plist:
	@(cd ${WRKSRC}${LOCALBASE} 2> /dev/null && find lib sbin share -type f) | sed "s:^:${LOCALBASE}/:" | sort

metadata:
	@mkdir -p ${PKGMETA}
	@${MAKE} manifest > ${PKGMETA}/+MANIFEST
	@KERNELS=$$(${JQ} -r 'map("\(.version) (\(.build_id))") | join(", ")' \
	    ${WRKSRC}${LOCALBASE}/share/if_pppoe/kernels.json 2>/dev/null); \
	[ -n "$$KERNELS" ] || KERNELS=$$(tr '\n' ' ' < ${WRKSRC}${LOCALBASE}/share/if_pppoe/build_ids); \
	sed -e "s/%%BUILD_IDS%%/$$KERNELS/" ${.CURDIR}/pkg-descr > ${PKGMETA}/+DESC
	@if [ -f ${.CURDIR}/+POST_INSTALL ]; then cp ${.CURDIR}/+POST_INSTALL ${PKGMETA}/+POST_INSTALL; fi
	@if [ -f ${.CURDIR}/+PRE_DEINSTALL ]; then cp ${.CURDIR}/+PRE_DEINSTALL ${PKGMETA}/+PRE_DEINSTALL; fi
	@${MAKE} plist > ${PKGMETA}/plist

package: build-ids-file features-file kernels-json-file
	@[ -n "$$(ls -A ${WRKSRC}${LOCALBASE}/lib/if_pppoe 2>/dev/null)" ] || \
	    { echo "package: nothing staged -- run stage-one or stage-prebuilt at least once first" >&2; exit 1; }
	@mkdir -p ${PKGDIR}
	@${MAKE} PKGMETA=${WRKDIR}/meta metadata
	@${PKG} create -v -m ${WRKDIR}/meta -r ${WRKSRC} -p ${WRKDIR}/meta/plist -o ${PKGDIR}
	@echo ">>> $$(ls ${PKGDIR}/${KMOD_NAME}-${KMOD_VERSION}*.pkg 2>/dev/null || echo '(no .pkg found -- check pkg create output above)')"

clean:
	rm -rf ${WRKDIR}

.PHONY: stage-one stage-prebuilt stage-pppoectl build-ids-file features-file \
	kernels-json-file manifest plist metadata package clean
