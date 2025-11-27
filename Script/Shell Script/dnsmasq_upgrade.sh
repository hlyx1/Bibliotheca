#!/usr/bin/env bash
set -eEuo pipefail
shopt -s inherit_errexit extglob globstar nullglob dotglob
umask 077

readonly ROOT=$HOME/Library/Mobile\ Documents/com~apple~CloudDocs/SmartDNS
readonly REPO=$ROOT/dnsmasq-china-list
readonly LOGP=$HOME/Library/Logs/dnsmasq_upgrade.log
readonly SEMP=/tmp/dnsmasq_upgrade.lock
declare -ir CAP=1048576 ROT=1
declare -i SEMFD=0

tx() {
	printf -v TS '%(%Y-%m-%dT%H:%M:%S)T' -1
	printf '[%s] %s\n' "$TS" "$*" >&2
}

halt() {
	tx "FAULT ${BASH_SOURCE[1]##*/}:${BASH_LINENO[0]}:${FUNCNAME[1]}"
	((SEMFD)) && exec {SEMFD}>&-
	[[ -f $SEMP ]] && rm -f -- "$SEMP"
	[[ -d $REPO ]] && { cd "$ROOT" && rm -rf -- "$REPO"; }
	exit 1
}

trim() {
	local DIR=${LOGP%/*}
	[[ -d $DIR ]] || mkdir -p -- "$DIR"
	[[ -f $LOGP ]] || return 0
	local -i S
	if [[ -r /proc/self/fd/0 ]]; then
		S=$(<"$LOGP" wc -c)
	elif stat --version &>/dev/null; then
		S=$(stat -c%s -- "$LOGP" 2>/dev/null || printf 0)
	else
		S=$(stat -f%z -- "$LOGP" 2>/dev/null || printf 0)
	fi
	((S < CAP)) && return 0
	local -i I
	for ((I = ROT; I > 0; I--)); do
		local PRE=$LOGP.$((I - 1)) CUR=$LOGP.$I
		[[ $I -eq $ROT && -f $CUR ]] && rm -f -- "$CUR"
		[[ -f $PRE ]] && mv -f -- "$PRE" "$CUR"
	done
	mv -f -- "$LOGP" "$LOGP.1"
}

gate() {
	if command -v flock &>/dev/null; then
		exec {SEMFD}>"$SEMP"
		flock -n $SEMFD || exit 0
	else
		if [[ -f $SEMP ]]; then
			local -i PID
			{ read -r PID <"$SEMP"; } 2>/dev/null || PID=0
			((PID > 0)) && kill -0 $PID 2>/dev/null && exit 0
			rm -f -- "$SEMP"
		fi
		printf '%d' $$ >"$SEMP"
	fi
}

wipe() {
	((SEMFD)) && exec {SEMFD}>&-
	[[ -f $SEMP ]] && rm -f -- "$SEMP"
}

trap halt ERR
trap wipe EXIT INT TERM HUP

command -v git &>/dev/null || {
	tx "CRITICAL git unavailable"
	exit 1
}

command -v make &>/dev/null || {
	tx "CRITICAL make unavailable"
	exit 1
}

gate
trim
exec > >(exec tee -a "$LOGP") 2>&1
export LC_ALL=C

{
	[[ -d $ROOT ]] || mkdir -p -- "$ROOT"
	if [[ -d $REPO/.git ]]; then
		tx "INFO Repository sync"
		GIT_TERMINAL_PROMPT=0 git -C "$REPO" pull --ff-only
	else
		tx "INFO Repository clone"
		GIT_TERMINAL_PROMPT=0 git clone --depth 1 https://github.com/felixonmars/dnsmasq-china-list.git "$REPO"
	fi
	cd "$REPO" || halt
	tx "INFO Rule synthesis"
	make --warn-undefined-variables SERVER=domestic SMARTDNS_SPEEDTEST_MODE=tcp:80 smartdns-domain-rules
	declare -a CFG=(accelerated-domains.china.domain.smartdns.conf apple.china.domain.smartdns.conf)
	declare F
	for F in "${CFG[@]}"; do
		[[ -f $F ]] || continue
		cp -f -- "$F" "$ROOT/"
	done
	tx "INFO Workspace wipe"
	cd "$ROOT" || halt
	rm -rf -- "$REPO"
	tx "INFO Completed"
} || halt
