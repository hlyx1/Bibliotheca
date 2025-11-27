#!/usr/bin/env bash
set -eEuo pipefail
shopt -s inherit_errexit extglob globstar nullglob dotglob
umask 077
readonly ROOT=$HOME/Library/Rime
readonly LOGP=$HOME/Library/Logs/rime_upgrade.log
readonly SEMP=/tmp/rime_upgrade.lock
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
		[[ $I -eq ROT && -f $CUR ]] && rm -f -- "$CUR"
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

[[ -d $ROOT/.git ]] || {
	tx "CRITICAL Rime repository offline"
	exit 1
}

command -v git &>/dev/null || {
	tx "CRITICAL git interface offline"
	exit 1
}

gate
trim
exec > >(exec tee -a "$LOGP") 2>&1
export GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND='ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new' LC_ALL=C

{
	tx "INFO Rime sync"
	cd "$ROOT" || halt
	git pull --ff-only
	tx "INFO Completed"
} || halt
