#!/usr/bin/env bash
set -eEuo pipefail
shopt -s inherit_errexit extglob globstar nullglob dotglob
umask 077

readonly LOGP=$HOME/Library/Logs/brew_upgrade.log
readonly SEMP=/tmp/brew_upgrade.lock
readonly BREWX=/opt/homebrew/bin/brew
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

	local -i S=0
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
			local -i PID=0
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

command -v brew &>/dev/null || [[ -x $BREWX ]] || {
	tx "CRITICAL Homebrew unavailable"
	exit 1
}

gate
trim
exec > >(exec tee -a "$LOGP") 2>&1

export HOMEBREW_NO_AUTO_UPDATE=1 \
	HOMEBREW_NO_INSTALL_CLEANUP=1 \
	HOMEBREW_NO_ANALYTICS=1 \
	HOMEBREW_NO_ENV_HINTS=1 \
	HOMEBREW_NO_INSTALL_UPGRADE=1 \
	LC_ALL=C

{
	declare -a BW
	if command -v brew &>/dev/null; then
		BW=(brew)
	else
		BW=("$BREWX")
	fi

	tx "INFO Brew update"
	"${BW[@]}" update

	tx "INFO Brew upgrade"
	"${BW[@]}" upgrade

	tx "INFO Brew cask upgrade"
	"${BW[@]}" upgrade --cask

	mapfile -t TP < <("${BW[@]}" tap 2>/dev/null || :)
	declare TPX
	for TPX in "${TP[@]}"; do
		[[ $TPX == buo/cask-upgrade ]] || continue
		tx "INFO Brew cu sequence"
		"${BW[@]}" cu -a -y
		break
	done

	tx "INFO Workspace wipe"
	"${BW[@]}" cleanup -s --prune=all

	tx "INFO Completed"
} || halt
