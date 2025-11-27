#!/usr/bin/env bash
set -eEuo pipefail
shopt -s inherit_errexit extglob globstar nullglob dotglob
umask 077

readonly LOGP=$HOME/Library/Logs/uv_upgrade.log
readonly SEMP=/tmp/uv_upgrade.lock
readonly UVX=/opt/homebrew/bin/uv
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

tools() {
	tx "INFO Enumerate installed tools"
	local -a tools_raw uv_cmd
	if command -v uv &>/dev/null; then
		uv_cmd=(uv)
	else
		uv_cmd=("$UVX")
	fi
	mapfile -t tools_raw < <("${uv_cmd[@]}" tool list 2>/dev/null || :)
	local -a tools=()
	local line
	for line in "${tools_raw[@]}"; do
		[[ $line == [^-[:space:]]* ]] && tools+=("${line%% *}")
	done
	((${#tools[@]} == 0)) && {
		tx "INFO No tools installed, nothing to upgrade"
		return 0
	}
	tx "INFO Found installed tools, proceeding with upgrades"
	local tool
	for tool in "${tools[@]}"; do
		[[ -n $tool && $tool != - ]] || continue
		tx "INFO Tool upgrade $tool"
		"${uv_cmd[@]}" tool upgrade "$tool" 2>/dev/null || tx "WARN Tool upgrade failure $tool"
	done
}

packages() {
	tx "INFO Checking for outdated Python packages"
	local -a outdated_lines uv_cmd
	if command -v uv &>/dev/null; then
		uv_cmd=(uv)
	else
		uv_cmd=("$UVX")
	fi
	mapfile -t outdated_lines < <("${uv_cmd[@]}" pip list --outdated 2>/dev/null || :)
	((${#outdated_lines[@]} < 3)) && {
		tx "INFO No outdated Python packages found"
		return 0
	}
	local -a outdated_packages=()
	local -i i
	for ((i = 2; i < ${#outdated_lines[@]}; i++)); do
		local pkg=${outdated_lines[i]%% *}
		[[ -n $pkg ]] && outdated_packages+=("$pkg")
	done
	((${#outdated_packages[@]} == 0)) && {
		tx "INFO No outdated Python packages found"
		return 0
	}
	tx "INFO Found outdated Python packages, proceeding with upgrades"
	local package
	for package in "${outdated_packages[@]}"; do
		[[ -n $package ]] || continue
		tx "INFO Package upgrade $package"
		"${uv_cmd[@]}" pip install -U "$package" 2>/dev/null || tx "WARN Package upgrade failure $package"
	done
}

trap halt ERR
trap wipe EXIT INT TERM HUP

command -v uv &>/dev/null || [[ -x $UVX ]] || {
	tx "CRITICAL uv interface offline"
	exit 1
}

gate
trim
exec > >(exec tee -a "$LOGP") 2>&1
export LC_ALL=C

main() {
	tools
	packages
	tx "INFO Completed"
}

main || halt
