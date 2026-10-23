# shellcheck shell=bash
voidport_cpus=${VOIDPORT_CPUS:-0-$(($(nproc) - 1))}
voidport_cores=${VOIDPORT_CORES:-$(nproc)}
