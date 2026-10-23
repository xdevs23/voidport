# SPDX-License-Identifier: GPL-2.0
# The allowlist is nonrecursive, so other types come from kernel::bindings.
quiet_cmd_voidport_bindgen = BINDGEN $@
      cmd_voidport_bindgen = $(BINDGEN) $< --use-core --ctypes-prefix kernel::ffi \
	--rust-target 1.85 --formatter none --no-layout-tests --no-debug '.*' \
	--no-recursive-allowlist \
	--allowlist-type 'fs_context|fs_context_operations|fs_context_purpose|fs_context_phase|p_log|fc_log|fs_parameter|fs_parameter_spec|fs_parse_result|fs_value_type|fs_param_type|kstatfs|xattr_handler|voidport_record_lock' \
	--allowlist-function '__fs_parse|get_tree_nodev|fs_param_is_u32|fs_param_is_string|posix_acl_from_xattr' \
	--allowlist-var 'VOIDPORT_LOOKUP_.*|VOIDPORT_SB_RDONLY|VOIDPORT_SB_POSIXACL|VOIDPORT_FMODE_.*|XATTR_CREATE|XATTR_REPLACE' \
	-o $@ -- $(voidport-bindgen-flags)

$(obj)/vfs_generated.rs: $(src)/../compat.h FORCE
	$(call if_changed_dep,voidport_bindgen)

$(obj)/voidport_main.o: $(obj)/vfs_generated.rs
# The generated source lives in the object directory, including for O= builds.
export VOIDPORT_VFS_BINDINGS = $(abspath $(obj)/vfs_generated.rs)
targets += vfs_generated.rs
clean-files += vfs_generated.rs
