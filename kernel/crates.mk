# SPDX-License-Identifier: GPL-2.0
# kbuild compiles one .rs per .o and offers the compiler only `--extern
# kernel --extern pin_init`. Each external crate therefore gets a rule that
# emits, from one invocation, the .o linked into the module (without it modpost
# reports undefined items), the .rlib for `--extern` and the .rmeta for the
# `-L` search. One invocation has the symbol names of the metadata and of the
# object in agreement.

# `--extern name=path` names direct dependencies only. Transitive crates, such
# as `zerocopy` and its `zerocopy_derive` proc macro, are found only by
# searching the `-L` directories, and a missing one is reported under the name
# of whichever crate was asked for first.
procmacro_deps := $(VOIDPORT_PROCMACRO_DIR)/deps
zerocopy_derive := $(VOIDPORT_PROCMACRO_DIR)/libzerocopy_derive.so

# `zerocopy` is named as well as searched for, because a module that builds a
# request body constructs the byte-order integers of the wire crate by their
# crate path. A distinct crate name lets the zerocopy of the kernel coexist with
# the locked version of the workspace.
voidport-crate-objs := voidport_transport.o voidport_bindings.o voidport_session.o voidport_proto.o voidport_zerocopy.o
voidport-crate-externs := \
	--extern voidport_transport=$(obj)/libvoidport_transport.rlib \
	--extern voidport_proto=$(obj)/libvoidport_proto.rlib \
	--extern voidport_session=$(obj)/libvoidport_session.rlib \
	--extern wire_zerocopy=$(obj)/libvoidport_zerocopy.rlib \
	-L$(obj) -L$(procmacro_deps)

# `$(rust_flags)` already resolves `--cfg MODULE` and the config cfgs. The
# sysroot pair and the crate type are kept by kbuild in `cmd_rustc_o_rs`, so
# they are restated. The edition is filtered out because rustc rejects
# `--edition` twice.
crate_rustflags = \
	$(filter-out --edition=2021,$(rust_flags)) \
	-Zunstable-options --sysroot=/dev/null \
	-L$(objtree)/rust -L$(obj) -L$(procmacro_deps) \
	--crate-type rlib

crate_stem = $(basename $(notdir $@))

crate_compiler = $(RUSTC)
quiet_cmd_rustc_crate = RUSTC L $@
      cmd_rustc_crate = $(crate_compiler) $(crate_rustflags) $(crate_flags) \
	--crate-name $(crate_stem) \
	--emit=obj=$@ \
	--emit=link=$(obj)/lib$(crate_stem).rlib \
	--emit=metadata=$(obj)/lib$(crate_stem).rmeta \
	$< $(cmd_objtool)

# `rust/Makefile` builds the `core` of the kernel with `--cfg no_fp_fmt_parse`,
# which removes `Display` and `Debug` for `f32` and `f64`, and an out-of-tree
# build does not inherit the cfg. zerocopy declares the same cfg to drop those
# impls for its `F32` and `F64` types, and fails without it.
$(obj)/voidport_zerocopy.o: private crate_flags = \
	--edition=2021 \
	--cfg 'feature="derive"' \
	--cfg 'feature="simd"' \
	--cfg no_fp_fmt_parse \
	--extern zerocopy_derive=$(zerocopy_derive) \
	-Aunexpected_cfgs -Amissing_docs -Aunreachable_pub
$(obj)/voidport_zerocopy.o: $(VOIDPORT_ZEROCOPY_SRC)/src/lib.rs FORCE
	$(call if_changed,rustc_crate)

# `rust_common_flags` sets `-Dnon_ascii_idents`. The zerocopy derive expands to
# an enum with a non-ASCII name per field, so the deny fires once per wire
# struct field and points at an ASCII field name. The wire and session crates
# are workspace crates, so the kernel's `-Wmissing_docs` does not apply to them.
$(obj)/voidport_proto.o: private crate_flags = \
	--edition=2024 \
	-Anon_ascii_idents -Amissing_docs \
	--extern zerocopy=$(obj)/libvoidport_zerocopy.rlib
$(obj)/voidport_proto.o: $(VOIDPORT_PROTO_SRC)/src/lib.rs $(obj)/voidport_zerocopy.o FORCE
	$(call if_changed,rustc_crate)

$(obj)/voidport_session.o: private crate_flags = \
	--edition=2024 -Amissing_docs \
	--extern voidport_proto=$(obj)/libvoidport_proto.rlib
$(obj)/voidport_session.o: $(VOIDPORT_SESSION_SRC)/src/lib.rs $(obj)/voidport_proto.o FORCE
	$(call if_changed,rustc_crate)

# Supplemental bindings use libclang even when the kernel uses GCC. Exclude the
# GCC-only options of `bindgen_skip_c_flags` in `rust/Makefile` of the newest
# supported kernel. libclang refuses an unknown option, so a kernel that adds
# one needs the list extended.
voidport-bindgen-skip-c-flags := -mno-fp-ret-in-387 -mpreferred-stack-boundary=% \
	-mskip-rax-setup -mgeneral-regs-only -msign-return-address=% \
	-mindirect-branch=thunk-extern -mindirect-branch-register \
	-mfunction-return=thunk-extern -mrecord-mcount -mabi=lp64 \
	-mindirect-branch-cs-prefix -mstack-protector-guard% -mtraceback=no \
	-mno-pointers-to-nested-functions -mno-string \
	-mno-strict-align -mstrict-align -mdirect-extern-access \
	-mexplicit-relocs -mno-check-zero-division \
	-fconserve-stack -falign-jumps=% -falign-loops=% \
	-femit-struct-debug-baseonly -fno-ipa-cp-clone -fno-ipa-sra \
	-fno-partial-inlining -fplugin-arg-arm_ssp_per_task_plugin-% \
	-fno-reorder-blocks -fno-allow-store-data-races -fasan-shadow-offset=% \
	-fzero-call-used-regs=% -fno-stack-clash-protection \
	-fno-inline-functions-called-once -fsanitize=bounds-strict \
	-fstrict-flex-arrays=% -fmin-function-alignment=% \
	-fzero-init-padding-bits=% -mno-fdpic \
	-fdiagnostics-show-context -fdiagnostics-show-context=% \
	--param=% --param asan-% -fno-isolate-erroneous-paths-dereference \
	-ffixed-r2 -mmultiple -mno-readonly-in-sdata
voidport-bindgen-flags = $(filter-out $(voidport-bindgen-skip-c-flags), $(c_flags)) \
	-fno-builtin -D__BINDGEN__

# Generated from the headers of this build, because the tree-wide bindings
# header list lacks them. The record of the virtio device stays opaque.
quiet_cmd_voidport_transport_bindgen = BINDGEN $@
      cmd_voidport_transport_bindgen = $(BINDGEN) $< --use-core --ctypes-prefix kernel::ffi \
	--rust-target 1.85 --formatter none --no-layout-tests --no-debug '.*' \
	--no-recursive-allowlist --with-derive-custom-struct '.*=MaybeZeroable' \
	--allowlist-type 'sockaddr_in|in_addr|sockaddr_un|virtio_driver|virtio_device_id|virtio_device|virtqueue|virtqueue_info|vq_callback_t|virtio_fs_config|__u8|__u32|__le32' \
	--opaque-type 'virtio_device' \
	--allowlist-function 'in4_pton|in6_pton|tcp_sock_set_nodelay|sk_net_refcnt_upgrade|voidport_get_net|voidport_put_net|voidport_connect_from_init_root|voidport_socket_wait_add|voidport_wait_woken_killable|__register_virtio_driver|unregister_virtio_driver|virtio_reset_device|virtqueue_add_sgs|virtqueue_kick_prepare|virtqueue_notify|virtqueue_get_buf|virtqueue_disable_cb|virtqueue_enable_cb|virtqueue_detach_unused_buf|virtqueue_get_vring_size|voidport_virtio_.*|voidport_sg_set_page|voidport_folio_page|voidport_get_page|voidport_put_page' \
	--allowlist-var 'UNIX_PATH_MAX|VIRTIO_ID_FS|VIRTIO_DEV_ANY_ID|VOIDPORT_GFP_NOIO' \
	-o $@ -- $(voidport-bindgen-flags)

$(obj)/transport_generated.rs: $(src)/../transport/transport_bindings.h FORCE
	$(call if_changed_dep,voidport_transport_bindgen)

export VOIDPORT_TRANSPORT_BINDINGS = $(abspath $(obj)/transport_generated.rs)
targets += transport_generated.rs
clean-files += transport_generated.rs

# The generated bindings are compiled with a lint cap so that the cap does not
# apply to the hand-written crates.
$(obj)/voidport_bindings.o: private crate_flags = --edition=2021 --cap-lints allow \
	--extern kernel --extern pin_init
$(obj)/voidport_bindings.o: $(src)/../transport/voidport_bindings.rs $(obj)/transport_generated.rs FORCE
	$(call if_changed,rustc_crate)

$(obj)/voidport_transport.o: private crate_compiler = $(RUSTC_OR_CLIPPY)
$(obj)/voidport_transport.o: private crate_flags = --edition=2021 \
	--extern kernel --extern pin_init \
	--extern voidport_bindings=$(obj)/libvoidport_bindings.rlib \
	--extern voidport_proto=$(obj)/libvoidport_proto.rlib \
	--extern voidport_session=$(obj)/libvoidport_session.rlib
transport-sources := $(addprefix $(src)/../transport/,clock.rs errno.rs \
	handshake.rs part.rs socket.rs thread.rs virtio.rs virtio/chain.rs \
	virtio/queue.rs wire.rs transport_helpers.rs) \
	$(src)/../compat.rs
$(obj)/voidport_transport.o: $(src)/../transport/voidport_transport.rs $(obj)/voidport_session.o $(obj)/voidport_bindings.o $(transport-sources) FORCE
	$(call if_changed,rustc_crate)

targets += voidport_transport.o voidport_bindings.o voidport_zerocopy.o voidport_proto.o voidport_session.o
clean-files += libvoidport_transport.rlib libvoidport_transport.rmeta \
	       libvoidport_bindings.rlib libvoidport_bindings.rmeta
clean-files += libvoidport_zerocopy.rlib libvoidport_zerocopy.rmeta \
	       libvoidport_proto.rlib libvoidport_proto.rmeta \
	       libvoidport_session.rlib libvoidport_session.rmeta
