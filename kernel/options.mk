# SPDX-License-Identifier: GPL-2.0

options-objs := voidport_kernel_options.o fixed.o bytemuck.o typenum.o cfg_if.o
# The out-of-line float conversions of az are not part of the kernel parser and
# must not enter the module object.
options-flags := --edition=2021 --cap-lints allow

# These metadata dependencies are not linked, but their sanitizer ABI must match
# the kernel core and the crates that consume their MIR.
KASAN_SANITIZE_az.o := y
KASAN_SANITIZE_half.o := y

$(obj)/az.o: private crate_flags = $(options-flags)
$(obj)/az.o: $(VOIDPORT_AZ_SRC)/src/lib.rs FORCE
	$(call if_changed,rustc_crate)

$(obj)/bytemuck.o: private crate_flags = $(options-flags)
$(obj)/bytemuck.o: $(VOIDPORT_BYTEMUCK_SRC)/src/lib.rs FORCE
	$(call if_changed,rustc_crate)

$(obj)/typenum.o: private crate_flags = $(options-flags)
$(obj)/typenum.o: $(VOIDPORT_TYPENUM_SRC)/src/lib.rs FORCE
	$(call if_changed,rustc_crate)

$(obj)/cfg_if.o: private crate_flags = $(options-flags)
$(obj)/cfg_if.o: $(VOIDPORT_CFG_IF_SRC)/src/lib.rs FORCE
	$(call if_changed,rustc_crate)

# No half object is linked. Its rlib supplies types and MIR for generic
# conversions.
$(obj)/half.o: private crate_flags = $(options-flags) --cfg no_fp_fmt_parse \
	--extern cfg_if=$(obj)/libcfg_if.rlib \
	--extern zerocopy=$(obj)/libvoidport_zerocopy.rlib
$(obj)/half.o: $(VOIDPORT_HALF_SRC)/src/lib.rs $(obj)/cfg_if.o $(obj)/voidport_zerocopy.o FORCE
	$(call if_changed,rustc_crate)

$(obj)/fixed.o: private crate_flags = $(options-flags) \
	--extern az=$(obj)/libaz.rlib \
	--extern bytemuck=$(obj)/libbytemuck.rlib \
	--extern typenum=$(obj)/libtypenum.rlib \
	--extern half=$(obj)/libhalf.rlib
$(obj)/fixed.o: $(VOIDPORT_FIXED_SRC)/src/lib.rs $(obj)/az.o $(obj)/bytemuck.o $(obj)/typenum.o $(obj)/half.o FORCE
	$(call if_changed,rustc_crate)

$(obj)/voidport_kernel_options.o: private crate_flags = --edition=2021 \
	--extern fixed=$(obj)/libfixed.rlib
$(obj)/voidport_kernel_options.o: $(VOIDPORT_OPTIONS_SRC)/src/lib.rs $(obj)/fixed.o FORCE
	$(call if_changed,rustc_crate)

targets += $(options-objs) half.o az.o
clean-files += $(foreach name,az bytemuck typenum cfg_if fixed half voidport_kernel_options,lib$(name).rlib lib$(name).rmeta)
