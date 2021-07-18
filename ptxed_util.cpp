#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <intel-pt.h>
#include <signal.h>
#include <wait.h>

extern "C" {
#include "lib/xed-interface.h"
}

#define GM_LEFT_CONTEXT 	(1<<0)
#define GM_RET_PENDING 		(1<<1)
#define GM_CALL_PENDING 	(1<<2)

enum ptxed_decoder_type {
	pdt_insn_decoder,
	pdt_block_decoder
};

struct ptxed_decoder {
	/* The decoder type. */
	enum ptxed_decoder_type type;

	/* The actual decoder. */
	union {
		/* If @type == pdt_insn_decoder */
		struct pt_insn_decoder *insn;

		/* If @type == pdt_block_decoder */
		struct pt_block_decoder *block;
	} variant;

	/* Decoder-specific configuration.
	 *
	 * We use a set of structs to store the configuration for multiple
	 * decoders.
	 *
	 * - block decoder.
	 */
	struct {
		/* A collection of decoder-specific flags. */
		struct pt_conf_flags flags;
	} block;

	/* - instruction flow decoder. */
	struct {
		/* A collection of decoder-specific flags. */
		struct pt_conf_flags flags;
	} insn;


	/* The image section cache. */
	struct pt_image_section_cache *iscache;
};

/* A collection of options. */
struct ptxed_options {
	/* Do not print the instruction. */
	uint32_t dont_print_insn:1;

	/* Remain as quiet as possible - excluding error messages. */
	uint32_t quiet:1;

	/* Print statistics (overrides quiet). */
	uint32_t print_stats:1;

	/* Print information about section loads and unloads. */
	uint32_t track_image:1;

	/* Track blocks in the output.
	 *
	 * This only applies to the block decoder.
	 */
	uint32_t track_blocks:1;

	/* Print in AT&T format. */
	uint32_t att_format:1;

	/* Print the offset into the trace file. */
	uint32_t print_offset:1;

	/* Print the current timestamp. */
	uint32_t print_time:1;

	/* Print the raw bytes for an insn. */
	uint32_t print_raw_insn:1;

	/* Perform checks. */
	uint32_t check:1;

	/* Print the time stamp of events. */
	uint32_t print_event_time:1;

	/* Print the ip of events. */
	uint32_t print_event_ip:1;
};

/* A collection of flags selecting which stats to collect/print. */
enum ptxed_stats_flag {
	/* Collect number of instructions. */
	ptxed_stat_insn		= (1 << 0),

	/* Collect number of blocks. */
	ptxed_stat_blocks	= (1 << 1)
};

/* A collection of statistics. */
struct ptxed_stats {
	/* The number of instructions. */
	uint64_t insn;

	/* The number of blocks.
	 *
	 * This only applies to the block decoder.
	 */
	uint64_t blocks;

	/* A collection of flags saying which statistics to collect/print. */
	uint32_t flags;
};

static int ptxed_init_decoder(struct ptxed_decoder *decoder)
{
	if (!decoder)
		return -pte_internal;

	memset(decoder, 0, sizeof(*decoder));
	decoder->type = pdt_block_decoder;

	decoder->iscache = pt_iscache_alloc(NULL);
	if (!decoder->iscache)
		return -pte_nomem;

	return 0;
}

static int ptxed_print_error(int errcode, const char *filename,
			     uint64_t offset, void *priv)
{
	const struct ptxed_options *options;
	const char *errstr, *severity;

	options = (struct ptxed_options *) priv;
	if (!options)
		return -pte_internal;

	if (errcode >= 0)
		return 0;

	if (!filename)
		filename = "<unknown>";

	severity = errcode < 0 ? "error" : "warning";

	errstr = errcode < 0
		? pt_errstr(pt_errcode(errcode))
		: "";

	if (!errstr)
		errstr = "<unknown error>";

	printf("[%s:%016" PRIx64 " sideband %s: %s]\n", filename, offset,
	       severity, errstr);

	return 0;
}

static int ptxed_have_decoder(const struct ptxed_decoder *decoder)
{
	/* It suffices to check for one decoder in the variant union. */
	return decoder && decoder->variant.insn;
}

static int alloc_decoder(struct ptxed_decoder *decoder,
			 const struct pt_config *conf, struct pt_image *image,
			 const struct ptxed_options *options, const char *prog)
{
	struct pt_config config;
	int errcode;

	if (!decoder || !conf || !options || !prog)
		return -pte_internal;

	config = *conf;

	switch (decoder->type) {
	case pdt_insn_decoder:
		config.flags = decoder->insn.flags;

		decoder->variant.insn = pt_insn_alloc_decoder(&config);
		if (!decoder->variant.insn) {
			fprintf(stderr,
				"%s: failed to create decoder.\n", prog);
			return -pte_nomem;
		}

		errcode = pt_insn_set_image(decoder->variant.insn, image);
		if (errcode < 0) {
			fprintf(stderr, "%s: failed to set image.\n", prog);
			return errcode;
		}

		break;

	case pdt_block_decoder:
		config.flags = decoder->block.flags;

		decoder->variant.block = pt_blk_alloc_decoder(&config);
		if (!decoder->variant.block) {
			fprintf(stderr,
				"%s: failed to create  decoder.\n", prog);
			return -pte_nomem;
		}

		errcode = pt_blk_set_image(decoder->variant.block, image);
		if (errcode < 0) {
			fprintf(stderr, "%s: failed to set image.\n", prog);
			return errcode;
		}

		break;
	}

	return 0;
}

static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return XED_MACHINE_MODE_INVALID;

	case ptem_16bit:
		return XED_MACHINE_MODE_LEGACY_16;

	case ptem_32bit:
		return XED_MACHINE_MODE_LEGACY_32;

	case ptem_64bit:
		return XED_MACHINE_MODE_LONG_64;
	}

	return XED_MACHINE_MODE_INVALID;
}

static const char *visualize_iclass(enum pt_insn_class iclass)
{
	switch (iclass) {
	case ptic_error:
		return "unknown/error";

	case ptic_other:
		return "other";

	case ptic_call:
		return "near call";

	case ptic_return:
		return "near return";

	case ptic_jump:
		return "near jump";

	case ptic_cond_jump:
		return "cond jump";

	case ptic_far_call:
		return "far call";

	case ptic_far_return:
		return "far return";

	case ptic_far_jump:
		return "far jump";

	case ptic_ptwrite:
		return "ptwrite";
	}

	return "undefined";
}

// GM
static enum pt_insn_class xed_to_pt_iclass(xed_iclass_enum_t xed_iclass,
									  xed_category_enum_t xed_category)
{
	enum pt_insn_class ret;

	switch (xed_iclass)
	{
		case XED_ICLASS_CALL_NEAR:
			ret = ptic_call;
			break;
		
		case XED_ICLASS_RET_NEAR:
			ret = ptic_return;
			break;

		case XED_ICLASS_JMP:
			ret = ptic_jump;
			break;

		case XED_ICLASS_CALL_FAR:
		case XED_ICLASS_INT:
		case XED_ICLASS_INT1:
		case XED_ICLASS_INT3:
		case XED_ICLASS_INTO:
		case XED_ICLASS_SYSCALL:
		case XED_ICLASS_SYSCALL_AMD:
		case XED_ICLASS_SYSENTER:
		case XED_ICLASS_VMCALL:
			ret = ptic_far_call;
			break;

		case XED_ICLASS_RET_FAR:
		case XED_ICLASS_IRET:
		case XED_ICLASS_IRETD:
		case XED_ICLASS_IRETQ:
		case XED_ICLASS_SYSRET:
		case XED_ICLASS_SYSRET_AMD:
		case XED_ICLASS_SYSEXIT:
		case XED_ICLASS_VMLAUNCH:
		case XED_ICLASS_VMRESUME:
			ret = ptic_far_return;
			break;
		
		case XED_ICLASS_JMP_FAR:
			ret = ptic_far_jump;
			break;
		
		default:
			ret = ptic_other;
	}

	if (xed_category == XED_CATEGORY_COND_BR && ret == ptic_other)
	{
		ret = ptic_cond_jump;
	}

	return ret;
}

static void check_insn_iclass(const xed_inst_t *inst,
			      const struct pt_insn *insn, uint64_t offset)
{
	xed_category_enum_t category;
	xed_iclass_enum_t iclass;

	if (!inst || !insn) {
		printf("[internal error]\n");
		return;
	}

	category = xed_inst_category(inst);
	iclass = xed_inst_iclass(inst);

	switch (insn->iclass) {
	case ptic_error:
		break;

	case ptic_ptwrite:
	case ptic_other:
		switch (category) {
		default:
			return;

		case XED_CATEGORY_CALL:
		case XED_CATEGORY_RET:
		case XED_CATEGORY_UNCOND_BR:
		case XED_CATEGORY_SYSCALL:
		case XED_CATEGORY_SYSRET:
			break;

		case XED_CATEGORY_COND_BR:
			switch (iclass) {
			case XED_ICLASS_XBEGIN:
			case XED_ICLASS_XEND:
				return;

			default:
				break;
			}
			break;

		case XED_CATEGORY_INTERRUPT:
			switch (iclass) {
			case XED_ICLASS_BOUND:
				return;

			default:
				break;
			}
			break;
		}
		break;

	case ptic_call:
		if (iclass == XED_ICLASS_CALL_NEAR)
			return;

		break;

	case ptic_return:
		if (iclass == XED_ICLASS_RET_NEAR)
			return;

		break;

	case ptic_jump:
		if (iclass == XED_ICLASS_JMP)
			return;

		break;

	case ptic_cond_jump:
		if (category == XED_CATEGORY_COND_BR)
			return;

		break;

	case ptic_far_call:
		switch (iclass) {
		default:
			break;

		case XED_ICLASS_CALL_FAR:
		case XED_ICLASS_INT:
		case XED_ICLASS_INT1:
		case XED_ICLASS_INT3:
		case XED_ICLASS_INTO:
		case XED_ICLASS_SYSCALL:
		case XED_ICLASS_SYSCALL_AMD:
		case XED_ICLASS_SYSENTER:
		case XED_ICLASS_VMCALL:
			return;
		}
		break;

	case ptic_far_return:
		switch (iclass) {
		default:
			break;

		case XED_ICLASS_RET_FAR:
		case XED_ICLASS_IRET:
		case XED_ICLASS_IRETD:
		case XED_ICLASS_IRETQ:
		case XED_ICLASS_SYSRET:
		case XED_ICLASS_SYSRET_AMD:
		case XED_ICLASS_SYSEXIT:
		case XED_ICLASS_VMLAUNCH:
		case XED_ICLASS_VMRESUME:
			return;
		}
		break;

	case ptic_far_jump:
		if (iclass == XED_ICLASS_JMP_FAR)
			return;

		break;
	}

	/* If we get here, @insn->iclass doesn't match XED's classification. */
	printf("[%" PRIx64 ", %" PRIx64 ": iclass error: iclass: %s, "
	       "xed iclass: %s, category: %s]\n", offset, insn->ip,
	       visualize_iclass(insn->iclass), xed_iclass_enum_t2str(iclass),
	       xed_category_enum_t2str(category));

}

static void check_insn_decode(xed_decoded_inst_t *inst,
			      const struct pt_insn *insn, uint64_t offset)
{
	xed_error_enum_t errcode;

	if (!inst || !insn) {
		printf("[internal error]\n");
		return;
	}

	xed_decoded_inst_set_mode(inst, translate_mode(insn->mode),
				  XED_ADDRESS_WIDTH_INVALID);

	/* Decode the instruction (again).
	 *
	 * We may have decoded the instruction already for printing.  In this
	 * case, we will decode it twice.
	 *
	 * The more common use-case, however, is to check the instruction class
	 * while not printing instructions since the latter is too expensive for
	 * regular use with long traces.
	 */
	errcode = xed_decode(inst, insn->raw, insn->size);
	if (errcode != XED_ERROR_NONE) {
		printf("[%" PRIx64 ", %" PRIx64 ": xed error: (%u) %s]\n",
		       offset, insn->ip, errcode,
		       xed_error_enum_t2str(errcode));
		return;
	}

	if (!xed_decoded_inst_valid(inst)) {
		printf("[%" PRIx64 ", %" PRIx64 ": xed error: "
		       "invalid instruction]\n", offset, insn->ip);
		return;
	}
}

static void check_insn(const struct pt_insn *insn, uint64_t offset)
{
	xed_decoded_inst_t inst;

	if (!insn) {
		printf("[internal error]\n");
		return;
	}

	if (insn->isid <= 0)
		printf("[%" PRIx64 ", %" PRIx64 ": check error: "
		       "bad isid]\n", offset, insn->ip);

	xed_decoded_inst_zero(&inst);
	check_insn_decode(&inst, insn, offset);

	/* We need a valid instruction in order to do further checks.
	 *
	 * Invalid instructions have already been diagnosed.
	 */
	if (!xed_decoded_inst_valid(&inst))
		return;

	check_insn_iclass(xed_decoded_inst_inst(&inst), insn, offset);
}

static void print_raw_insn(const struct pt_insn *insn)
{
	uint8_t length, idx;

	if (!insn) {
		printf("[internal error]");
		return;
	}

	length = insn->size;
	if (sizeof(insn->raw) < length)
		length = sizeof(insn->raw);

	for (idx = 0; idx < length; ++idx)
		printf(" %02x", insn->raw[idx]);

	for (; idx < pt_max_insn_size; ++idx)
		printf("   ");
}

static void xed_print_insn(const xed_decoded_inst_t *inst, uint64_t ip,
			   const struct ptxed_options *options)
{
	xed_print_info_t pi;
	char buffer[256];
	xed_bool_t ok;

	if (!inst || !options) {
		printf(" [internal error]");
		return;
	}

	if (options->print_raw_insn) {
		xed_uint_t length, i;

		length = xed_decoded_inst_get_length(inst);
		for (i = 0; i < length; ++i)
			printf(" %02x", xed_decoded_inst_get_byte(inst, i));

		for (; i < pt_max_insn_size; ++i)
			printf("   ");
	}

	xed_init_print_info(&pi);
	pi.p = inst;
	pi.buf = buffer;
	pi.blen = sizeof(buffer);
	pi.runtime_address = ip;

	if (options->att_format)
		pi.syntax = XED_SYNTAX_ATT;

	ok = xed_format_generic(&pi);
	if (!ok) {
		printf(" [xed print error]");
		return;
	}

	printf("  %s", buffer);
}

static void print_insn(const struct pt_insn *insn, xed_state_t *xed,
		       const struct ptxed_options *options, uint64_t offset,
		       uint64_t time)
{
	if (!insn || !options) {
		printf("[internal error]\n");
		return;
	}

	if (options->print_offset)
		printf("%016" PRIx64 "  ", offset);

	if (options->print_time)
		printf("%016" PRIx64 "  ", time);

	if (insn->speculative)
		printf("? ");

	printf("%016" PRIx64, insn->ip);

	if (!options->dont_print_insn) {
		xed_machine_mode_enum_t mode;
		xed_decoded_inst_t inst;
		xed_error_enum_t errcode;

		mode = translate_mode(insn->mode);

		xed_state_set_machine_mode(xed, mode);
		xed_decoded_inst_zero_set_mode(&inst, xed);

		errcode = xed_decode(&inst, insn->raw, insn->size);
		switch (errcode) {
		case XED_ERROR_NONE:
			xed_print_insn(&inst, insn->ip, options);
			break;

		default:
			print_raw_insn(insn);

			printf(" [xed decode error: (%u) %s]", errcode,
			       xed_error_enum_t2str(errcode));
			break;
		}
	}

	printf("\n");
}

static const char *print_exec_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return "<unknown>";

	case ptem_16bit:
		return "16-bit";

	case ptem_32bit:
		return "32-bit";

	case ptem_64bit:
		return "64-bit";
	}

	return "<invalid>";
}

static void print_event(const struct pt_event *event,
			const struct ptxed_options *options, uint64_t offset)
{
	if (!event || !options) {
		printf("[internal error]\n");
		return;
	}

	printf("[");

	if (options->print_offset)
		printf("%016" PRIx64 "  ", offset);

	if (options->print_event_time && event->has_tsc)
		printf("%016" PRIx64 "  ", event->tsc);

	switch (event->type) {
	case ptev_enabled:
		printf("%s", event->variant.enabled.resumed ? "resumed" :
		       "enabled");

		if (options->print_event_ip)
			printf(", ip: %016" PRIx64, event->variant.enabled.ip);
		break;

	case ptev_disabled:
		printf("disabled");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.disabled.ip);
		break;

	case ptev_async_disabled:
		printf("disabled");

		if (options->print_event_ip) {
			printf(", at: %016" PRIx64,
			       event->variant.async_disabled.at);

			if (!event->ip_suppressed)
				printf(", ip: %016" PRIx64,
				       event->variant.async_disabled.ip);
		}
		break;

	case ptev_async_branch:
		printf("interrupt");

		if (options->print_event_ip) {
			printf(", from: %016" PRIx64,
			       event->variant.async_branch.from);

			if (!event->ip_suppressed)
				printf(", to: %016" PRIx64,
				       event->variant.async_branch.to);
		}
		break;

	case ptev_paging:
		printf("paging, cr3: %016" PRIx64 "%s",
		       event->variant.paging.cr3,
		       event->variant.paging.non_root ? ", nr" : "");
		break;

	case ptev_async_paging:
		printf("paging, cr3: %016" PRIx64 "%s",
		       event->variant.async_paging.cr3,
		       event->variant.async_paging.non_root ? ", nr" : "");

		if (options->print_event_ip)
			printf(", ip: %016" PRIx64,
			       event->variant.async_paging.ip);
		break;

	case ptev_overflow:
		printf("overflow");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.overflow.ip);
		break;

	case ptev_exec_mode:
		printf("exec mode: %s",
		       print_exec_mode(event->variant.exec_mode.mode));

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64,
			       event->variant.exec_mode.ip);
		break;

	case ptev_tsx:
		if (event->variant.tsx.aborted)
			printf("aborted");
		else if (event->variant.tsx.speculative)
			printf("begin transaction");
		else
			printf("committed");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.tsx.ip);
		break;

	case ptev_stop:
		printf("stopped");
		break;

	case ptev_vmcs:
		printf("vmcs, base: %016" PRIx64, event->variant.vmcs.base);
		break;

	case ptev_async_vmcs:
		printf("vmcs, base: %016" PRIx64,
		       event->variant.async_vmcs.base);

		if (options->print_event_ip)
			printf(", ip: %016" PRIx64,
			       event->variant.async_vmcs.ip);
		break;

	case ptev_exstop:
		printf("exstop");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.exstop.ip);
		break;

	case ptev_mwait:
		printf("mwait %" PRIx32 " %" PRIx32,
		       event->variant.mwait.hints, event->variant.mwait.ext);

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.mwait.ip);
		break;

	case ptev_pwre:
		printf("pwre c%u.%u", (event->variant.pwre.state + 1) & 0xf,
		       (event->variant.pwre.sub_state + 1) & 0xf);

		if (event->variant.pwre.hw)
			printf(" hw");
		break;


	case ptev_pwrx:
		printf("pwrx ");

		if (event->variant.pwrx.interrupt)
			printf("int: ");

		if (event->variant.pwrx.store)
			printf("st: ");

		if (event->variant.pwrx.autonomous)
			printf("hw: ");

		printf("c%u (c%u)", (event->variant.pwrx.last + 1) & 0xf,
		       (event->variant.pwrx.deepest + 1) & 0xf);
		break;

	case ptev_ptwrite:
		printf("ptwrite: %" PRIx64, event->variant.ptwrite.payload);

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.ptwrite.ip);
		break;

	case ptev_tick:
		printf("tick");

		if (options->print_event_ip && !event->ip_suppressed)
			printf(", ip: %016" PRIx64, event->variant.tick.ip);
		break;

	case ptev_cbr:
		printf("cbr: %x", event->variant.cbr.ratio);
		break;

	case ptev_mnt:
		printf("mnt: %" PRIx64, event->variant.mnt.payload);
		break;
	}

	printf("]\n");
}

static int xed_next_ip(uint64_t *pip, const xed_decoded_inst_t *inst,
		       uint64_t ip)
{
	xed_uint_t length, disp_width;

	if (!pip || !inst)
		return -pte_internal;

	length = xed_decoded_inst_get_length(inst);
	if (!length) {
		printf("[xed error: failed to determine instruction length]\n");
		return -pte_bad_insn;
	}

	ip += length;

	/* If it got a branch displacement it must be a branch.
	 *
	 * This includes conditional branches for which we don't know whether
	 * they were taken.  The next IP won't be used in this case as a
	 * conditional branch ends a block.  The next block will start with the
	 * correct IP.
	 */
	disp_width = xed_decoded_inst_get_branch_displacement_width(inst);
	if (disp_width)
		ip += (uint64_t) (int64_t)
			xed_decoded_inst_get_branch_displacement(inst);

	*pip = ip;
	return 0;
}

static int block_fetch_insn(struct pt_insn *insn, const struct pt_block *block,
			    uint64_t ip, struct pt_image_section_cache *iscache)
{
	if (!insn || !block)
		return -pte_internal;

	/* We can't read from an empty block. */
	if (!block->ninsn)
		return -pte_invalid;

	memset(insn, 0, sizeof(*insn));
	insn->mode = block->mode;
	insn->isid = block->isid;
	insn->ip = ip;

	/* The last instruction in a block may be truncated. */
	if ((ip == block->end_ip) && block->truncated) {
		if (!block->size || (sizeof(insn->raw) < (size_t) block->size))
			return -pte_bad_insn;

		insn->size = block->size;
		memcpy(insn->raw, block->raw, insn->size);
	} else {
		int size;

		size = pt_iscache_read(iscache, insn->raw, sizeof(insn->raw),
				       insn->isid, ip);
		if (size < 0)
			return size;

		insn->size = (uint8_t) size;
	}

	return 0;
}

static void diagnose(struct ptxed_decoder *decoder, uint64_t ip,
		     const char *errtype, int errcode)
{
	int err;
	uint64_t pos;

	err = -pte_internal;
	pos = 0ull;

	switch (decoder->type) {
	case pdt_insn_decoder:
		err = pt_insn_get_offset(decoder->variant.insn, &pos);
		break;

	case pdt_block_decoder:
		err = pt_blk_get_offset(decoder->variant.block, &pos);
		break;
	}

	if (err < 0) {
		printf("could not determine offset: %s\n",
		       pt_errstr(pt_errcode(err)));
		printf("[?, %" PRIx64 ": %s: %s]\n", ip, errtype,
		       pt_errstr(pt_errcode(errcode)));
	} else
		printf("[%" PRIx64 ", %" PRIx64 ": %s: %s]\n", pos,
		       ip, errtype, pt_errstr(pt_errcode(errcode)));
}

static void diagnose_block(struct ptxed_decoder *decoder,
			   const char *errtype, int errcode,
			   const struct pt_block *block)
{
	uint64_t ip;
	int err;

	if (!decoder || !block) {
		printf("ptxed: internal error");
		return;
	}

	/* Determine the IP at which to report the error.
	 *
	 * Depending on the type of error, the IP varies between that of the
	 * last instruction in @block or the next instruction outside of @block.
	 *
	 * When the block is empty, we use the IP of the block itself,
	 * i.e. where the first instruction should have been.
	 */
	if (!block->ninsn)
		ip = block->ip;
	else {
		ip = block->end_ip;

		switch (errcode) {
		case -pte_nomap:
		case -pte_bad_insn: {
			struct pt_insn insn;
			xed_decoded_inst_t inst;
			xed_error_enum_t xederr;

			/* Decode failed when trying to fetch or decode the next
			 * instruction.  Since indirect or conditional branches
			 * end a block and don't cause an additional fetch, we
			 * should be able to reach that IP from the last
			 * instruction in @block.
			 *
			 * We ignore errors and fall back to the IP of the last
			 * instruction.
			 */
			err = block_fetch_insn(&insn, block, ip,
					       decoder->iscache);
			if (err < 0)
				break;

			xed_decoded_inst_zero(&inst);
			xed_decoded_inst_set_mode(&inst,
						  translate_mode(insn.mode),
						  XED_ADDRESS_WIDTH_INVALID);

			xederr = xed_decode(&inst, insn.raw, insn.size);
			if (xederr != XED_ERROR_NONE)
				break;

			(void) xed_next_ip(&ip, &inst, insn.ip);
		}
			break;

		default:
			break;
		}
	}

	diagnose(decoder, ip, errtype, errcode);
}

static int drain_events_insn(struct ptxed_decoder *decoder, uint64_t *time,
			     int status, const struct ptxed_options *options)
{
	struct pt_insn_decoder *ptdec;
	int errcode;

	if (!decoder || !time || !options)
		return -pte_internal;

	ptdec = decoder->variant.insn;

	while (status & pts_event_pending) {
		struct pt_event event;
		uint64_t offset;

		offset = 0ull;
		if (options->print_offset) {
			errcode = pt_insn_get_offset(ptdec, &offset);
			if (errcode < 0)
				return errcode;
		}

		status = pt_insn_event(ptdec, &event, sizeof(event));
		if (status < 0)
			return status;

		*time = event.tsc;

		if (!options->quiet && !event.status_update)
			print_event(&event, options, offset);
	}

	return status;
}

static int drain_events_block(struct ptxed_decoder *decoder, uint64_t *time,
			      int status, const struct ptxed_options *options, uint16_t *ctxflags)
{
	struct pt_block_decoder *ptdec;
	int errcode;

	if (!decoder || !time || !options)
		return -pte_internal;

	ptdec = decoder->variant.block;

	while (status & pts_event_pending) {
		struct pt_event event;
		uint64_t offset;

		offset = 0ull;
		if (options->print_offset) {
			errcode = pt_blk_get_offset(ptdec, &offset);
			if (errcode < 0)
				return errcode;
		}

		status = pt_blk_event(ptdec, &event, sizeof(event));
		if (status < 0)
			return status;

		// GM
		if (event.type == ptev_disabled)
		{
			*ctxflags |= GM_LEFT_CONTEXT;
		}

		*time = event.tsc;
		// GM
		// if (!options->quiet && !event.status_update)
		// 	print_event(&event, options, offset);
	}

	return status;
}

static void decode_insn(struct ptxed_decoder *decoder,
			const struct ptxed_options *options,
			struct ptxed_stats *stats)
{
	struct pt_insn_decoder *ptdec;
	xed_state_t xed;
	uint64_t offset, sync, time;

	if (!decoder || !options) {
		printf("[internal error]\n");
		return;
	}

	xed_state_zero(&xed);

	ptdec = decoder->variant.insn;
	offset = 0ull;
	sync = 0ull;
	time = 0ull;

	for (;;) {
		struct pt_insn insn;
		int status;

		/* Initialize the IP - we use it for error reporting. */
		insn.ip = 0ull;
		do
		{
			status = pt_insn_sync_forward(ptdec);
		} while (status == -pte_eos);

		if (status < 0) {
			uint64_t new_sync;
			int errcode;

			if (status == -pte_eos)
				break;

			diagnose(decoder, insn.ip, "sync error", status);

			/* Let's see if we made any progress.  If we haven't,
			 * we likely never will.  Bail out.
			 *
			 * We intentionally report the error twice to indicate
			 * that we tried to re-sync.  Maybe it even changed.
			 */
			errcode = pt_insn_get_offset(ptdec, &new_sync);
			if (errcode < 0 || (new_sync <= sync))
				break;

			sync = new_sync;
			continue;
		}

		for (;;) {
			status = drain_events_insn(decoder, &time, status,
						   options);
			if (status < 0)
				break;

			if (status & pts_eos) {
				if (!(status & pts_ip_suppressed) &&
				    !options->quiet)
					printf("[end of trace]\n");

				status = -pte_eos;
				break;
			}

			if (options->print_offset || options->check) {
				int errcode;

				errcode = pt_insn_get_offset(ptdec, &offset);
				if (errcode < 0)
					break;
			}

			status = pt_insn_next(ptdec, &insn, sizeof(insn));
			if (status < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding the current instruction.
				 */
				if (insn.iclass != ptic_error) {
					if (!options->quiet)
						print_insn(&insn, &xed, options,
							   offset, time);
					if (stats)
						stats->insn += 1;

					if (options->check)
						check_insn(&insn, offset);
				}
				break;
			}

			if (!options->quiet)
				print_insn(&insn, &xed, options, offset, time);

			if (stats)
				stats->insn += 1;

			if (options->check)
				check_insn(&insn, offset);
		}

		/* We shouldn't break out of the loop without an error. */
		if (!status)
			status = -pte_internal;

		/* We're done when we reach the end of the trace stream. */
		if (status == -pte_eos)
			break;

		diagnose(decoder, insn.ip, "error",  status);
	}
}

static void print_block(struct ptxed_decoder *decoder,
			const struct pt_block *block,
			const struct ptxed_options *options,
			const struct ptxed_stats *stats,
			uint64_t offset, uint64_t time)
{
	xed_machine_mode_enum_t mode;
	xed_state_t xed;
	uint64_t ip;
	uint16_t ninsn;

	if (!block || !options) {
		printf("[internal error]\n");
		return;
	}

	if (options->track_blocks) {
		printf("[block");
		if (stats)
			printf(" %" PRIx64, stats->blocks);
		printf("]\n");
	}

	mode = translate_mode(block->mode);
	xed_state_init2(&xed, mode, XED_ADDRESS_WIDTH_INVALID);

	/* There's nothing to do for empty blocks. */
	ninsn = block->ninsn;
	if (!ninsn)
		return;

	ip = block->ip;
	for (;;) {
		struct pt_insn insn;
		xed_decoded_inst_t inst;
		xed_error_enum_t xederrcode;
		int errcode;

		// GM
		if (options->print_offset)
			printf("%016" PRIx64 "  ", offset);

		if (options->print_time)
			printf("%016" PRIx64 "  ", time);

		if (block->speculative)
			printf("? ");

		printf("%016" PRIx64, ip);

		errcode = block_fetch_insn(&insn, block, ip, decoder->iscache);
		if (errcode < 0) {
			printf(" [fetch error: %s]\n",
			       pt_errstr(pt_errcode(errcode)));
			break;
		}

		xed_decoded_inst_zero_set_mode(&inst, &xed);

		xederrcode = xed_decode(&inst, insn.raw, insn.size);
		if (xederrcode != XED_ERROR_NONE) {
			print_raw_insn(&insn);

			printf(" [xed decode error: (%u) %s]\n", xederrcode,
			       xed_error_enum_t2str(xederrcode));
			break;
		}

		// GM
		if (!options->dont_print_insn)
			xed_print_insn(&inst, insn.ip, options);

		printf("\n");

		ninsn -= 1;
		if (!ninsn)
			break;

		errcode = xed_next_ip(&ip, &inst, ip);
		if (errcode < 0) {
			diagnose(decoder, ip, "reconstruct error", errcode);
			break;
		}
	}

	/* Decode should have brought us to @block->end_ip. */
	if (ip != block->end_ip)
		diagnose(decoder, ip, "reconstruct error", -pte_nosync);
}

static void check_block(const struct pt_block *block,
			struct pt_image_section_cache *iscache,
			uint64_t offset)
{
	struct pt_insn insn;
	xed_decoded_inst_t inst;
	uint64_t ip;
	uint16_t ninsn;
	int errcode;

	if (!block) {
		printf("[internal error]\n");
		return;
	}

	/* There's nothing to check for an empty block. */
	ninsn = block->ninsn;
	if (!ninsn)
		return;

	if (block->isid <= 0)
		printf("[%" PRIx64 ", %" PRIx64 ": check error: "
		       "bad isid]\n", offset, block->ip);

	ip = block->ip;
	do {
		errcode = block_fetch_insn(&insn, block, ip, iscache);
		if (errcode < 0) {
			printf("[%" PRIx64 ", %" PRIx64 ": fetch error: %s]\n",
			       offset, ip, pt_errstr(pt_errcode(errcode)));
			return;
		}

		xed_decoded_inst_zero(&inst);
		check_insn_decode(&inst, &insn, offset);

		/* We need a valid instruction in order to do further checks.
		 *
		 * Invalid instructions have already been diagnosed.
		 */
		if (!xed_decoded_inst_valid(&inst))
			return;

		errcode = xed_next_ip(&ip, &inst, ip);
		if (errcode < 0) {
			printf("[%" PRIx64 ", %" PRIx64 ": error: %s]\n",
			       offset, ip, pt_errstr(pt_errcode(errcode)));
			return;
		}
	} while (--ninsn);

	/* We reached the end of the block.  Both @insn and @inst refer to the
	 * last instruction in @block.
	 *
	 * Check that we reached the end IP of the block.
	 */
	if (insn.ip != block->end_ip) {
		printf("[%" PRIx64 ", %" PRIx64 ": error: did not reach end: %"
		       PRIx64 "]\n", offset, insn.ip, block->end_ip);
	}

	/* Check the last instruction's classification, if available. */
	insn.iclass = block->iclass;
	if (insn.iclass)
		check_insn_iclass(xed_decoded_inst_inst(&inst), &insn, offset);
}

// GM
static int extract_target(char *target, char *buf)
{
	// Parse the last word of the buffer
	char *token = strrchr(buf, ' ')+1;

	if (token)
	{
		strcpy(target, token);
	}

	return 0;
}

// GM
static void print_cfg(struct ptxed_decoder *decoder,
								   const struct ptxed_options *options,
								   struct pt_block *block_prev,
								   struct pt_block *block,
								   uint16_t *ctxflags)
{
	xed_decoded_inst_t inst;
	xed_error_enum_t xederrcode;
	struct pt_insn insn;
	int errcode;
	int lcreport = 0;
	long unsigned int branchaddr;
	xed_machine_mode_enum_t mode;
	xed_state_t xed;

	// Skip blocks that do not match flags
	if (((block_prev->iclass == ptic_call
		|| block_prev->iclass == ptic_far_call)
		&& (*ctxflags & GM_RET_PENDING))
		|| ((block_prev->iclass == ptic_return
		|| block_prev->iclass == ptic_far_return)
		&& (*ctxflags & GM_CALL_PENDING))
		|| ((block_prev->iclass == ptic_jump
		|| block_prev->iclass == ptic_far_jump
		|| block_prev->iclass == ptic_cond_jump)
		&& ((*ctxflags & GM_RET_PENDING)
		|| (*ctxflags & GM_CALL_PENDING))))
	{
		return;
	}

	// Detect leaving context
	// Get previous instruction
	if (block_prev->ninsn)
	{
		// Handle jumps and calls
		if (block_prev->iclass == ptic_jump
			|| block_prev->iclass == ptic_cond_jump
			|| block_prev->iclass == ptic_far_jump
			|| block_prev->iclass == ptic_call
			|| block_prev->iclass == ptic_far_call)
		{
			
			if (block_prev->iclass == ptic_jump
				|| block_prev->iclass == ptic_cond_jump
				|| block_prev->iclass == ptic_call)
			{
				// Init xed components
				mode = translate_mode(block_prev->mode);
				xed_state_init2(&xed, mode, XED_ADDRESS_WIDTH_INVALID);
				

				// Decode last instruction
				errcode = block_fetch_insn(&insn, block_prev, block_prev->end_ip,
											decoder->iscache);
				if (errcode < 0) {
					printf(" [fetch error: %s]\n",
							pt_errstr(pt_errcode(errcode)));
					return;
				}
				xed_decoded_inst_zero_set_mode(&inst, &xed);
				xederrcode = xed_decode(&inst, insn.raw, insn.size);
				if (xederrcode != XED_ERROR_NONE) {
					print_raw_insn(&insn);

					printf(" [xed decode error: (%u) %s]\n", xederrcode,
							xed_error_enum_t2str(xederrcode));
					return;
				}
				// xed_print_insn(&inst, block_prev->end_ip, options);

				// Get branch target
				xed_next_ip(&branchaddr, &inst, block_prev->end_ip);
			}
			else
			{
				branchaddr = 0;
			}
			
			// Ignore conditional jumps not taken
			if ((*ctxflags & GM_LEFT_CONTEXT)
				|| !(block_prev->iclass == ptic_cond_jump
				&& branchaddr != block->ip))
			{
				if (*ctxflags & GM_LEFT_CONTEXT)
				{
					lcreport = 1;
					if (!options->quiet)
						printf("<");
				}
				else
				{
					if (!options->quiet)
						printf("|");
				}

				if ((block_prev->iclass == ptic_jump
					|| block_prev->iclass == ptic_cond_jump
					|| block_prev->iclass == ptic_far_jump)
					&& !options->quiet)
				{
					printf("JUMP  ");
				}
				else if ((block_prev->iclass == ptic_call
					|| block_prev->iclass == ptic_far_call)
					&& !options->quiet)
				{
					printf("CALL  ");
				}

				if (!options->quiet)
					printf("@ 0x%lx", block_prev->end_ip);

				if (branchaddr != 0 && !options->quiet)
						printf(" target: 0x%lx", branchaddr);

				if (!options->quiet)
					printf("\n");
			}
		}
		// Handle returns
		else if (block_prev->iclass == ptic_return
			|| block_prev->iclass == ptic_far_return)
		{
			if (*ctxflags & GM_LEFT_CONTEXT)
			{
				lcreport = 1;
				if (!options->quiet)
					printf("<");
			}
			else
			{
				if (!options->quiet)
					printf("|");
			}
			if (!options->quiet)
				printf("RET   @ 0x%lx\n", block_prev->end_ip);
		}
	}

	// Detect entry into context
	if (!block_prev->ninsn || (*ctxflags & GM_LEFT_CONTEXT))
	{
		// Detect non-branching context exits. This should not happen.
		if (!lcreport && block_prev->ninsn && !options->quiet)
		{
			printf("<EXIT  @ 0x%lx\n", block_prev->end_ip);
		}
		if (!options->quiet)
			printf(">ENTER @ 0x%lx\n", block->ip);
	}

	// Reset context flags
	*ctxflags &= ~GM_LEFT_CONTEXT;
	*ctxflags &= ~GM_RET_PENDING;
	*ctxflags &= ~GM_CALL_PENDING;

	// Detect calls and syscalls out
	if (block->iclass == ptic_call
		|| block->iclass == ptic_far_call)
	{
		*ctxflags |= GM_CALL_PENDING;
	}

	// To identify whether this returns outside context,
	// raise the RET_PENDING flag
	if (block->iclass == ptic_return
		|| block->iclass == ptic_far_return)
	{	
		*ctxflags |= GM_RET_PENDING;
	}
}

static uint64_t get_max_offset(pt_block_decoder *decoder)
{
	const pt_config *config = pt_blk_get_config(decoder);

	return config->end - config->begin;
}

static void decode_block(struct ptxed_decoder *decoder,
			 struct ptxed_options *options,
			 struct ptxed_stats *stats,
			 pid_t targetpid)
{
	struct pt_image_section_cache *iscache;
	struct pt_block_decoder *ptdec;
	uint64_t offset, offset_prev, offset_max, offset_pause,
				count, count_pause, sync, time;
	bool skip = false, lasttry = false;

	if (!decoder || !options) {
		printf("[internal error]\n");
		return;
	}

	iscache = decoder->iscache;
	ptdec = decoder->variant.block;
	offset = 0ull;
	offset_prev = 0ull;
	offset_max = get_max_offset(ptdec);
	offset_pause = 0ull;
	count = 0ull;
	sync = 0ull;
	time = 0ull;

	for (;;) {
		// GM
		uint16_t ctxflags = 0;
		struct pt_block block, prev_block;
		int status;

		/* Initialize IP and ninsn - we use it for error reporting. */
		block.ip = 0ull;
		block.ninsn = 0u;
		do
		{
			status = pt_blk_sync_forward(ptdec);
		} while (status == -pte_eos);
		
		if (status < 0) {
			uint64_t new_sync;
			int errcode;

			if (status == -pte_eos)
			{
				printf("[end of trace]\n");
				break;
			}

			diagnose_block(decoder, "sync error", status, &block);

			/* Let's see if we made any progress.  If we haven't,
			 * we likely never will.  Bail out.
			 *
			 * We intentionally report the error twice to indicate
			 * that we tried to re-sync.  Maybe it even changed.
			 */
			errcode = pt_blk_get_offset(ptdec, &new_sync);
			if (errcode < 0 || (new_sync <= sync))
				break;

			sync = new_sync;
			continue;
		}

		for (;;) {
			// Check whether target is still running
			bool istargetrunning = waitpid(targetpid, NULL, WNOHANG) == 0;

			pt_blk_get_offset(ptdec, &offset);

			status = drain_events_block(decoder, &time, status,
							options, &ctxflags);

			if (status < 0)
				break;
			if (status & pts_eos)
			{
				// Workaround for early-abort edge case
				if (!lasttry && !istargetrunning && !skip)
				{
					count--;
					lasttry = true;
				}
				else
				{
					lasttry = false;
				}

				// Check if target process is still running
				// If so, return to previous sync point and continue!
				if (istargetrunning || skip || lasttry)
				{
					// printf("SKIP\n");
					uint64_t syncoffset;
					offset_pause = offset_prev;

					// Synchronize to the last PSB
					pt_blk_get_sync_offset(ptdec, &syncoffset);
					pt_blk_sync_set(ptdec, syncoffset);
					// pt_blk_sync_forward(ptdec);

					// Update the offset variable
					pt_blk_get_offset(ptdec, &offset);

					int64_t repeat = offset_prev - offset;
					if (repeat < 0)
					{
						pt_blk_sync_backward(ptdec);
						pt_blk_get_offset(ptdec, &offset);
						repeat = offset_prev - offset;
					}
					
					skip = true;
					count_pause = count;
					count = 0;
					status = 0;
					continue;
				}

				// printf("OUT: 0x%lx 0x%lx 0x%lx, %lu %lu %d %d %d\n",
				// 	offset, offset_prev, offset_pause,
				// 	count, count_pause,
				// 	istargetrunning, skip, lasttry);

				if (ctxflags & GM_RET_PENDING)// && !options->quiet)
				{
					ctxflags ^= GM_RET_PENDING;
					printf("<RET   @ 0x%lx\n", block.end_ip);
				}
				else if (ctxflags & GM_CALL_PENDING && !options->quiet)
				{
					ctxflags ^= GM_CALL_PENDING;
					printf("<CALL  @ 0x%lx\n", block.end_ip);
				}

				if (!(status & pts_ip_suppressed) && !options->quiet)
				{
					printf("[end of trace]\n");
				}

				status = -pte_eos;
				break;
			}

			if (options->print_offset || options->check) {
				int errcode;

				errcode = pt_blk_get_offset(ptdec, &offset);
				if (errcode < 0)
					break;
			}

			// GM
			prev_block = block;
			status = pt_blk_next(ptdec, &block, sizeof(block));

			if (status < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding some instructions.
				 */
				if (block.ninsn) {
					if (stats) {
						stats->insn += block.ninsn;
						stats->blocks += 1;
					}

					if (!options->quiet)
						print_block(decoder, &block,
							    options, stats,
							    offset, time);

					if (options->check)
						check_block(&block, iscache,
							    offset);
				}
				break;
			}

			// GM
			// If we had to revert to the previous sync point,
			// some special handling is required to skip the
			// blocks already decoded
			// printf("0x%lx 0x%lx 0x%lx %lu %lu\n", offset, offset_prev, offset_pause, count, count_pause);

			if (offset_pause > 0)
			{
				// Once the decoder has caught up with its
				// previous position, stop skipping
				if (offset < offset_max && offset_prev <= offset)
				{
					skip = false;
					// offset_pause = 0;
				}
				
				// Skip the current block if skipping
				if (skip)
				{
					continue;
				}
				if (count < count_pause)
				{
					count++;
					continue;
				}
				else
				{
					count_pause = 0;
				}
			}

			if (offset < offset_max && offset != offset_prev)
			{
				count = 0;
			}

			if (offset < offset_max && offset_prev < offset)
			{
				offset_prev = offset;
			}

			if (stats) {
				stats->insn += block.ninsn;
				stats->blocks += 1;
			}

			// GM
			count++;
			print_cfg(decoder, options, &prev_block, &block,
						&ctxflags);

			// if (!options->quiet)
			// 	print_block(decoder, &block, options, stats,
			// 		    offset, time);

			if (options->check)
				check_block(&block, iscache, offset);
		}

		/* We shouldn't break out of the loop without an error. */
		if (!status)
			status = -pte_internal;

		/* We're done when we reach the end of the trace stream. */
		if (status == -pte_eos)
			break;

		// GM
		// diagnose_block(decoder, "error", status, &block);
	}
}

static void decode(struct ptxed_decoder *decoder,
		   struct ptxed_options *options,
		   struct ptxed_stats *stats,
		   pid_t targetpid)
{
	if (!decoder) {
		printf("[internal error]\n");
		return;
	}

	switch (decoder->type) {
	case pdt_insn_decoder:
		decode_insn(decoder, options, stats);
		break;

	case pdt_block_decoder:
		decode_block(decoder, options, stats, targetpid);
		break;
	}
}

static void print_stats(struct ptxed_stats *stats)
{
	if (!stats) {
		printf("[internal error]\n");
		return;
	}

	if (stats->flags & ptxed_stat_insn)
		printf("insn: %" PRIu64 ".\n", stats->insn);

	if (stats->flags & ptxed_stat_blocks)
		printf("blocks:\t%" PRIu64 ".\n", stats->blocks);
}

static int load_raw(struct pt_image_section_cache *iscache,
		    struct pt_image *image, char *filename, uint64_t base,
			const char *prog)
{
	int isid, errcode;

	isid = pt_iscache_add_file(iscache, filename, 0, UINT64_MAX, base);
	if (isid < 0) {
		fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
			prog, filename, base, pt_errstr(pt_errcode(isid)));
		return -1;
	}

	errcode = pt_image_add_cached(image, iscache, isid, NULL);
	if (errcode < 0) {
		fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
			prog, filename, base, pt_errstr(pt_errcode(errcode)));
		return -1;
	}

	return 0;
}
