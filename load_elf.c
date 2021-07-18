/*
 * Copyright (c) 2013-2020, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "lib/load_elf.h"
#include "lib/intel-pt.h"

#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

static int set_context64(FILE *file, const char *name, const char *prog,
						 Elf64_Ehdr *ehdr, struct gm_trace_context *context)
{
	Elf64_Shdr shdr, shsymtab, shsymstrtab, shstrtab;
	Elf64_Phdr phdr;
	Elf64_Dyn dyn;
	size_t count;
	int errcode;

	// Read section header strtab
	fseek(file, ehdr->e_shoff + ehdr->e_shstrndx*ehdr->e_shentsize, SEEK_SET);
	fread(&shstrtab, ehdr->e_shentsize, 1, file);
	char strtab[shstrtab.sh_size];
	fseek(file, shstrtab.sh_offset, SEEK_SET);
	fread(&strtab, shstrtab.sh_size, 1, file);

	// Find section headers
	fseek(file, ehdr->e_shoff, SEEK_SET);

	// Read symtab section header and symbol strtab
	int c = 0;
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		count = fread(&shdr, sizeof(shdr), 1, file);
		if (count != 1) {
			fprintf(stderr,
				"%s: warning: %s error reading section header: %s.\n",
				prog, name, strerror(errcode));
			return -pte_bad_config;
		}

		if (shdr.sh_type == SHT_SYMTAB)
		{
			shsymtab = shdr;
		}
		else if (shdr.sh_type == SHT_STRTAB
			&& strcmp(strtab+shdr.sh_name, ".strtab") == 0)
		{
			shsymstrtab = shdr;
		}

		if (shdr.sh_type && shsymstrtab.sh_type)
		{
			break;
		}
	}

	if (!shsymstrtab.sh_type)
	{
		printf("Symbol not found!\n");
		exit(EXIT_FAILURE);
	}

	// Read symbol strtab
	char symstrtab[shsymstrtab.sh_size];
	fseek(file, shsymstrtab.sh_offset, SEEK_SET);
	fread(&symstrtab, shsymstrtab.sh_size, 1, file);

	// Read symtab
	int symtab_num = shsymtab.sh_size/sizeof(Elf64_Sym);
	Elf64_Sym symtab[symtab_num];
	fseek(file, shsymtab.sh_offset, SEEK_SET);
	fread(&symtab, shsymtab.sh_size, 1, file);

	// Find the symbol matching the requested context
	for (int i = 0; i < symtab_num; i++)
	{
		if ((int)symtab[i].st_name != 0
			&& strcmp(symstrtab+symtab[i].st_name, context->function) == 0)
		{
			context->start = symtab[i].st_value;
			context->end = context->start + symtab[i].st_size;
			break;
		}
	}

	return 0;
}

static int set_context32(FILE *file, const char *name, const char *prog,
						 Elf32_Ehdr *ehdr, struct gm_trace_context *context)
{
	Elf32_Shdr shdr, shsymtab, shsymstrtab, shstrtab;
	Elf32_Phdr phdr;
	Elf32_Dyn dyn;
	size_t count;
	int errcode;

	// Read section header strtab
	fseek(file, ehdr->e_shoff + ehdr->e_shstrndx*ehdr->e_shentsize, SEEK_SET);
	fread(&shstrtab, ehdr->e_shentsize, 1, file);
	char strtab[shstrtab.sh_size];
	fseek(file, shstrtab.sh_offset, SEEK_SET);
	fread(&strtab, shstrtab.sh_size, 1, file);

	// Find section headers
	fseek(file, ehdr->e_shoff, SEEK_SET);

	// Read symtab section header and symbol strtab
	int c = 0;
	for (int i = 0; i < ehdr->e_shnum; i++)
	{
		count = fread(&shdr, sizeof(shdr), 1, file);
		if (count != 1) {
			fprintf(stderr,
				"%s: warning: %s error reading section header: %s.\n",
				prog, name, strerror(errcode));
			return -pte_bad_config;
		}

		if (shdr.sh_type == SHT_SYMTAB)
		{
			shsymtab = shdr;
		}
		else if (shdr.sh_type == SHT_STRTAB
			&& strcmp(strtab+shdr.sh_name, ".strtab") == 0)
		{
			shsymstrtab = shdr;
		}

		if (shdr.sh_type && shsymstrtab.sh_type)
		{
			break;
		}
	}

	if (!shsymstrtab.sh_type)
	{
		printf("Symbol not found!\n");
		exit(EXIT_FAILURE);
	}

	// Read symbol strtab
	char symstrtab[shsymstrtab.sh_size];
	fseek(file, shsymstrtab.sh_offset, SEEK_SET);
	fread(&symstrtab, shsymstrtab.sh_size, 1, file);

	// Read symtab
	int symtab_num = shsymtab.sh_size/sizeof(Elf32_Sym);
	Elf32_Sym symtab[symtab_num];
	fseek(file, shsymtab.sh_offset, SEEK_SET);
	fread(&symtab, shsymtab.sh_size, 1, file);

	// Find the symbol matching the requested context
	for (int i = 0; i < symtab_num; i++)
	{
		if ((int)symtab[i].st_name != 0
			&& strcmp(symstrtab+symtab[i].st_name, context->function) == 0)
		{
			context->start = symtab[i].st_value;
			context->end = context->start + symtab[i].st_size;
			break;
		}
	}

	return 0;
}

static int elf_load_offset32(FILE *file, uint64_t base, uint64_t *offset,
		      const char *name, const char *prog,
			  struct gm_trace_context *context)
{
	Elf32_Ehdr ehdr;
	Elf32_Half pidx;
	size_t count;
	int errcode;

	errcode = fseek(file, 0, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	count = fread(&ehdr, sizeof(ehdr), 1, file);
	if (count != 1) {
		fprintf(stderr,
			"%s: warning: %s error reading ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	errcode = fseek(file, (long) ehdr.e_phoff, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking program header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	/* Determine the load offset. */
	if (!base)
		*offset = 0;
	else {
		uint32_t minaddr;

		minaddr = UINT32_MAX;

		for (pidx = 0; pidx < ehdr.e_phnum; ++pidx) {
			Elf32_Phdr phdr;

			count = fread(&phdr, sizeof(phdr), 1, file);
			if (count != 1) {
				fprintf(stderr,
					"%s: warning: %s error reading "
					"phdr %u: %s.\n",
					prog, name, pidx, strerror(errno));
				return -pte_bad_config;
			}

			if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
				continue;

			if (phdr.p_vaddr < minaddr)
				minaddr = phdr.p_vaddr;
		}

		*offset = base - minaddr;
	}

	if (context && context->function != NULL)
	{
		context->base = *offset;
		set_context32(file, name, prog, &ehdr, context);
	}

	return 0;
}

static int elf_load_offset64(FILE *file, uint64_t base, uint64_t *offset,
		      const char *name, const char *prog,
			  struct gm_trace_context *context)
{
	Elf64_Ehdr ehdr;
	Elf64_Half pidx;
	size_t count;
	int errcode;

	errcode = fseek(file, 0, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	count = fread(&ehdr, sizeof(ehdr), 1, file);
	if (count != 1) {
		fprintf(stderr,
			"%s: warning: %s error reading ELF header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	if (LONG_MAX < ehdr.e_phoff) {
		fprintf(stderr, "%s: warning: %s ELF header too big.\n",
			prog, name);
		return -pte_bad_config;
	}

	errcode = fseek(file, (long) ehdr.e_phoff, SEEK_SET);
	if (errcode) {
		fprintf(stderr,
			"%s: warning: %s error seeking program header: %s.\n",
			prog, name, strerror(errno));
		return -pte_bad_config;
	}

	/* Determine the load offset. */
	if (!base)
		*offset = 0;
	else {
		uint64_t minaddr;

		minaddr = UINT64_MAX;

		for (pidx = 0; pidx < ehdr.e_phnum; ++pidx) {
			Elf64_Phdr phdr;

			count = fread(&phdr, sizeof(phdr), 1, file);
			if (count != 1) {
				fprintf(stderr,
					"%s: warning: %s error reading "
					"phdr %u: %s.\n",
					prog, name, pidx, strerror(errno));
				return -pte_bad_config;
			}

			if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
				continue;

			if (phdr.p_vaddr < minaddr)
				minaddr = phdr.p_vaddr;
		}

		*offset = base - minaddr;
	}

	if (context)
	{
		context->base = *offset;

		if (context->function != NULL)
		{
			set_context64(file, name, prog, &ehdr, context);
		}
	}

	return 0;
}

int elf_load_offset(const char *name, uint64_t base,
			  uint64_t *offset, const char *prog,
			  struct gm_trace_context *context)
{
	uint8_t e_ident[EI_NIDENT];
	FILE *file;
	size_t count;
	int errcode, idx;

	file = fopen(name, "rb");
	if (!file) {
		fprintf(stderr, "%s: warning: failed to open %s: %s.\n", prog,
			name, strerror(errno));
		return -pte_bad_config;
	}

	count = fread(e_ident, sizeof(e_ident), 1, file);
	if (count != 1) {
		fprintf(stderr,
			"%s: warning: %s failed to read file header: %s.\n",
			prog, name, strerror(errno));

		errcode = -pte_bad_config;
		goto out;
	}

	for (idx = 0; idx < SELFMAG; ++idx) {
		if (e_ident[idx] != ELFMAG[idx]) {
			fprintf(stderr,
				"%s: warning: ignoring %s: not an ELF file.\n",
				prog, name);

			errcode = -pte_bad_config;
			goto out;
		}
	}

	switch (e_ident[EI_CLASS]) {
	default:
		fprintf(stderr, "%s: unsupported ELF class: %d\n",
			prog, e_ident[EI_CLASS]);
		errcode =  -pte_bad_config;
		break;

	case ELFCLASS32:
		errcode = elf_load_offset32(file, base, offset, name, prog, context);
		break;

	case ELFCLASS64:
		errcode = elf_load_offset64(file, base, offset, name, prog, context);
		break;
	}

out:
	fclose(file);
	return errcode;
}
