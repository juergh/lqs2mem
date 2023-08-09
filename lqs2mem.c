/*
 * lqs2mem.c - convert libvirt save files or qemu savevm dumps into raw
 *             physical memory images
 *
 * Copyright (C) 2016 Hewlett Packard Enterprise Development, L.P.
 * Copyright (C) 2011-2013 Raytheon Pikewerks Corporation. All rights reserved.
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P. 
 *
 * Authors: Andrew Tappert <andrew@pikewerks.com>
 *          Juerg Haefliger <juerg.haefliger@hpe.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * TODO:
 * - handle compressed libvirt-qemu-save formats
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define NAME "lqs2mem"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohll(x) (((x) << 56 & 0xFF00000000000000ULL) | \
                   ((x) << 40 & 0x00FF000000000000ULL) | \
                   ((x) << 24 & 0x0000FF0000000000ULL) | \
                   ((x) << 8  & 0x000000FF00000000ULL) | \
                   ((x) >> 8  & 0x00000000FF000000ULL) | \
                   ((x) >> 24 & 0x0000000000FF0000ULL) | \
                   ((x) >> 40 & 0x000000000000FF00ULL) | \
                   ((x) >> 56 & 0x00000000000000FFULL) )
#else
#define ntohll(x) (x)
#endif

/*
 * libvirt defines and structs (v1.3.4)
 *
 * libvirt's QEMU save file format is:
 *   - Header (virQEMUSaveHeader)
 *   - Domain XML config data
 *   - QEMU savevm data
 */

/* From src/qemu/qemu_driver.c */

#define QEMU_SAVE_MAGIC   "LibvirtQemudSave"
#define QEMU_SAVE_PARTIAL "LibvirtQemudPart"
#define QEMU_SAVE_VERSION 2

typedef struct _virQEMUSaveHeader virQEMUSaveHeader;
typedef virQEMUSaveHeader *virQEMUSaveHeaderPtr;
struct _virQEMUSaveHeader {
    char magic[sizeof(QEMU_SAVE_MAGIC)-1];
    uint32_t version;
    uint32_t xml_len;
    uint32_t was_running;
    uint32_t compressed;
    uint32_t unused[15];
};

/*
 * QEMU defines and structs (v2.6.0)
 *
 * The conversion of a QEMU savevm file into a raw physical memory image is
 * based on function qemu_loadvm_state in migartion/savevm.c. Each section has
 * a different handler function; save/load functions are scattered
 * throughout the QEMU code base. Comments in our section handler functions
 * reference the corresponding QEMU savevm/vmstate load functions.
 */

/* From include/migration/migration.h */

#define QEMU_VM_FILE_MAGIC           0x5145564d
#define QEMU_VM_FILE_VERSION_COMPAT  0x00000002
#define QEMU_VM_FILE_VERSION         0x00000003
#define QEMU_VM_EOF                  0x00
#define QEMU_VM_SECTION_START        0x01
#define QEMU_VM_SECTION_PART         0x02
#define QEMU_VM_SECTION_END          0x03
#define QEMU_VM_SECTION_FULL         0x04
#define QEMU_VM_SUBSECTION           0x05
#define QEMU_VM_VMDESCRIPTION        0x06
#define QEMU_VM_CONFIGURATION        0x07
#define QEMU_VM_COMMAND              0x08
#define QEMU_VM_SECTION_FOOTER       0x7e

const char *section_type_name[] = {
	"EOF",
	"SECTION_START",
	"SECTION_PART",
	"SECTION_END",
	"SECTION_FULL",
	"SUBSECTION",
	"VMDESCRIPTION",
	"CONFIGURATION",
	"COMMAND",
	"SECTION_FOOTER",
};

/* From migration/ram.c */

#define RAM_SAVE_FLAG_FULL      0x01 /* Obsolete, not used anymore */
#define RAM_SAVE_FLAG_COMPRESS  0x02
#define RAM_SAVE_FLAG_MEM_SIZE  0x04
#define RAM_SAVE_FLAG_PAGE      0x08
#define RAM_SAVE_FLAG_EOS       0x10
#define RAM_SAVE_FLAG_CONTINUE  0x20
#define RAM_SAVE_FLAG_XBZRLE    0x40
/* 0x80 is reserved in migration.h start with 0x100 next */
#define RAM_SAVE_FLAG_COMPRESS_PAGE    0x100

/****************************************************************************/

#define DEFAULT         (1 << 0)
#define VERBOSE         (1 << 1)
#define SECTION_INFO    (1 << 2)
#define SECTION_DETAILS (1 << 3)
#define SECTION_DATA    (1 << 4)
#define READ_DETAILS    (1 << 5)

int debug = DEFAULT;
#define DEBUG(d, ...) { if (debug & d) printf(__VA_ARGS__); }

uint64_t section_size = 0;
uint64_t file_size = 0;

struct section_info {
	uint32_t id;
	uint32_t version;
	char *idstr;
	struct section_info *next;
};

size_t _fread(void *ptr, size_t size, size_t nmemb, FILE *stream, char *desc)
{
	size_t num_membs;
	size_t num_bytes, i;

	DEBUG(READ_DETAILS, "%016lx   %4lx   ", ftell(stream),
	      (uint64_t)(size * nmemb));

	num_membs = fread(ptr, size, nmemb, stream);
	num_bytes = num_membs * size;
	for (i = 0; i < 16; i++) {
		if (i < num_bytes) {
			DEBUG(READ_DETAILS, "%02x ",
			      (unsigned char)((unsigned char*)ptr)[i]);
		} else {
			DEBUG(READ_DETAILS, "   ");
		}
	}
	DEBUG(READ_DETAILS, "  # %s\n", desc);

	return num_membs;
}

/* From migration/qemu-file.c */

void qemu_file_skip(FILE *f, int size)
{
	fseek(f, size, SEEK_CUR);
}

int qemu_peek_byte(FILE *f, int offset)
{
	int val;

	fseek(f, offset, SEEK_CUR);
	fread(&val, 1, 1, f);
	fseek(f, -(offset + 1), SEEK_CUR);
	return val;
}

int qemu_get_byte(FILE *f)
{
	int result;

	result = qemu_peek_byte(f, 0);
	qemu_file_skip(f, 1);
	return result;
}

unsigned int qemu_get_be32(FILE *f)
{
	unsigned int v;

	v = (unsigned int)qemu_get_byte(f) << 24;
	v |= qemu_get_byte(f) << 16;
	v |= qemu_get_byte(f) << 8;
	v |= qemu_get_byte(f);
	return v;
}

uint64_t qemu_get_be64(FILE *f)
{
	uint64_t v;

	v = (uint64_t)qemu_get_be32(f) << 32;
	v |= qemu_get_be32(f);
	return v;
}

int libvirt_check(FILE *f)
{
	virQEMUSaveHeader hdr;

	DEBUG(VERBOSE, "Checking for Libvirt-QEMU-save magic...\n");

	if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
		printf("Failed to read Libvirt-QEMU-save header: %s\n",
		       strerror(errno));
		rewind(f);
		goto out;
	}

	if (memcmp(hdr.magic, QEMU_SAVE_MAGIC, sizeof(hdr.magic))) {
		DEBUG(VERBOSE, "Invalid Libvirt-QEMU-save magic\n");
		rewind(f);
		goto out;
	}
	DEBUG(VERBOSE, "Found Libvirt-QEMU-save magic\n");

	DEBUG(VERBOSE, "Libvirt-QEMU-save version = %d\n", hdr.version);
	if (hdr.version != QEMU_SAVE_VERSION) {
		printf("Unsupported Libvirt-QEMU-save version\n");
		return -EINVAL;
	}

	/* Skip past the libvirt XML config to get to the QEMU savevm data */
	if (fseek(f, sizeof(hdr) + hdr.xml_len, SEEK_SET)) {
		printf("Failed seek to QEMU-savevm start: %s\n",
		       strerror(errno));
		return -EINVAL;
	}

out:
	return 0;
}

int qemu_check(FILE *f)
{
	uint32_t v;

	DEBUG(VERBOSE, "Checking for QEMU-savevm magic...\n");

	v = qemu_get_be32(f);
	DEBUG(VERBOSE, "QEMU-savevm magic = %08x\n", v);
	if (v != QEMU_VM_FILE_MAGIC) {
		DEBUG(VERBOSE, "Invalid QEMU-savevm magic\n");
		return -EINVAL;
	}

	v = qemu_get_be32(f);
	DEBUG(VERBOSE, "QEMU-savevm version = %u\n", v);
	if (v != QEMU_VM_FILE_VERSION) {
		printf("Unsupported QEMU-savevm version\n");
		return -EINVAL;
	}

	return 0;
}

#define BLK_MIG_FLAG_EOS (0x02)
int block_load(FILE *f)
{
	uint64_t x;

	/*
	 * A more complete implementation could be based on qemu-kvm's
	 * block-migration.c, function block_load.  We don't really attempt to
	 * support block sections here.  We just know enough to skip past an
	 * empty one.
	 */

	x = qemu_get_be64(f);

	DEBUG(SECTION_DETAILS, "block: flags    : 0x%016lx\n", x);

	if (x != BLK_MIG_FLAG_EOS) {
		printf("Unsupported non-empty 'block' section\n");
		return -1;
	}


	return 0;
}

// XXX: Assume 4k pages
#define PAGE_SIZE 4096
#define PAGE_MASK 0xfffffffffffff000

int mem_page_write(FILE *f, uint64_t addr, uint8_t *page)
{
	/* Account for the 512 MB 'hole' from 3.5 GB to 4 GB for the memory
	 * mapped PCI devices */
	if (addr >= 0xe0000000) {
		addr += 0x20000000;
	}

	if (fseek(f, addr, SEEK_SET)) {
		printf("Failed to seek to address 0x%016llx in output file\n",
				(unsigned long long) addr);
		return -1;
	}

	if (fwrite(page, PAGE_SIZE, 1, f) != 1) {
		printf("Failed to write page at address 0x%016llx in output "
		       "file\n", (unsigned long long) addr);
		return -1;
	}

	return 0;
}

int mem_page_fill(FILE *f, uint64_t addr, uint8_t byte)
{
	uint8_t page[PAGE_SIZE];

	memset(page, byte, PAGE_SIZE);
	return mem_page_write(f, addr, page);
}

/*
 * Based on qemu-kvm function of same name in arch_init.c
 */
int ram_load(FILE *infp, FILE *outfp, char *section_name, int version_id)
{
	static int write_to_file = 0;
	uint64_t addr, flags;
	uint64_t total_ram_bytes;
	uint8_t idstr_len;
	char idstr[256];
	uint64_t length;
	int kb, mb;
	uint8_t byte;
	uint8_t page[PAGE_SIZE];
	uint64_t offset;

	if (version_id != 4) {
		printf("Unsupported 'ram' section version %d\n", version_id);
		return -1;
	}

	do {
		addr = qemu_get_be64(infp);
		flags = addr & ~PAGE_MASK;
		addr &= PAGE_MASK;

		DEBUG(SECTION_DETAILS, "ram: flags      : 0x%016lx\n", flags);
		DEBUG(SECTION_DETAILS, "ram: addr       : 0x%016lx\n", addr);

		if (flags & RAM_SAVE_FLAG_MEM_SIZE) {
			total_ram_bytes = addr;

			DEBUG(SECTION_DATA, "ram: total_size : %llu "
			      "(%llu MB)\n", (unsigned long long) addr,
			      (unsigned long long) addr / (1<<20));

			while (total_ram_bytes) {

				idstr_len = qemu_get_byte(infp);

				if (_fread(idstr, idstr_len, 1, infp,
					   "idstr (ram)") != 1) {
					printf("Failed to read idstr\n");
					return -1;
				}
				idstr[idstr_len] = '\0';

				length = qemu_get_be64(infp);
				kb = (length >> 10) > 0 ? length >> 10 : 0;
				mb = (length >> 20) > 0 ? length >> 20 : 0;
				DEBUG(DEFAULT, "section = %-32s size = %5llu "
				      "[%s] %12llu [bytes]\n", idstr,
				      (unsigned long long)(mb > 0 ? mb :
							   kb > 0 ? kb :
							   length),
				      mb > 0 ? "MB" : kb > 0 ? "KB" : "bytes",
				      (unsigned long long)length);

				if (section_name &&
				    !strcmp(idstr, section_name)) {
					section_size = length;
				}

				total_ram_bytes -= length;
			}
		}

		if ((flags & RAM_SAVE_FLAG_COMPRESS) ||
		    (flags & RAM_SAVE_FLAG_PAGE)) {

			if (!(flags & RAM_SAVE_FLAG_CONTINUE)) {

				idstr_len = qemu_get_byte(infp);

				if (_fread(idstr, idstr_len, 1, infp,
					   "idstr (ram)") != 1) {
					printf("Failed to read idstr\n");
					return -1;
				}
				idstr[idstr_len] = '\0';

				DEBUG(SECTION_DATA, "ram: idstr      : %s\n",
				      idstr);

				if (section_name &&
				    !strcmp(idstr, section_name)) {
					write_to_file = 1;
				} else {
					write_to_file = 0;
				}
			}

			if (flags & RAM_SAVE_FLAG_COMPRESS) {

				offset = ftell(infp);

				byte = qemu_get_byte(infp);

				DEBUG(SECTION_DATA, "ram: fill_byte  : 0x%02x "
				      "(read from file position 0x%016llx)\n",
				      byte, (unsigned long long)offset);

				if (write_to_file) {
					DEBUG(SECTION_DATA, "ram: Writing "
					      "page at address 0x%016llx "
					      "(fill byte = 0x%02x)\n",
					      (unsigned long long) addr, byte);
					mem_page_fill(outfp, addr, byte);
					file_size += PAGE_SIZE;
				}
			}

			if (flags & RAM_SAVE_FLAG_PAGE) {

				offset = ftell(infp);

				if (_fread(page, PAGE_SIZE, 1, infp,
					   "data (ram)") != 1) {
					printf("Failed to read page\n");
					return -1;
				}

				DEBUG(SECTION_DATA, "ram: page[0]    : 0x%02x "
				      "(read from file position 0x%016llx)\n",
				      page[0], (unsigned long long)offset);

				if (write_to_file) {
					DEBUG(SECTION_DATA, "ram: Writing "
					      "page at address 0x%016llx\n",
					      (unsigned long long) addr);
					mem_page_write(outfp, addr, page);
					file_size += PAGE_SIZE;
				}
			}
		}

	} while (!(flags & RAM_SAVE_FLAG_EOS));

	return 0;
}

int section_add_info(struct section_info **sections, uint32_t id, char *idstr,
		     uint32_t version)
{
	struct section_info *secinfo = malloc(sizeof(struct section_info));

	if (!secinfo) {
		printf("Failed to allocate memory for new section info "
		       "struct\n");
		return -1;
	}
	secinfo->id = id;
	secinfo->version = version;
	secinfo->idstr = strdup(idstr);
	if (!secinfo->idstr) {
		printf("Failed to duplicate section name\n");
		return -1;
	}
	secinfo->next = *sections;
	*sections = secinfo;

	return 0;
}

struct section_info *section_get_info(struct section_info *sections,
				      uint32_t id)
{
	struct section_info *secinfo = sections;

	while (secinfo) {
		if (secinfo->id == id) {
			break;
		}
		secinfo = secinfo->next;
	}
	return secinfo;
}

int section_handle(FILE *infp, FILE *outfp, char *section_name,
		   struct section_info *sections, uint32_t id)
{
	struct section_info *secinfo;

	secinfo = section_get_info(sections, id);
	if (!secinfo) {
		printf("No matching section with section_id = %d\n", id);
		return -1;
	}

	if (!strcmp(secinfo->idstr, "block")) {
		if (block_load(infp)) {
			return -1;
		}
	} else if (!strcmp(secinfo->idstr, "ram")) {
		if (ram_load(infp, outfp, section_name, secinfo->version)) {
			return -1;
		}
	} else {
		printf("Unsupported section: '%s'\n", secinfo->idstr);
		return -1;
	}

	return 0;
}

void usage(void)
{
	printf("Usage: %s [-d MASK] -l INFILE\n"
	       "       %s [-d MASK] -w SECTION INFILE OUTFILE\n\n", NAME,
	       NAME);
	printf("List available sections in INFILE or extract SECTION from "
	       "INFILE and write it\nto OUTFILE\n\n");
	printf("Options:\n");
	printf("  -d MASK     enable debug output\n");
	printf("  -l          list available sections in INFILE\n");
	printf("  -w SECTION  extract SECTION from INFILE and write it to "
	       "OUTFILE\n\n");
	printf("Examples:\n");
	printf("  %s -l instance-00000d93.save\n", NAME);
	printf("  %s -w pc.ram instance-00000d93.save instance-00000d93.ram\n",
	       NAME);
}

int main(int argc, char *argv[])
{
	int opt;
	int list = 0;
	FILE *infp, *outfp = NULL;
	char *section_name = NULL;
	int section_count = 0;
	struct section_info *sections = NULL;
	struct section_info *secinfo;
	uint64_t offset;
	uint8_t section_type;
	uint32_t section_id;
	uint32_t footer_section_id;
	uint8_t idstr_len;
	char idstr[256];
	uint32_t instance_id;
	uint32_t version_id;
	int done;
	uint32_t name_len, i;

	while (1) {
		opt = getopt(argc, argv, "d:lw:");
		if (opt < 0) {
			break;
		}
		switch (opt) {
		case 'd':
			debug = atoi(optarg);
			break;
		case 'l':
			list = 1;
			break;
		case 'w':
			section_name = optarg;
			break;
		default:
			usage();
			return -1;
		}
	}

	if ((list && section_name) ||
	    (!list && !section_name) ||
	    (list && (argc - optind) != 1) ||
	    (section_name && (argc - optind) != 2)) {
		usage();
		return -1;
	}

	infp = fopen(argv[optind], "r");
	if (!infp) {
		printf("Failed to open %s: %s\n", argv[optind],
		       strerror(errno));
		return -1;
	}

	if (section_name) {
		outfp = fopen(argv[optind + 1], "wx");
		if (!outfp) {
			printf("Failed to open %s: %s\n", argv[optind + 1],
			       strerror(errno));
			return -1;
		}
	}

	DEBUG(READ_DETAILS, "%-16s   %-4s   %-47s   %s\n", "Read offset",
	      "Size", "Data[0:15]", "Description");
	DEBUG(READ_DETAILS, "--------------------------------------------");
	DEBUG(READ_DETAILS, "-------------------------------------------\n");

	/* Check for libvirt-qemu-save and/or qemu-savevm header */
	if (libvirt_check(infp) < 0 || qemu_check(infp) < 0) {
		printf("Unrecogized file format\n");
		return -1;
	}

	done = 0;
	while (!done) {
		offset = ftell(infp);

		section_type = qemu_get_byte(infp);

		DEBUG(SECTION_INFO, "\nSection %d\n", section_count);
		DEBUG(SECTION_INFO, "offset          : 0x%016llx\n",
		      (unsigned long long) offset);
		DEBUG(SECTION_INFO, "section_type    : %d (%s)\n", section_type,
		      section_type_name[section_type]);

		if (section_type == QEMU_VM_EOF) {
			break;
		}

		if (section_type == QEMU_VM_SECTION_START ||
		    section_type == QEMU_VM_SECTION_FULL) {

			/* Read the section info/header */

			section_id = qemu_get_be32(infp);

			idstr_len = qemu_get_byte(infp);

			if (_fread(idstr, idstr_len, 1, infp, "idstr") != 1) {
				printf("Failed to read idstr\n");
				return -1;
			}
			idstr[idstr_len] = '\0';

			instance_id = qemu_get_be32(infp);
			version_id = qemu_get_be32(infp);

			DEBUG(SECTION_INFO, "section_id      : %u\n",
			      section_id);
			DEBUG(SECTION_INFO, "idstr           : %s\n",
			      idstr);
			DEBUG(SECTION_INFO, "instance_id     : 0x%08x\n",
			      instance_id);
			DEBUG(SECTION_INFO, "version         : %u\n",
			      version_id);

			/* Add the section info to our section list. We need
			 * this to be able to process sections of type
			 *  QEMU_VM_SECTION_PART and QEMU_VM_SECTION_END */
			if (section_add_info(&sections, section_id, idstr,
					     version_id)) {
				return -1;
			}

		} else if (section_type == QEMU_VM_SECTION_PART ||
			   section_type == QEMU_VM_SECTION_END) {

			/* Read the section info/header */

			section_id = qemu_get_be32(infp);

			/* Find the section info in our list so we can print
			* its name */
			secinfo = section_get_info(sections, section_id);
			DEBUG(SECTION_INFO, "section_id      : %u (%s)\n",
			      section_id, secinfo ? secinfo->idstr : "NULL");

		} else if (section_type == QEMU_VM_CONFIGURATION) {
			name_len = qemu_get_be32(infp);
			for (i = 0; i < name_len; i++) {
				qemu_get_byte(infp);
			}
			continue;
		} else if (section_type == QEMU_VM_SECTION_FOOTER) {
			footer_section_id = qemu_get_be32(infp);
			if (footer_section_id != section_id) {
				printf("Incorrect section footer: %x != %x\n", footer_section_id, section_id);
				return -1;
			}
			continue;
		} else {
			printf("Invalid section type: %d\n", section_type);
			return -1;
		}

		/* Handle the section */
		if (section_handle(infp, outfp, section_name, sections,
				   section_id) < 0) {
			return 1;
		}

		/* We're only interested in (and we only support) RAM sections
		 * so short-cycle the processing of the file if we're done with
		 * them */
		if (section_type == QEMU_VM_SECTION_END) {
			secinfo = section_get_info(sections, section_id);
			if (secinfo && !strcmp(secinfo->idstr, "ram")) {
				done = 1;
			}
		}

		section_count++;
	}

	if (section_name) {
		if (file_size != section_size) {
			printf("Error: Wrote %llu bytes from section '%s' to "
			       "file %s (expected %llu bytes)\n",
			       (unsigned long long)file_size, section_name,
			       argv[optind + 1],
			       (unsigned long long)section_size);
			return -1;
		} else {
			printf("Wrote %llu bytes from section '%s' to file "
			       "%s\n", (unsigned long long)file_size,
			       section_name, argv[optind + 1]);
		}
	}

	return 0;
}
