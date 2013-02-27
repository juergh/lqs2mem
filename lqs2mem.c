/*
 * lqs2mem.c - convert libvirt save files or qemu savevm dumps into raw
 *             physical memory images
 *
 * Copyright (C) 2011-2013 Raytheon Pikewerks Corporation. All rights reserved.
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P. 
 *
 * Authors: Andrew Tappert <andrew@pikewerks.com>
 *          Juerg Haefliger <juerg.haefliger@hp.com>
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
 * The following come from libvirt's src/qemu/qemu_driver.c (v0.9.0).
 * After the qemud_save_header comes libvirt xml config, then QEMU savevm data
 * (see below).
 */

#define QEMUD_SAVE_MAGIC "LibvirtQemudSave"
#define QEMUD_SAVE_VERSION 2

enum qemud_save_formats {
    QEMUD_SAVE_FORMAT_RAW = 0,
    QEMUD_SAVE_FORMAT_GZIP = 1,
    QEMUD_SAVE_FORMAT_BZIP2 = 2,
    QEMUD_SAVE_FORMAT_XZ = 3,
    QEMUD_SAVE_FORMAT_LZOP = 4,
    QEMUD_SAVE_FORMAT_LAST
};

struct qemud_save_header {
    char magic[sizeof(QEMUD_SAVE_MAGIC)-1];
    int version;
    int xml_len;
    int was_running;
    int compressed;
    int unused[15];
};

/*
 * The following come from qemu-kvm's savevm.c (v0.14.0).  The logic
 * for conversion of a QEMU savevm file into a raw physical memory image is
 * based on function qemu_loadvm_state in same qemu-kvm file.  Each kind of
 * section has a different handler function; save/load functions are scattered
 * through the QEMU code base.  Comments in our section handler functions
 * reference the corresponding QEMU savevm/vmstate load function.
 */

#define QEMU_VM_FILE_MAGIC           0x5145564d
#define QEMU_VM_FILE_VERSION_COMPAT  0x00000002
#define QEMU_VM_FILE_VERSION         0x00000003
#define QEMU_VM_EOF                  0x00
#define QEMU_VM_SECTION_START        0x01
#define QEMU_VM_SECTION_PART         0x02
#define QEMU_VM_SECTION_END          0x03
#define QEMU_VM_SECTION_FULL         0x04
#define QEMU_VM_SUBSECTION           0x05

/* From qemu arch-init.c */

#define RAM_SAVE_FLAG_FULL      0x01 /* Obsolete, not used anymore */
#define RAM_SAVE_FLAG_COMPRESS  0x02
#define RAM_SAVE_FLAG_MEM_SIZE  0x04
#define RAM_SAVE_FLAG_PAGE      0x08
#define RAM_SAVE_FLAG_EOS       0x10
#define RAM_SAVE_FLAG_CONTINUE  0x20

/****************************************************************************/

#define DEBUG(d,...) { if (debug >= d) printf(__VA_ARGS__); }
static int debug = 0;

struct section_info {
	uint32_t id;
	uint32_t version;
	char *idstr;
	struct section_info *next;
};

int get_byte(FILE *f, uint8_t *x)
{
	if (fread(x, sizeof(*x), 1, f) != 1) {
		return -1;
	}
	return 0;
}

int get_be32(FILE *f, uint32_t *x)
{
	if (fread(x, sizeof(*x), 1, f) != 1) {
		return -1;
	}
	*x = ntohl(*x);
	return 0;
}

int get_be64(FILE *f, uint64_t *x)
{
	if (fread(x, sizeof(*x), 1, f) != 1) {
		return -1;
	}
	*x = ntohll(*x);
	return 0;
}

int libvirt_check(FILE *f)
{
	struct qemud_save_header hdr;

	DEBUG(1, "Checking for Libvirt-QEMU-save magic...\n");

	if (fread(&hdr, sizeof(hdr), 1, f) != 1) {
		printf("Failed to read Libvirt-QEMU-save header: %s\n",
		       strerror(errno));
		return -1;
	}

	if (memcmp(hdr.magic, QEMUD_SAVE_MAGIC, sizeof(hdr.magic))) {
		printf("Invalid Libvirt-QEMU-save magic\n");
		return -1;
	}
	DEBUG(1, "Found Libvirt-QEMU-save magic\n");

	DEBUG(1, "Libvirt-QEMU-save version = %d\n", hdr.version);
	if (hdr.version != QEMUD_SAVE_VERSION) {
		printf("Unsupported Libvirt-QEMU-save version\n");
		return -1;
	}

	/* Skip past Libvirt XML configuration to get to QEMU savevm data. */
	if (fseek(f, sizeof(hdr) + hdr.xml_len, SEEK_SET)) {
		printf("Failed seek to QEMU-savevm start: %s\n",
		       strerror(errno));
		return -1;
	}

	return 0;
}

int qemu_check(FILE *f)
{
	uint32_t magic, version;

	DEBUG(1, "Checking for QEMU-savevm magic...\n");

	if (get_be32(f, &magic)) {
		printf("Failed to read QEMU-savevm magic\n");
		return -1;
	}

	if (magic != QEMU_VM_FILE_MAGIC) {
		printf("Invalid QEMU-savevm magic\n");
		return -1;
	}
	DEBUG(1, "Found QEMU-savevm magic\n");

	if (get_be32(f, &version)) {
		printf("Failed to read QEMU-savevm version\n");
		return -1;
	}

	DEBUG(1, "QEMU-savevm version = %u\n", version);
	if (version != QEMU_VM_FILE_VERSION) {
		printf("Unsupported QEMU-savevm version\n");
		return -1;
	}

	return 0;
}

#define BLK_MIG_FLAG_EOS (0x02)
int block_check(FILE *f)
{
	/*
	 * A more complete implementation could be based on qemu-kvm's
	 * block-migration.c, function block_load.  We don't really attempt to
	 * support block sections here.  We just know enough to skip past an
	 * empty one.
	 */

	uint64_t x;
	if (get_be64(f, &x)) {
		printf("Failed to read from 'block' section\n");
		return -1;
	}
	if (x != BLK_MIG_FLAG_EOS) {
		printf("Found unsupported non-empty 'block' section\n");
		return -1;
	}

	return 0;
}

// XXX: Assume 4k pages
#define PAGE_SIZE 4096
#define PAGE_MASK 0xfffffffffffff000

int mem_page_write(FILE *f, uint64_t addr, uint8_t *page)
{
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
	uint64_t addr, flags;
	static int write_to_file = 0;

	if (version_id != 4) {
		printf("Unsupported 'ram' section version\n");
		return -1;
	}

	do {
		if (get_be64(infp, &addr)) {
			printf("Failed to read address\n");
			return -1;
		}

		flags = addr & ~PAGE_MASK;
		addr &= PAGE_MASK;

		DEBUG(1, "flags = 0x%016lx\n", flags);
		DEBUG(1, "addr = 0x%016lx\n", addr);

		if (flags & RAM_SAVE_FLAG_MEM_SIZE) {
			uint64_t total_ram_bytes = addr;

			DEBUG(1, "Total data size = 0x%016llx (%llu MB)\n",
			       (unsigned long long) addr,
			       (unsigned long long) addr / (1<<20));

			while (total_ram_bytes) {
				uint8_t idstr_len;
				if (get_byte(infp, &idstr_len)) {
					printf("Failed to read id string "
					       "len\n");
					return -1;
				}
				char idstr[256];
				if (fread(idstr, idstr_len, 1, infp) != 1) {
					printf("Failed to read idstr\n");
					return -1;
				}
				idstr[idstr_len] = '\0';
				uint64_t length;
				if (get_be64(infp, &length)) {
					printf("Failed to read length\n");
					return -1;
				}

				int kb = (length >> 10) > 0 ? length >> 10 : 0;
				int mb = (length >> 20) > 0 ? length >> 20 : 0;
				printf("section = %-32s size = %5llu [%s] "
				       "%12llu [Bytes]\n",
				       idstr,
				       (unsigned long long)(mb > 0 ? mb :
							    kb > 0 ? kb :
							    length),
				       mb > 0 ? "MB" : kb > 0 ? "KB" : "Bytes",
				       (unsigned long long)length);

				total_ram_bytes -= length;
			}
		}

		if ((flags & RAM_SAVE_FLAG_COMPRESS) ||
		    (flags & RAM_SAVE_FLAG_PAGE)) {

			if (!(flags & RAM_SAVE_FLAG_CONTINUE)) {
				uint8_t idstr_len;
				if (get_byte(infp, &idstr_len)) {
					printf("Failed to read id string "
					       "len\n");
					return -1;
				}
				char idstr[256];
				if (fread(idstr, idstr_len, 1, infp) != 1) {
					printf("Failed to read idstr\n");
					return -1;
				}
				idstr[idstr_len] = '\0';

				DEBUG(1, "idstr = '%s'\n", idstr);

				if (!strcmp(idstr, section_name)) {
					write_to_file = 1;
				} else {
					write_to_file = 0;
				}
			}

			if (flags & RAM_SAVE_FLAG_COMPRESS) {
				uint8_t byte;
				if (get_byte(infp, &byte)) {
					printf("Failed to read byte\n");
					return -1;
				}

				if (write_to_file) {
					DEBUG(2, "Writing page at address "
					      "0x%016llx (fill byte = "
					      "0x%02x)\n",
					      (unsigned long long) addr, byte);
					mem_page_fill(outfp, addr, byte);
				}
			}

			if (flags & RAM_SAVE_FLAG_PAGE) {
				uint8_t page[PAGE_SIZE];
				if (fread(page, PAGE_SIZE, 1, infp) != 1) {
					printf("Failed to read page\n");
					return -1;
				}

				if (write_to_file) {
					DEBUG(2, "Writing page at address "
					      "0x%016llx\n",
					      (unsigned long long) addr);
					mem_page_write(outfp, addr, page);
				}
			}
		}

	} while (!(flags & RAM_SAVE_FLAG_EOS));

	return 0;
}

int add_section_info(struct section_info **sections, uint32_t id,
		     char *idstr, uint32_t version)
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

int handle_section(FILE *infp, FILE *outfp, char *section_name,
		   struct section_info *sections, uint32_t id, uint32_t type)
{
	struct section_info *secinfo = sections;
	while (secinfo) {
		if (secinfo->id == id) {
			break;
		}
		secinfo = secinfo->next;
	}
	if (!secinfo) {
		printf("No matching section in section list with id %d\n", id);
		return -1;
	}

	if (!strcmp(secinfo->idstr, "block")) {
		if (block_check(infp)) {
			return -1;
		}
	} else if (!strcmp(secinfo->idstr, "ram")) {
		if (ram_load(infp, outfp, section_name, secinfo->version)) {
			return -1;
		}
		if (type == QEMU_VM_SECTION_END) {
			return 1;
		}
	} else {
		/*
		 * Rather than continue to implement support for all other
		 * kinds of section, we could potentially write a heuristic
		 * scan-for-next-section based on low big-endian section_id,
		 * followed by one byte len and same number of ascii chars,
		 * followed by low big-endian instance and version ids.
		 */

		printf("Unsupported '%s' section before final 'ram' section, "
		       "conversion failed\n", secinfo->idstr);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char *options = "dl";
	int list = 0;
	FILE *infp, *outfp = NULL;
	char section_name[256];

	while (1) {
		int opt = getopt(argc, argv, options);
		if (opt < 0) {
			break;
		}
		switch (opt) {
			case 'd':
				debug++;
				break;
			case 'l':
				list = 1;
				break;
		}
	}

	if ((list && (argc - optind) != 1) ||
	    (!list && ((argc - optind) != 3))) {
		printf("Usage: %s [-d] INFILE OUTFILE SECTION\n"
		       "       %s [-d] -l INFILE\n\n",
		       argv[0], argv[0]);
		printf("Extract SECTION from INFILE and write it to "
		       "OUTFILE or\n");
		printf("list available sections in INFILE\n\n");
		printf("Options:\n");
		printf("  -d          enable debug output\n");
		printf("  -l INFILE   list available sections in INFILE\n\n");
		printf("Examples:\n");
		printf("  %s -l instance-00000d93.save\n", argv[0]);
		printf("  %s instance-00000d93.save instance-00000d93.ram "
		       "pc.ram\n", argv[0]);
		return -1;
	}

	infp = fopen(argv[optind], "r");
	if (!infp) {
		printf("Failed to open %s: %s\n", argv[optind],
		       strerror(errno));
		return -1;
	}

	if (!list) {
		outfp = fopen(argv[optind + 1], "wx");
		if (!outfp) {
			printf("Failed to open %s: %s\n", argv[optind + 1],
			       strerror(errno));
			return -1;
		}
		strcpy(section_name, argv[optind + 2]);
	}

	if (libvirt_check(infp)) {
		printf("Libvirt-QEMU-save check failed, checking if this is a "
		       "raw QEMU-savevm dump\n");
		rewind(infp);
	}

	if (qemu_check(infp)) {
		return -1;
	}

	struct section_info *sections = NULL;
	int section_count = 0;
	while (1) {
		uint64_t offset = ftell(infp);

		uint8_t section_type;
		if (get_byte(infp, &section_type)) {
			printf("Failed to read section type\n");
			return -1;
		}
		if (section_type == QEMU_VM_EOF) {
			break;
		}
		DEBUG(1, "Section %d (offset = 0x%016llx, type = %d)\n",
		      section_count, (unsigned long long) offset,
		      section_type);

		if (section_type == QEMU_VM_SECTION_START ||
				section_type == QEMU_VM_SECTION_FULL) {
			uint32_t section_id;
			if (get_be32(infp, &section_id)) {
				printf("Failed to read section id\n");
				return -1;
			}
			DEBUG(1, "section_id = 0x%08x\n", section_id);
			uint8_t idstr_len;
			if (get_byte(infp, &idstr_len)) {
				printf("Failed to read id string len\n");
				return -1;
			}
			char idstr[256];
			if (fread(idstr, idstr_len, 1, infp) != 1) {
				printf("Failed to read idstr\n");
				return -1;
			}
			idstr[idstr_len] = '\0';
			DEBUG(1, "idstr = '%s'\n", idstr);
			uint32_t instance_id;
			if (get_be32(infp, &instance_id)) {
				printf("Failed to read instance id\n");
				return -1;
			}
			DEBUG(1, "instance_id = 0x%08x\n", instance_id);
			uint32_t version_id;
			if (get_be32(infp, &version_id)) {
				printf("Failed to read version id\n");
				return -1;
			}
			DEBUG(1, "version = %u\n", version_id);

			if (add_section_info(&sections, section_id, idstr,
					     version_id)) {
				return -1;
			}

			if (handle_section(infp, outfp, section_name, sections,
					   section_id, section_type)) {
				return -1;
			}
		} else if (section_type == QEMU_VM_SECTION_PART ||
				section_type == QEMU_VM_SECTION_END) {
			uint32_t section_id;
			if (get_be32(infp, &section_id)) {
				printf("Failed to read section id\n");
				return -1;
			}
			DEBUG(1, "section_id = 0x%08x\n", section_id);

			int r = handle_section(infp, outfp, section_name,
					       sections, section_id,
					       section_type);
			if (r < 0) {
				return -1;
			} else if (r > 0) {
//				printf("Handled final 'ram' section, "
//				       "conversion complete\n");
				break;
			}
		} else {
			printf("Invalid section type: %d\n", section_type);
			return -1;
		}
		section_count++;
	}

	return 0;
}
