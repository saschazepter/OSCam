/*
 * OSCam WebIf Wiki generator
 * Parses Wiki markdown files and generates C code with help texts
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#include "../config.h"
#ifdef WITH_COMPRESS_WEBIF
#include "../minilzo/minilzo.h"
#define USE_COMPRESSION 1
#endif

#define MAX_WIKI_ENTRIES 1024
#define MAX_PARAM_LEN 64
#define MAX_CONFIG_LEN 32
#define MAX_TEXT_LEN 4096
#define MAX_LINE_LEN 1024
#define MAX_FLAG_LEN 64
#define MAX_CONFIG_MAPPINGS 128

/*
 * Dynamic mapping from config file to compile flag
 * Built at runtime from pages_index.txt
 */
struct config_mapping {
	char config[MAX_CONFIG_LEN];
	char flag[MAX_FLAG_LEN];
};

static struct config_mapping config_flags[MAX_CONFIG_MAPPINGS];
static int config_flags_count = 0;

/* Safe string copy - always null-terminates */
static void safe_strncpy(char *dst, const char *src, size_t size)
{
	if(size == 0)
		{ return; }
	size_t i;
	for(i = 0; i < size - 1 && src[i] != '\0'; i++)
	{
		dst[i] = src[i];
	}
	dst[i] = '\0';
}

static char *wiki_dir = "../wiki/pages/configuration";
static char *pages_index_file = "pages_index.txt";
static char *output_wiki_c = "pages_wiki.c";
static char *output_wiki_h = "pages_wiki.h";

struct wiki_entry
{
	char param[MAX_PARAM_LEN];      /* parameter name, e.g. "serverip" */
	char config[MAX_CONFIG_LEN];    /* config file, e.g. "conf", "server", "user" */
	char text[MAX_TEXT_LEN];        /* help text */
	int text_len;
	char flag[MAX_FLAG_LEN];        /* compile flag or empty if always included */
#ifdef USE_COMPRESSION
	uint32_t param_ofs;
	uint32_t config_ofs;
	uint32_t text_ofs;
#endif
};

struct wiki_data
{
	unsigned int num;
	struct wiki_entry entries[MAX_WIKI_ENTRIES];
};

static struct wiki_data wiki;
static FILE *output_file;

__attribute__ ((noreturn)) static void die(const char *s, ...)
{
	va_list args;
	va_start(args, s);
	fprintf(stderr, "ERROR: ");
	vfprintf(stderr, s, args);
	if(s[strlen(s) - 1] != '\n')
		{ fprintf(stderr, "\n"); }
	va_end(args);
	exit(EXIT_FAILURE);
}

static FILE *xfopen(char *filename, char *mode)
{
	FILE *fh = fopen(filename, mode);
	if(!fh)
		{ die("fopen(%s, %s): %s\n", filename, mode, strerror(errno)); }
	return fh;
}

/*
 * Extract config name from template path
 * e.g. "config/dvbapi.html" -> "dvbapi"
 *      "config/global.html" -> "conf" (special case)
 *      "readerconfig/readerconfig.html" -> "server"
 *      "user_edit/user_edit.html" -> "user"
 */
static void template_to_config(const char *template_path, char *config, size_t config_size)
{
	config[0] = '\0';

	/* Check for config/ prefix */
	if(strncmp(template_path, "config/", 7) == 0)
	{
		const char *filename = template_path + 7;

		/* Special mappings */
		if(strncmp(filename, "global", 6) == 0)
		{
			safe_strncpy(config, "conf", config_size);
			return;
		}
		if(strncmp(filename, "loadbalancer", 12) == 0)
		{
			safe_strncpy(config, "conf", config_size);
			return;
		}
		if(strncmp(filename, "cache", 5) == 0)
		{
			safe_strncpy(config, "conf", config_size);
			return;
		}
		if(strncmp(filename, "webif", 5) == 0)
		{
			safe_strncpy(config, "conf", config_size);
			return;
		}

		/* Extract name before .html */
		size_t i = 0;
		while(filename[i] && filename[i] != '.' && i < config_size - 1)
		{
			config[i] = filename[i];
			i++;
		}
		config[i] = '\0';
	}
	else if(strncmp(template_path, "readerconfig/", 13) == 0)
	{
		safe_strncpy(config, "server", config_size);
	}
	else if(strncmp(template_path, "user_edit/", 10) == 0 ||
			strncmp(template_path, "userconfig/", 11) == 0)
	{
		safe_strncpy(config, "user", config_size);
	}
}

/*
 * Parse pages_index.txt to build config->flag mapping
 * Format: TEMPLATE_NAME  FILENAME  DEPENDENCY1,DEPENDENCYx
 */
static void parse_pages_index(const char *filepath)
{
	FILE *f = fopen(filepath, "r");
	if(!f)
	{
		fprintf(stderr, "Warning: Cannot open %s: %s\n", filepath, strerror(errno));
		fprintf(stderr, "         Config->Flag mapping will be empty, all entries will be included.\n");
		return;
	}

	char line[MAX_LINE_LEN];
	while(fgets(line, sizeof(line), f))
	{
		/* Skip comments and empty lines */
		char *p = line;
		while(isspace((unsigned char)*p)) p++;
		if(*p == '#' || *p == '\0' || *p == '\n')
			{ continue; }

		/* Parse: TEMPLATE_NAME  FILENAME  DEPENDENCY */
		char template_name[128] = "";
		char filename[256] = "";
		char dependency[128] = "";

		int field = 0;
		char *token_start = p;
		bool in_token = true;

		while(*p)
		{
			if(*p == ' ' || *p == '\t' || *p == '\n')
			{
				if(in_token)
				{
					*p = '\0';
					switch(field)
					{
						case 0: safe_strncpy(template_name, token_start, sizeof(template_name)); break;
						case 1: safe_strncpy(filename, token_start, sizeof(filename)); break;
						case 2: safe_strncpy(dependency, token_start, sizeof(dependency)); break;
					}
					field++;
					in_token = false;
				}
			}
			else if(!in_token)
			{
				token_start = p;
				in_token = true;
			}
			p++;
		}

		/* Handle last token if line doesn't end with whitespace */
		if(in_token && field < 3)
		{
			/* Remove trailing newline */
			char *nl = strchr(token_start, '\n');
			if(nl) *nl = '\0';
			switch(field)
			{
				case 0: safe_strncpy(template_name, token_start, sizeof(template_name)); break;
				case 1: safe_strncpy(filename, token_start, sizeof(filename)); break;
				case 2: safe_strncpy(dependency, token_start, sizeof(dependency)); break;
			}
		}

		/* Skip entries without dependency (always included) */
		if(dependency[0] == '\0')
			{ continue; }

		/* Convert template path to config name */
		char config[MAX_CONFIG_LEN];
		template_to_config(filename, config, sizeof(config));

		if(config[0] == '\0')
			{ continue; }

		/* Check if we already have this config */
		bool found = false;
		for(int i = 0; i < config_flags_count; i++)
		{
			if(strcmp(config_flags[i].config, config) == 0)
			{
				found = true;
				/* If existing entry has no flag but new one does, update it */
				if(config_flags[i].flag[0] == '\0' && dependency[0] != '\0')
				{
					/* Use first flag if multiple (comma-separated) */
					char *comma = strchr(dependency, ',');
					if(comma) *comma = '\0';
					safe_strncpy(config_flags[i].flag, dependency, MAX_FLAG_LEN);
				}
				break;
			}
		}

		if(!found && config_flags_count < MAX_CONFIG_MAPPINGS)
		{
			safe_strncpy(config_flags[config_flags_count].config, config, MAX_CONFIG_LEN);
			/* Use first flag if multiple (comma-separated) */
			char dep_copy[128];
			safe_strncpy(dep_copy, dependency, sizeof(dep_copy));
			char *comma = strchr(dep_copy, ',');
			if(comma) *comma = '\0';
			safe_strncpy(config_flags[config_flags_count].flag, dep_copy, MAX_FLAG_LEN);
			config_flags_count++;
		}
	}

	fclose(f);

	printf("GEN\tLoaded %d config->flag mappings from %s\n", config_flags_count, filepath);
}

/* Get compile flag for config name */
static const char *get_flag_for_config(const char *config)
{
	for(int i = 0; i < config_flags_count; i++)
	{
		if(strcmp(config_flags[i].config, config) == 0)
		{
			if(config_flags[i].flag[0] != '\0')
				{ return config_flags[i].flag; }
			return NULL;
		}
	}
	return NULL;
}

/* Extract config name from filename, e.g. "oscam.conf.md" -> "conf" */
static void extract_config_name(const char *filename, char *config, size_t config_size)
{
	const char *base = filename;
	const char *slash = strrchr(filename, '/');
	if(slash)
		{ base = slash + 1; }

	/* Skip "oscam." prefix */
	if(strncmp(base, "oscam.", 6) == 0)
		{ base += 6; }

	/* Copy until ".md" */
	size_t i = 0;
	while(*base && *base != '.' && i < config_size - 1)
	{
		config[i++] = *base++;
	}
	config[i] = '\0';
}

/* Trim whitespace from both ends of string */
static char *trim(char *str)
{
	char *end;

	/* Trim leading space */
	while(isspace((unsigned char)*str))
		{ str++; }

	if(*str == 0)
		{ return str; }

	/* Trim trailing space */
	end = str + strlen(str) - 1;
	while(end > str && isspace((unsigned char)*end))
		{ end--; }

	end[1] = '\0';
	return str;
}

/* Escape string for C string literal */
static void escape_for_c(const char *src, char *dst, size_t dst_size)
{
	size_t j = 0;
	for(size_t i = 0; src[i] && j < dst_size - 2; i++)
	{
		switch(src[i])
		{
		case '\n':
			if(j < dst_size - 3) { dst[j++] = '\\'; dst[j++] = 'n'; }
			break;
		case '\r':
			/* Skip CR */
			break;
		case '\t':
			if(j < dst_size - 3) { dst[j++] = '\\'; dst[j++] = 't'; }
			break;
		case '\\':
			if(j < dst_size - 3) { dst[j++] = '\\'; dst[j++] = '\\'; }
			break;
		case '"':
			if(j < dst_size - 3) { dst[j++] = '\\'; dst[j++] = '"'; }
			break;
		default:
			dst[j++] = src[i];
			break;
		}
	}
	dst[j] = '\0';
}

/* Check if line is a parameter heading (### param_name) */
static bool is_param_heading(const char *line, char *param_name, size_t param_size)
{
	/* Skip leading whitespace */
	while(isspace((unsigned char)*line))
		{ line++; }

	/* Check for ### */
	if(strncmp(line, "###", 3) != 0)
		{ return false; }

	line += 3;

	/* Skip whitespace after ### */
	while(isspace((unsigned char)*line))
		{ line++; }

	/* Extract parameter name (alphanumeric and underscore) */
	size_t i = 0;
	while((isalnum((unsigned char)*line) || *line == '_' || *line == '-') && i < param_size - 1)
	{
		param_name[i++] = *line++;
	}
	param_name[i] = '\0';

	return i > 0;
}

/* Check if line is a section separator (---) */
static bool is_separator(const char *line)
{
	/* Skip leading whitespace */
	while(isspace((unsigned char)*line))
		{ line++; }

	/* Check for --- (at least 3 dashes) */
	int dashes = 0;
	while(*line == '-')
	{
		dashes++;
		line++;
	}

	/* Rest should be whitespace or end of line */
	while(*line)
	{
		if(!isspace((unsigned char)*line))
			{ return false; }
		line++;
	}

	return dashes >= 3;
}

/* Check if line is a section heading (## Section) - not parameter */
static bool is_section_heading(const char *line)
{
	/* Skip leading whitespace */
	while(isspace((unsigned char)*line))
		{ line++; }

	/* ## but not ### */
	if(line[0] == '#' && line[1] == '#' && line[2] != '#')
		{ return true; }

	return false;
}

/* Parse a single markdown file */
static void parse_wiki_file(const char *filepath)
{
	FILE *f = fopen(filepath, "r");
	if(!f)
	{
		fprintf(stderr, "Warning: Cannot open %s: %s\n", filepath, strerror(errno));
		return;
	}

	char config[MAX_CONFIG_LEN];
	extract_config_name(filepath, config, sizeof(config));
	const char *flag = get_flag_for_config(config);

	char line[MAX_LINE_LEN];
	char current_param[MAX_PARAM_LEN] = "";
	char current_text[MAX_TEXT_LEN] = "";
	int text_pos = 0;
	bool in_param = false;

	while(fgets(line, sizeof(line), f))
	{
		char param_name[MAX_PARAM_LEN];

		if(is_param_heading(line, param_name, sizeof(param_name)))
		{
			/* Save previous parameter if exists */
			if(in_param && current_param[0] && text_pos > 0)
			{
				if(wiki.num < MAX_WIKI_ENTRIES)
				{
					struct wiki_entry *e = &wiki.entries[wiki.num];
					safe_strncpy(e->param, current_param, MAX_PARAM_LEN);
					safe_strncpy(e->config, config, MAX_CONFIG_LEN);
					current_text[text_pos] = '\0';
					char *trimmed = trim(current_text);
					escape_for_c(trimmed, e->text, MAX_TEXT_LEN);
					e->text_len = strlen(e->text);
					if(flag)
						{ safe_strncpy(e->flag, flag, MAX_FLAG_LEN); }
					else
						{ e->flag[0] = '\0'; }
					wiki.num++;
				}
			}

			/* Start new parameter */
			safe_strncpy(current_param, param_name, MAX_PARAM_LEN);
			text_pos = 0;
			current_text[0] = '\0';
			in_param = true;
		}
		else if(in_param)
		{
			/* Check for end of parameter section */
			if(is_separator(line) || is_section_heading(line))
			{
				/* Save current parameter */
				if(current_param[0] && text_pos > 0)
				{
					if(wiki.num < MAX_WIKI_ENTRIES)
					{
						struct wiki_entry *e = &wiki.entries[wiki.num];
						safe_strncpy(e->param, current_param, MAX_PARAM_LEN);
						safe_strncpy(e->config, config, MAX_CONFIG_LEN);
						current_text[text_pos] = '\0';
						char *trimmed = trim(current_text);
						escape_for_c(trimmed, e->text, MAX_TEXT_LEN);
						e->text_len = strlen(e->text);
						if(flag)
							{ safe_strncpy(e->flag, flag, MAX_FLAG_LEN); }
						else
							{ e->flag[0] = '\0'; }
						wiki.num++;
					}
				}
				in_param = false;
				current_param[0] = '\0';
				text_pos = 0;
			}
			else
			{
				/* Append line to current text */
				int line_len = strlen(line);
				if(text_pos + line_len < MAX_TEXT_LEN - 1)
				{
					memcpy(current_text + text_pos, line, line_len);
					text_pos += line_len;
				}
			}
		}
	}

	/* Save last parameter if file ends without separator */
	if(in_param && current_param[0] && text_pos > 0)
	{
		if(wiki.num < MAX_WIKI_ENTRIES)
		{
			struct wiki_entry *e = &wiki.entries[wiki.num];
			safe_strncpy(e->param, current_param, MAX_PARAM_LEN);
			safe_strncpy(e->config, config, MAX_CONFIG_LEN);
			current_text[text_pos] = '\0';
			char *trimmed = trim(current_text);
			escape_for_c(trimmed, e->text, MAX_TEXT_LEN);
			e->text_len = strlen(e->text);
			if(flag)
				{ safe_strncpy(e->flag, flag, MAX_FLAG_LEN); }
			else
				{ e->flag[0] = '\0'; }
			wiki.num++;
		}
	}

	fclose(f);
}

/* Scan wiki directory for markdown files */
static void scan_wiki_directory(const char *dirpath)
{
	DIR *dir = opendir(dirpath);
	if(!dir)
	{
		fprintf(stderr, "Warning: Cannot open wiki directory %s: %s\n", dirpath, strerror(errno));
		return;
	}

	struct dirent *entry;
	while((entry = readdir(dir)) != NULL)
	{
		/* Skip hidden files and directories */
		if(entry->d_name[0] == '.')
			{ continue; }

		/* Check for .md extension */
		size_t len = strlen(entry->d_name);
		if(len < 4 || strcmp(entry->d_name + len - 3, ".md") != 0)
			{ continue; }

		/* Build full path */
		char filepath[512];
		snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);

		printf("WIKI\tParsing %s\n", entry->d_name);
		parse_wiki_file(filepath);
	}

	closedir(dir);
}

/* Generate pages_wiki.h */
static void generate_header(void)
{
	output_file = xfopen(output_wiki_h, "w");

	fprintf(output_file, "/*\n");
	fprintf(output_file, " * OSCam WebIf Wiki data - AUTO GENERATED, DO NOT EDIT!\n");
	fprintf(output_file, " * Generated by wiki_gen from wiki markdown files\n");
	fprintf(output_file, " */\n");
	fprintf(output_file, "#ifndef WEBIF_PAGES_WIKI_H_\n");
	fprintf(output_file, "#define WEBIF_PAGES_WIKI_H_\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#ifdef WEBIF_WIKI\n");
	fprintf(output_file, "\n");
#ifdef USE_COMPRESSION
	fprintf(output_file, "#define COMPRESSED_WIKI 1\n\n");
	fprintf(output_file, "struct wiki_entry {\n");
	fprintf(output_file, "\tuint32_t param_ofs;\n");
	fprintf(output_file, "\tuint32_t config_ofs;\n");
	fprintf(output_file, "\tuint32_t text_ofs;\n");
	fprintf(output_file, "};\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "int32_t wiki_count(void);\n");
	fprintf(output_file, "const struct wiki_entry *wiki_get_entries(void);\n");
	fprintf(output_file, "const char *wiki_get_help(const char *config, const char *param);\n");
	fprintf(output_file, "void wiki_get_data(const char **data, size_t *data_len, size_t *data_olen);\n");
	fprintf(output_file, "void webif_wiki_prepare(void);\n");
	fprintf(output_file, "void webif_wiki_free(void);\n");
#else
	fprintf(output_file, "struct wiki_entry {\n");
	fprintf(output_file, "\tconst char *param;\n");
	fprintf(output_file, "\tconst char *config;\n");
	fprintf(output_file, "\tconst char *text;\n");
	fprintf(output_file, "};\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "int32_t wiki_count(void);\n");
	fprintf(output_file, "const struct wiki_entry *wiki_get_entries(void);\n");
	fprintf(output_file, "const char *wiki_get_help(const char *config, const char *param);\n");
	fprintf(output_file, "void webif_wiki_prepare(void);\n");
	fprintf(output_file, "void webif_wiki_free(void);\n");
#endif
	fprintf(output_file, "\n");
	fprintf(output_file, "#endif /* WEBIF_WIKI */\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#endif /* WEBIF_PAGES_WIKI_H_ */\n");

	fclose(output_file);
}

#ifdef USE_COMPRESSION
#define HEAP_ALLOC(var, size) \
	lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);

static void dump_cbinary(char *var_name, uint8_t *buf, size_t buf_len, size_t obuf_len)
{
	fprintf(output_file, "static const char   *%s     = \"", var_name);
	size_t i;
	for(i = 0; i < buf_len; i++)
	{
		fprintf(output_file, "\\x%02x", buf[i]);
	}
	fprintf(output_file, "\";\n");
	fprintf(output_file, "static const size_t %s_len  = %zu;\n"  , var_name, buf_len);
	fprintf(output_file, "static const size_t %s_olen = %zu;\n\n", var_name, obuf_len);
}
#endif

/* Print wiki entry with optional #ifdef guards */
static void print_wiki_entry(int idx)
{
	static char current_flag[MAX_FLAG_LEN] = "";
	struct wiki_entry *e = &wiki.entries[idx];
	const char *next_flag = (idx + 1 < (int)wiki.num) ? wiki.entries[idx + 1].flag : "";

	/* Open #ifdef if flag changes */
	if(e->flag[0] && strcmp(e->flag, current_flag) != 0)
	{
		if(current_flag[0])
			{ fprintf(output_file, "#endif\n"); }
		fprintf(output_file, "#ifdef %s\n", e->flag);
	}
	else if(!e->flag[0] && current_flag[0])
	{
		fprintf(output_file, "#endif\n");
	}
	safe_strncpy(current_flag, e->flag, MAX_FLAG_LEN);

#ifdef USE_COMPRESSION
	fprintf(output_file, "\t{ .param_ofs=%5u, .config_ofs=%5u, .text_ofs=%5u }, /* %s.%s */\n",
			e->param_ofs, e->config_ofs, e->text_ofs, e->config, e->param);
#else
	fprintf(output_file, "\t{ .param = \"%s\", .config = \"%s\", .text = \"%s\" },\n",
			e->param, e->config, e->text);
#endif

	/* Close #ifdef if next entry has different flag */
	if(idx + 1 >= (int)wiki.num && current_flag[0])
	{
		fprintf(output_file, "#endif\n");
		current_flag[0] = '\0';
	}
	else if(strcmp(next_flag, current_flag) != 0 && current_flag[0])
	{
		fprintf(output_file, "#endif\n");
		current_flag[0] = '\0';
	}
}

/* Sort entries by flag for better #ifdef grouping */
static int compare_entries(const void *a, const void *b)
{
	const struct wiki_entry *ea = (const struct wiki_entry *)a;
	const struct wiki_entry *eb = (const struct wiki_entry *)b;

	/* Empty flags (always included) come first */
	if(ea->flag[0] == '\0' && eb->flag[0] != '\0') return -1;
	if(ea->flag[0] != '\0' && eb->flag[0] == '\0') return 1;
	if(ea->flag[0] == '\0' && eb->flag[0] == '\0') return 0;

	/* Sort by flag name */
	return strcmp(ea->flag, eb->flag);
}

/* Generate pages_wiki.c */
static void generate_source(void)
{
	unsigned int i;

	/* Sort entries by flag for cleaner #ifdef grouping */
	qsort(wiki.entries, wiki.num, sizeof(struct wiki_entry), compare_entries);

	output_file = xfopen(output_wiki_c, "w");

	fprintf(output_file, "/*\n");
	fprintf(output_file, " * OSCam WebIf Wiki data - AUTO GENERATED, DO NOT EDIT!\n");
	fprintf(output_file, " * Generated by wiki_gen from wiki markdown files\n");
	fprintf(output_file, " */\n");
	fprintf(output_file, "#define MODULE_LOG_PREFIX \"webif\"\n");
	fprintf(output_file, "#include \"../globals.h\"\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#if defined(WEBIF) && defined(WEBIF_WIKI)\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#include \"pages_wiki.h\"\n");
	fprintf(output_file, "#include <string.h>\n");
#ifdef USE_COMPRESSION
	fprintf(output_file, "#ifdef WITH_COMPRESS_WEBIF\n");
	fprintf(output_file, "#include \"../minilzo/minilzo.h\"\n");
	fprintf(output_file, "#endif\n");
#endif
	fprintf(output_file, "\n");

#ifdef USE_COMPRESSION
	/* Calculate positions */
	uint32_t cur_pos = 0;
#define align_up(val, align) (val += (align - val % align))
	for(i = 0; i < wiki.num; i++)
	{
		struct wiki_entry *e = &wiki.entries[i];
		e->param_ofs = cur_pos;
		cur_pos += strlen(e->param) + 1;
		align_up(cur_pos, sizeof(void *));
		e->config_ofs = cur_pos;
		cur_pos += strlen(e->config) + 1;
		align_up(cur_pos, sizeof(void *));
		e->text_ofs = cur_pos;
		cur_pos += strlen(e->text) + 1;
		align_up(cur_pos, sizeof(void *));
	}

	/* Allocate and populate data buffer */
	uint32_t data_len = cur_pos;
	if(!data_len)
		{ die("No wiki entries"); }
	uint8_t *data = calloc(1, data_len);
	if(!data)
		{ die("Can't alloc %u bytes", data_len); }
	for(i = 0; i < wiki.num; i++)
	{
		struct wiki_entry *e = &wiki.entries[i];
		memcpy(data + e->param_ofs, e->param, strlen(e->param));
		memcpy(data + e->config_ofs, e->config, strlen(e->config));
		memcpy(data + e->text_ofs, e->text, strlen(e->text));
	}

	/* Compress data */
	lzo_uint in_len = data_len;
	lzo_uint out_len = data_len + data_len / 16 + 64 + 3;
	uint8_t *out = malloc(out_len);
	if(!out)
		{ die("Can't alloc %zu bytes", out_len); }

	if(lzo_init() != LZO_E_OK)
	{
		fprintf(stderr, "internal error - lzo_init() failed!\n");
		free(out);
		free(data);
		exit(3);
	}

	int r = lzo1x_1_compress(data, in_len, out, &out_len, wrkmem);
	if(r == LZO_E_OK)
	{
		printf("GEN\tCompressed %lu bytes into %lu bytes. %ld saved (%.1f%%)\n",
				(unsigned long)in_len, (unsigned long)out_len,
				(long)in_len - (long)out_len, 100.0 - ((float)out_len / in_len) * 100);
	}
	else
	{
		fprintf(stderr, "compression failed: %d\n", r);
		free(out);
		free(data);
		exit(2);
	}

	dump_cbinary("wiki_data", out, out_len, data_len);
	free(out);
	free(data);
#endif

	/* Generate wiki entries array */
	fprintf(output_file, "static const struct wiki_entry wiki_entries[] = {\n");
	for(i = 0; i < wiki.num; i++)
	{
		print_wiki_entry(i);
	}
	fprintf(output_file, "};\n");
	fprintf(output_file, "\n");

	/* Generate accessor functions */
	fprintf(output_file, "int32_t wiki_count(void)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\treturn sizeof(wiki_entries) / sizeof(struct wiki_entry);\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");

	fprintf(output_file, "const struct wiki_entry *wiki_get_entries(void)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\treturn wiki_entries;\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");

#ifdef USE_COMPRESSION
	fprintf(output_file, "static char *wiki_data_decompressed = NULL;\n");
	fprintf(output_file, "\n");

	fprintf(output_file, "void wiki_get_data(const char **data, size_t *data_len, size_t *data_olen)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\t*data = wiki_data;\n");
	fprintf(output_file, "\t*data_len = wiki_data_len;\n");
	fprintf(output_file, "\t*data_olen = wiki_data_olen;\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");

	fprintf(output_file, "void webif_wiki_prepare(void)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\tif(wiki_data_decompressed) return;\n");
	fprintf(output_file, "\tconst char *data;\n");
	fprintf(output_file, "\tsize_t data_len, data_olen;\n");
	fprintf(output_file, "\twiki_get_data(&data, &data_len, &data_olen);\n");
	fprintf(output_file, "\twiki_data_decompressed = malloc(data_olen);\n");
	fprintf(output_file, "\tif(!wiki_data_decompressed)\n");
	fprintf(output_file, "\t{\n");
	fprintf(output_file, "\t\tcs_log(\"wiki: cannot allocate %%zu bytes for decompression\", data_olen);\n");
	fprintf(output_file, "\t\treturn;\n");
	fprintf(output_file, "\t}\n");
	fprintf(output_file, "\tlzo_uint new_len = data_olen;\n");
	fprintf(output_file, "\tint r = lzo1x_decompress_safe((uint8_t *)data, data_len, (uint8_t *)wiki_data_decompressed, &new_len, NULL);\n");
	fprintf(output_file, "\tif(r == LZO_E_OK && new_len == data_olen)\n");
	fprintf(output_file, "\t{\n");
	fprintf(output_file, "\t\tcs_log(\"wiki: decompressed %%zu bytes back into %%zu bytes\", data_len, data_olen);\n");
	fprintf(output_file, "\t}\n");
	fprintf(output_file, "\telse\n");
	fprintf(output_file, "\t{\n");
	fprintf(output_file, "\t\tcs_log(\"wiki: decompression failed: %%d\", r);\n");
	fprintf(output_file, "\t\tfree(wiki_data_decompressed);\n");
	fprintf(output_file, "\t\twiki_data_decompressed = NULL;\n");
	fprintf(output_file, "\t}\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");

	fprintf(output_file, "void webif_wiki_free(void)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\tif(wiki_data_decompressed)\n");
	fprintf(output_file, "\t{\n");
	fprintf(output_file, "\t\tfree(wiki_data_decompressed);\n");
	fprintf(output_file, "\t\twiki_data_decompressed = NULL;\n");
	fprintf(output_file, "\t}\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");

	fprintf(output_file, "const char *wiki_get_help(const char *config, const char *param)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\tif(!wiki_data_decompressed) return NULL;\n");
	fprintf(output_file, "\tint32_t i, count = wiki_count();\n");
	fprintf(output_file, "\tfor(i = 0; i < count; i++)\n");
	fprintf(output_file, "\t{\n");
	fprintf(output_file, "\t\tconst char *e_config = wiki_data_decompressed + wiki_entries[i].config_ofs;\n");
	fprintf(output_file, "\t\tconst char *e_param = wiki_data_decompressed + wiki_entries[i].param_ofs;\n");
	fprintf(output_file, "\t\tif(strcmp(e_config, config) == 0 && strcmp(e_param, param) == 0)\n");
	fprintf(output_file, "\t\t\treturn wiki_data_decompressed + wiki_entries[i].text_ofs;\n");
	fprintf(output_file, "\t}\n");
	fprintf(output_file, "\treturn NULL;\n");
	fprintf(output_file, "}\n");
#else
	fprintf(output_file, "void webif_wiki_prepare(void)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\tcs_log(\"wiki: %%d help entries loaded\", wiki_count());\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");

	fprintf(output_file, "void webif_wiki_free(void)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\t/* nothing to free in uncompressed mode */\n");
	fprintf(output_file, "}\n");
	fprintf(output_file, "\n");

	fprintf(output_file, "const char *wiki_get_help(const char *config, const char *param)\n");
	fprintf(output_file, "{\n");
	fprintf(output_file, "\tint32_t i;\n");
	fprintf(output_file, "\tint32_t count = wiki_count();\n");
	fprintf(output_file, "\tfor(i = 0; i < count; i++)\n");
	fprintf(output_file, "\t{\n");
	fprintf(output_file, "\t\tif(strcmp(wiki_entries[i].config, config) == 0 &&\n");
	fprintf(output_file, "\t\t   strcmp(wiki_entries[i].param, param) == 0)\n");
	fprintf(output_file, "\t\t{\n");
	fprintf(output_file, "\t\t\treturn wiki_entries[i].text;\n");
	fprintf(output_file, "\t\t}\n");
	fprintf(output_file, "\t}\n");
	fprintf(output_file, "\treturn NULL;\n");
	fprintf(output_file, "}\n");
#endif

	fprintf(output_file, "\n");
	fprintf(output_file, "#endif /* WEBIF && WEBIF_WIKI */\n");

	fclose(output_file);
}

int main(int argc, char *argv[])
{
	/* Allow overriding wiki directory via command line */
	if(argc > 1)
		{ wiki_dir = argv[1]; }

	/* Parse pages_index.txt to build config->flag mapping */
	printf("GEN\tReading %s for config->flag mapping\n", pages_index_file);
	parse_pages_index(pages_index_file);

	printf("WIKI\tScanning %s\n", wiki_dir);
	scan_wiki_directory(wiki_dir);

	if(wiki.num == 0)
	{
		fprintf(stderr, "Warning: No wiki entries found in %s\n", wiki_dir);
	}
	else
	{
		/* Count unconditional vs conditional entries */
		unsigned int unconditional = 0;
		unsigned int conditional = 0;
		for(unsigned int i = 0; i < wiki.num; i++)
		{
			if(wiki.entries[i].flag[0] == '\0')
				{ unconditional++; }
			else
				{ conditional++; }
		}
		printf("GEN\tFound %u parameter entries (%u unconditional, %u conditional)\n",
				wiki.num, unconditional, conditional);
	}

	printf("GEN\t%s\n", output_wiki_h);
	generate_header();

	printf("GEN\t%s\n", output_wiki_c);
	generate_source();

	return 0;
}
