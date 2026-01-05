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
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>

#define MAX_WIKI_ENTRIES 1024
#define MAX_PARAM_LEN 64
#define MAX_CONFIG_LEN 32
#define MAX_TEXT_LEN 4096
#define MAX_LINE_LEN 1024

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
static char *output_wiki_c = "pages_wiki.c";
static char *output_wiki_h = "pages_wiki.h";

struct wiki_entry
{
	char param[MAX_PARAM_LEN];      /* parameter name, e.g. "serverip" */
	char config[MAX_CONFIG_LEN];    /* config file, e.g. "conf", "server", "user" */
	char text[MAX_TEXT_LEN];        /* help text */
	int text_len;
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
	fprintf(output_file, "struct wiki_entry {\n");
	fprintf(output_file, "\tconst char *param;\n");
	fprintf(output_file, "\tconst char *config;\n");
	fprintf(output_file, "\tconst char *text;\n");
	fprintf(output_file, "};\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "int32_t wiki_count(void);\n");
	fprintf(output_file, "const struct wiki_entry *wiki_get_entries(void);\n");
	fprintf(output_file, "const char *wiki_get_help(const char *config, const char *param);\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#endif /* WEBIF_WIKI */\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#endif /* WEBIF_PAGES_WIKI_H_ */\n");

	fclose(output_file);
}

/* Generate pages_wiki.c */
static void generate_source(void)
{
	output_file = xfopen(output_wiki_c, "w");

	fprintf(output_file, "/*\n");
	fprintf(output_file, " * OSCam WebIf Wiki data - AUTO GENERATED, DO NOT EDIT!\n");
	fprintf(output_file, " * Generated by wiki_gen from wiki markdown files\n");
	fprintf(output_file, " */\n");
	fprintf(output_file, "#include \"../globals.h\"\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#if defined(WEBIF) && defined(WEBIF_WIKI)\n");
	fprintf(output_file, "\n");
	fprintf(output_file, "#include \"pages_wiki.h\"\n");
	fprintf(output_file, "#include <string.h>\n");
	fprintf(output_file, "\n");

	/* Generate wiki entries array */
	fprintf(output_file, "static const struct wiki_entry wiki_entries[] = {\n");
	for(unsigned int i = 0; i < wiki.num; i++)
	{
		struct wiki_entry *e = &wiki.entries[i];
		fprintf(output_file, "\t{ .param = \"%s\", .config = \"%s\", .text = \"%s\" },\n",
				e->param, e->config, e->text);
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
	fprintf(output_file, "\n");

	fprintf(output_file, "#endif /* WEBIF && WEBIF_WIKI */\n");

	fclose(output_file);
}

int main(int argc, char *argv[])
{
	/* Allow overriding wiki directory via command line */
	if(argc > 1)
		{ wiki_dir = argv[1]; }

	printf("WIKI\tScanning %s\n", wiki_dir);
	scan_wiki_directory(wiki_dir);

	if(wiki.num == 0)
	{
		fprintf(stderr, "Warning: No wiki entries found in %s\n", wiki_dir);
	}
	else
	{
		printf("WIKI\tFound %u parameter entries\n", wiki.num);
	}

	printf("GEN\t%s\n", output_wiki_h);
	generate_header();

	printf("GEN\t%s\n", output_wiki_c);
	generate_source();

	return 0;
}
