/**
 * Relocate execution in another directory
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "cec_lib.h"
#include "addons/syscall_addons.h"
#include "extension/extension.h"


/**
 * Defines OUTPUT macro for all addon outputs.
 */
#define OUTPUT(...)     \
  fprintf(output_file, __VA_ARGS__)
#define VERBOSE(...)    \
  do { if (verbose) OUTPUT(__VA_ARGS__); } while (0)


/**
 * Local variables, self describing.
 */
static int active;
static int verbose;
static FILE *output_file = NULL;
static char *reloc_dir = NULL;

static cec_hash_t *ignored_pathes = NULL;
static cec_hash_t *translated_pathes = NULL;

static char *predef_ignored_prefixes[] =
  {
    "/dev", "/sys", "/proc", 0
  };

static char **userdef_ignored_prefixes;
static char **handled_prefixes;


/*
 * Forward declarations.
 */
static int reloc_exec_callback(Extension *, ExtensionEvent, intptr_t, intptr_t);


/**
 * Register the current addon through a constructor function.
 */
static void __attribute__((constructor)) init(void)
{
  static struct addon_info addon = {
    "reloc_exec", reloc_exec_callback
  };

  syscall_addons_register(&addon);
}


static void __attribute__((destructor)) fini(void)
{
  if (ignored_pathes != NULL)
    cec_hash_del(ignored_pathes);
  if (translated_pathes != NULL)
    cec_hash_del(translated_pathes);
}


static int reloc_exec_mkdir(char *path)
{
  int status;
  char command[ARG_MAX];
  status = snprintf(command, ARG_MAX, "/bin/mkdir -p %s", path);
  if (status < 0)
    return status;
  VERBOSE("   command: %s\n", command);
  status = system(command);
  return status;
}


static int reloc_exec_copyfile(char *src, char *dstdir)
{
  int status;
  char command[ARG_MAX];
  status = snprintf(command, ARG_MAX,
		    "/bin/cp --no-clobber --preserve --parents %s %s",
		    src, dstdir);
  if (status < 0)
    return status;
  VERBOSE("   command: %s\n", command);
  status = system(command);
  return status;
}


static int in_prefix_list(char **prefixes, char *str)
{
  int i;
  if (prefixes == NULL)
    return 0;
  for (i = 0; prefixes[i]; i++)
    {
      if (!strncmp(str, prefixes[i], strlen(prefixes[i])))
	return 1;
    }
  return 0;
}


static char **str_to_list(char *str)
{
  char *delim = ",";
  int index = 0, nb_prefixes = 1;
  char *saveptr, *tmp_str = str;
  char **res_list;

  if (str == NULL)
    {
      return NULL;
    }

  while ((tmp_str = strpbrk(tmp_str, delim)) != NULL)
    {
      nb_prefixes ++; tmp_str ++;
    }

  res_list =
    (char **)malloc((nb_prefixes + 1) * sizeof(char *));

  tmp_str = strtok_r(str, delim, &saveptr);
  while (tmp_str != NULL)
    {
      res_list[index++] = tmp_str;
      tmp_str = strtok_r(NULL, delim, &saveptr);
    }
  res_list[index] = NULL;

  return res_list;
}


static int reloc_exec_init(Extension *extension)
{
  active = getenv("PROOT_ADDON_RELOC_EXEC") != NULL;
  verbose = getenv("PROOT_ADDON_RELOC_EXEC_VERBOSE") != NULL;
  reloc_dir = getenv("PROOT_ADDON_RELOC_EXEC_DIR");
  output_file = stderr;
  active = active && reloc_dir;

  if (active)
    {
      userdef_ignored_prefixes =
	str_to_list(getenv("PROOT_ADDON_RELOC_EXEC_IGNORED"));
      handled_prefixes =
	str_to_list(getenv("PROOT_ADDON_RELOC_EXEC_PREFIXES"));

      ignored_pathes = cec_hash_new
	(cec_hash_string, cec_compare_strings, cec_free_element);
      assert(ignored_pathes != NULL);

      translated_pathes = cec_hash_new
	(cec_hash_string, cec_compare_strings, cec_free_element);
      assert(translated_pathes != NULL);

      return reloc_exec_mkdir(reloc_dir);
    }
  return 0;
}


static int reloc_exec_enter(Extension *extension, intptr_t data1)
{
  if (!active) return 0;

  char *translated = *(char **)data1, *relocated;
  int reloc_dir_len = strlen(reloc_dir);
  int translated_len = strlen(translated);
  int status, stat_status;
  struct stat statbuf;

  VERBOSE("RELOC_EXEC_ENTER [%s]\n", translated);

  /* handle already relocated path */
  if (strncmp(translated, reloc_dir, reloc_dir_len) == 0)
    {
      char detranslated[PATH_MAX], *detranslated_ptr = detranslated;
      strcpy(detranslated, translated + reloc_dir_len);
      /* only copy/create relocated file/dir. do not relocate again */
      return reloc_exec_enter(extension, (intptr_t)&detranslated_ptr);
    }

  /* skip pathes starting by one of the ignored prefixes */
  if (cec_hash_has_element(ignored_pathes, translated))
    {
      return 0;
    }

  if(in_prefix_list(predef_ignored_prefixes, translated) ||
     in_prefix_list(userdef_ignored_prefixes, translated))
    {
      cec_hash_add_element(ignored_pathes, strdup(translated));
      return 0;
    }

  /* skip pathes not starting by one of the relocation prefixes */
  if(handled_prefixes && !in_prefix_list(handled_prefixes, translated))
    {
      cec_hash_add_element(ignored_pathes, strdup(translated));
      return 0;
    }

  stat_status = stat(translated, &statbuf);

  if (!(stat_status || statbuf.st_mode & (S_IFDIR | S_IFREG)))
    {
      /* skip when not a file or a directory */
      cec_hash_add_element(ignored_pathes, strdup(translated));
      return 0;
    }

  /* relocate translated path by adding reloc_dir prefix */
  assert((translated_len + reloc_dir_len + 1) <= PATH_MAX);
  relocated = translated;
  memmove(translated + reloc_dir_len, translated, translated_len + 1);
  memcpy(translated, reloc_dir, reloc_dir_len);
  translated = translated + reloc_dir_len;

  VERBOSE("translated: %s\n", translated);
  VERBOSE(" relocated: %s\n", relocated);

  if (cec_hash_has_element(translated_pathes, relocated))
    {
      return 0;
    }
  cec_hash_add_element(translated_pathes, strdup(relocated));

  if (stat_status)
    {
      return 0;
    }
  else if (statbuf.st_mode & S_IFDIR)
    {
      status = reloc_exec_mkdir(relocated);
      return status;
    }
  else if(statbuf.st_mode & S_IFREG)
    {
      status = reloc_exec_copyfile(translated, reloc_dir);
      return status;
    }

  return 0;
}


static int reloc_exec_callback(Extension *extension, ExtensionEvent event,
			    intptr_t data1, intptr_t data2)
{

  switch (event)
    {
    case INITIALIZATION:
      return reloc_exec_init(extension);

    case TRANSLATED_PATH:
      return reloc_exec_enter(extension, data1);

    case INHERIT_PARENT:
      return 0;

    default:
      break;
    }

  return 0;
}

