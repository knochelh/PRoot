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
    "/dev", "/sys", "/proc"
  };

static char **userdef_ignored_prefixes;


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


static int in_predef_prefix_list(char *str)
{
  int i;
  for (i = 0; i < (sizeof(predef_ignored_prefixes) / sizeof(char *)); i++)
    {
      if (!strncmp(str, predef_ignored_prefixes[i],
		   strlen(predef_ignored_prefixes[i])))
	return 1;
    }
  return 0;
}

static int in_userdef_prefix_list(char *str)
{
  int i;
  if (userdef_ignored_prefixes == NULL)
    return 0;
  for (i = 0; userdef_ignored_prefixes[i]; i++)
    {
      if (!strncmp(str, userdef_ignored_prefixes[i],
		   strlen(userdef_ignored_prefixes[i])))
	return 1;
    }
  return 0;
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
      char *userdef_ignored_prefixes_str =
	getenv("PROOT_ADDON_RELOC_EXEC_IGNORED");
      if (userdef_ignored_prefixes_str)
	{
	  char *delim = ",";
	  int index = 0, nb_prefixes = 1;
	  char *saveptr, *tmp_str = userdef_ignored_prefixes_str;
	  while ((tmp_str = strpbrk(tmp_str, delim)) != NULL)
	    {
	      nb_prefixes ++; tmp_str ++;
	    }
	  userdef_ignored_prefixes =
	    (char **)malloc((nb_prefixes + 1) * sizeof(char *));

	  tmp_str = strtok_r(userdef_ignored_prefixes_str, delim, &saveptr);
	  while (tmp_str != NULL)
	    {
	      userdef_ignored_prefixes[index++] = tmp_str;
	      tmp_str = strtok_r(NULL, delim, &saveptr);
	    }
	  userdef_ignored_prefixes[index] = NULL;
	}

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


static int reloc_exec_fini(Extension *extension)
{
  return 0;
}


static int reloc_exec_enter(Extension *extension, intptr_t data1)
{
  int status;

  if (!active) return 0;

  char *translated = *(char**)data1, *relocated;
  int reloc_dir_len = strlen(reloc_dir);
  int translated_len = strlen(translated);
  int stat_status;
  struct stat statbuf;

  VERBOSE("translated: %s\n", translated);

  if (cec_hash_has_element(ignored_pathes, translated))
    {
      VERBOSE(" a-ignored: %s\n", translated);
      return 0;
    }

  /* skip already relocated path */
  if (strncmp(translated, reloc_dir, reloc_dir_len) == 0)
    {
      VERBOSE("   ignored: %s\n", translated);
      cec_hash_add_element(ignored_pathes, strdup(translated));
      return 0;
    }

  /* skip pathes starting by one of the predefined ignored prefixes */
  if (in_predef_prefix_list(translated))
    {
      VERBOSE("   ignored: %s\n", translated);
      cec_hash_add_element(ignored_pathes, strdup(translated));
      return 0;
    }

  /* skip pathes starting by one of the userdefined ignored prefixes */
  if (in_userdef_prefix_list(translated))
    {
      VERBOSE("   ignored: %s\n", translated);
      cec_hash_add_element(ignored_pathes, strdup(translated));
      return 0;
    }

  stat_status = stat(translated, &statbuf);

  if (!(stat_status || statbuf.st_mode & (S_IFDIR | S_IFREG)))
    {
      /* skip when not a file or a directory */
      VERBOSE("   ignored: %s\n", translated);
      cec_hash_add_element(ignored_pathes, strdup(translated));
      return 0;
    }

  /* relocate translated path by adding reloc_dir prefix */
  assert((translated_len + reloc_dir_len + 1) <= PATH_MAX);
  relocated = translated;
  memmove(translated + reloc_dir_len, translated, translated_len + 1);
  memcpy(translated, reloc_dir, reloc_dir_len);
  translated = translated + reloc_dir_len;
  VERBOSE(" relocated: %s\n", relocated);

  if (cec_hash_has_element(translated_pathes, relocated))
    {
      VERBOSE(" a-relocat: %s\n", translated);
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

    case REMOVED:
      return reloc_exec_fini(extension);

    case TRANSLATED_PATH:
      return reloc_exec_enter(extension, data1);

    default:
      break;
    }

  return 0;
}

