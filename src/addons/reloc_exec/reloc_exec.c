/**
 * Relocate execution in another directory
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <dirent.h>
#include <libgen.h>

#include "cec_lib.h"
#include "path/path.h"
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
static cec_hash_t *getdented_dirs = NULL;

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
  if (getdented_dirs != NULL)
    cec_hash_del(getdented_dirs);
}


/* TODO: replace system() calls */

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

  {
    struct stat statbuf;
    char dstfile[PATH_MAX];

    status = snprintf(dstfile, PATH_MAX, "%s/%s", dstdir, src);
    if (status < 0)
      return status;
    status = stat(dstfile, &statbuf);
    /* do not overwrite unless empty file */
    /* (this should be ok as it is the 1st relocation) */
    if (!status && statbuf.st_mode & S_IFREG && statbuf.st_size != 0)
      return 0;
  }

  status = snprintf(command, ARG_MAX,
		    "/bin/cp --preserve --parents %s %s",
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

      getdented_dirs = cec_hash_new
	(cec_hash_string, cec_compare_strings, cec_free_element);
      assert(getdented_dirs != NULL);

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
      /* no such file or directory */
      /* create parent directory in reloc_dir if existing in srcdir */
      char *parent = dirname(strdup(translated));
      stat_status = stat(parent, &statbuf);
      if ((!stat_status) && (statbuf.st_mode & S_IFDIR))
	{
	  status = reloc_exec_mkdir(dirname(strdup(relocated)));
	  return status;
	}
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

static int reloc_exec_getdents(Extension *extension)
{
  if (!active) return 0;

  char path[PATH_MAX], command[ARG_MAX], *detranslated;
  Tracee *tracee = TRACEE(extension);
  int fd = (int)peek_reg(tracee, ORIGINAL, SYSARG_1);
  int status, reloc_dir_len = strlen(reloc_dir);
  DIR *dir_ptr;

  status = readlink_proc_pid_fd(tracee->pid, fd, path);
  if (status)
    return status;

  if (strncmp(path, reloc_dir, reloc_dir_len) != 0)
    return 0;  /* non-relocated path */

  detranslated = &path[0] + reloc_dir_len;
  if (cec_hash_has_element(getdented_dirs, detranslated))
    return 0;  /* fake dirent already created */
  cec_hash_add_element(getdented_dirs, strdup(detranslated));

  dir_ptr = opendir (detranslated);
  if (dir_ptr == NULL)
    return 0;

  VERBOSE("   DIRENT for directory: %s\n", detranslated);

  /* TODO: take care of access rights and access dates */
  while (1)
    {
      struct dirent *dir_entry = readdir(dir_ptr);
      if (dir_entry == NULL) break;

      /* TODO: should be optimized (useless touch/mkdir system calls) */
      switch (dir_entry->d_type)
	{
	case DT_REG:
	case DT_LNK:
	  status = snprintf
	    (command, ARG_MAX, "/usr/bin/touch %s/%s",
	     path, dir_entry->d_name);
	  if (status < 0) break;
	  VERBOSE("   DIRENT command: %s\n", command);
	  status = system(command);  /* ignore status */
	  break;

	case DT_DIR:
	    if (dir_entry->d_name[0] == '.')
	      break; /* relative path (., ..) */
	    status = snprintf
	      (command, ARG_MAX, "/bin/mkdir -p %s/%s",
	       path, dir_entry->d_name);
	    if (status < 0) break;
	    VERBOSE("   DIRENT command: %s\n", command);
	    status = system(command);  /* ignore status */
	    break;

	default: /* DT_BLK, DT_CHR, DT_FIFO, DT_SOCK, DT_UNKNOWN */
	  break;
	}
    }

  (void)closedir(dir_ptr);

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

    case SYSCALL_ENTER_START:
      switch (get_sysnum(TRACEE(extension), ORIGINAL))
	{
	case PR_getdents:
	case PR_getdents64:
	  return reloc_exec_getdents(extension);
	default:
	  break;
	}
      return 0;

    case INHERIT_PARENT:
      return 0;

    default:
      break;
    }

  return 0;
}

