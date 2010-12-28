/* CHMDump was written by Matthew T. Russotto, who hereby
   places this source file in the public domain. */

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include "chmlib.h"

static void  usage(char *pname)
{
  fprintf(stderr, "Usage: %s chmfile outdir\n", pname);
}

main(int argc, char *argv[])
{
  ubyte *buf;
  ulong length;
  chmfile *c;
  char *infname;
  char *outdirname;
  int i;
  ubyte *outbuf;
  int namelen;
  char *rel;
  char dirname[PATH_MAX];
  int err;
  FILE *f;

  if (3 != argc) {
    usage(argv[0]);
    exit(-1);
  }

  infname = argv[1];
  outdirname = argv[2];
  err = mkdir(outdirname, 0777);
  if (err) {
    if (errno == EEXIST) {
      fprintf(stderr, "Directory %s already exists; you must specify a new directory.\n", outdirname);
    }
    else
      perror("mkdir");
    exit(-1);
  }

  c = chm_openfile(infname);

  if (!c) {
    perror("chm_openfile");
    exit(-1);
  }

  err = chdir(outdirname);
  if (err != 0) {
    perror("chdir");
    rmdir(outdirname);
    exit(-1);
  }
  
  for (i = 0; i < c->dir->nentries; i++) {
    if (c->dir->entry[i].name[0] == '/') {
      namelen = strlen(c->dir->entry[i].name);
      if (namelen == 1) continue; /* skip the slash */
      rel = c->dir->entry[i].name + 1;
      if (c->dir->entry[i].name[namelen-1] == '/') {
	strncpy(dirname, rel, namelen-2);
	dirname[namelen-2] = 0;
	err = mkdir(dirname, 0777);
	if (err != 0) {
	  fprintf(stderr, "mkdir failed on %s\n", dirname);
	  perror("mkdir");
	  exit(-1);
	}
      }
      else {
	chm_getfile(c, c->dir->entry[i].name, &length, &outbuf);
	f = fopen(rel, "wb");
	if (!f) {
	  fprintf(stderr, "Couldn't open %s\n", rel);
	  perror("fopen");
	  exit(-1);
	}
	fwrite(outbuf, 1, length, f);
	fclose(f);
	if (outbuf) free(outbuf);
      }
    }
  }
  chm_close(c);
}
