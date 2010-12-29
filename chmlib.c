/* CHMtools v0.1 */
/* Copyright 2001 Matthew T. Russotto */
/*  
    This file is part of CHMtools

    CHMtools is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
    
    CHMtools is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdlib.h>
#include "chmlib.h"
#include "fixendian.h"

#define FILELEN_HSECT 0
#define DIR_HSECT 1
#define CONTENT_FORMAT "::DataSpace/Storage/%s/Content"
#define CONTROLDATA_FORMAT "::DataSpace/Storage/%s/ControlData"
#define SPANINFO_FORMAT "::DataSpace/Storage/%s/SpanInfo"
#define LIST_FORMAT "::DataSpace/Storage/%s/Transform/List"
#define INSTANCEDATA_FORMAT "::DataSpace/Storage/%s/Transform/%s/InstanceData/"
#define RT_FORMAT "::DataSpace/Storage/%s/Transform/%s/InstanceData/ResetTable"
#define TRANSFORM_FORMAT "::Transform/%s/"
#define NAMELIST "::DataSpace/NameList"

#ifdef DEBUG
#define DPRINTF fprintf
#else
#define DPRINTF while (0) fprintf
#endif

static void 
get_guid(ubyte *buf, guid_t *guid)
{
    memcpy(guid, buf, sizeof(guid_t));
    FIXENDIAN32(guid->guid1);
    FIXENDIAN16(guid->guid2[0]);
    FIXENDIAN16(guid->guid2[1]);
}

static void
make_guid_string(guid_t *guid, char *s)
{
    sprintf(s, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
	    guid->guid1, guid->guid2[0], guid->guid2[1],
	    guid->guid3[0], guid->guid3[1], guid->guid3[2], guid->guid3[3],
	    guid->guid3[4], guid->guid3[5], guid->guid3[6], guid->guid3[7]);
}

static void guid_fix_endian(guid_t *guid) 
{
  FIXENDIAN32(guid->guid1);
  FIXENDIAN16(guid->guid2[0]);
  FIXENDIAN16(guid->guid2[1]);
}

static int readheader(chmfile *c)
{
  int ret;

  fseek(c->cf, 0, SEEK_SET);
  ret = fread(&c->ch, sizeof(chmheader), 1, c->cf);
  guid_fix_endian(&c->ch.unk_guid1);
  guid_fix_endian(&c->ch.unk_guid2);
  FIXENDIAN32(c->ch.tot_hdrlen);
  fseek(c->cf, 0x58, SEEK_SET);
  fread(&c->content_offset, sizeof(c->content_offset), 1, c->cf);
  FIXENDIAN32(c->content_offset);

#ifdef DEBUG
  {
    char str[40];
    fprintf(stderr, "itsf: %-4.4s\n", c->ch.itsf);
    fprintf(stderr, "tot_hdrlen: %08x\n", c->ch.tot_hdrlen);
    fprintf(stderr, "content_offset: %08x\n", c->content_offset);
    make_guid_string(&c->ch.unk_guid1, str);
    fprintf(stderr, "guid1: %s\n", str);
    make_guid_string(&c->ch.unk_guid2, str);
    fprintf(stderr, "guid2: %s\n", str);
  }
#endif

  fseek(c->cf, sizeof(chmheader), SEEK_SET);
  return ret;
}

static int readhsectable(chmfile *c)
{
  int i;
  int result;
  int nhsecs = 2;

  result = fread(c->hs, nhsecs, sizeof(hsecentry), c->cf);
  for (i = 0; i < nhsecs; i++) {
    FIXENDIAN32(c->hs[i].offset);
    FIXENDIAN32(c->hs[i].length);
  }
  return result;
}

static int readdirheader(chmfile *c)
{
  int ret;
  int result;

  fseek(c->cf, c->hs[DIR_HSECT].offset, SEEK_SET);
  result = fread(&c->dh, sizeof(dirheader), 1, c->cf);
  FIXENDIAN32(c->dh.chunksize);
  FIXENDIAN32(c->dh.indexchunk);
  FIXENDIAN32(c->dh.ndirchunks);
  FIXENDIAN32(c->dh.firstpmglchunk);
  FIXENDIAN32(c->dh.lastpmglchunk);
  FIXENDIAN32(c->dh.length);
  guid_fix_endian(&c->dh.unk_guid1);
#ifdef DEBUG
  {
    char str[40];
    fprintf(stderr, "directory header length: %x\n", c->dh.length);
    fprintf(stderr, "chunksize: %x\n", c->dh.chunksize);
    fprintf(stderr, "ndirchunks: %x\n", c->dh.ndirchunks);
    fprintf(stderr, "indexchunk: %x\n", c->dh.indexchunk);
    fprintf(stderr, "firstpmglchunk: %x\n", c->dh.firstpmglchunk);
    fprintf(stderr, "lastpmglchunk: %x\n", c->dh.lastpmglchunk);
    make_guid_string(&c->dh.unk_guid1, str);
    fprintf(stderr, "guid1: %s\n", str);
  }
#endif
  return result;
}

static ulong getencint(ubyte **p)
{
  ulong accum = 0;
  while ((**p) & 0x80) {
    accum = (accum << 7) | ((*(*p)++)&0x7F);
  }
  accum = (accum << 7) | (*(*p)++);
  return accum;
}

static int 
read_chm_dir(chmfile *c)
{
  int length;
  int bodylength;
  dirheader dh;
  ubyte *buf;
  ubyte *bufend;
  ubyte *p, *oldp;
  int namelen;
  int i;
  unsigned long section, offset, dlength;
  int nentries;
  int nchunks;
  pmglchunkheader pmglch;
  fpos_t chunkstart;
  
  readdirheader(c);
  chunkstart = ftell(c->cf);
  length = c->dh.chunksize * c->dh.ndirchunks;
  p = buf = malloc(length);
  bufend = buf;
  nchunks = 0;
  pmglch.next_chunk = 0;
  do {
    fseek(c->cf, chunkstart + pmglch.next_chunk * c->dh.chunksize, SEEK_SET);
    fread(&pmglch, sizeof(pmglch), 1, c->cf);
    FIXENDIAN32(pmglch.next_chunk);
    FIXENDIAN32(pmglch.prev_chunk);
    FIXENDIAN32(pmglch.quickreflen);
#ifdef DEBUG
    fprintf(stderr, "prev_chunk: %d\n", pmglch.prev_chunk);
    fprintf(stderr, "next_chunk: %d\n", pmglch.next_chunk);
    fprintf(stderr, "quickreflen: %x\n", pmglch.quickreflen);
#endif
    bodylength = c->dh.chunksize - sizeof(pmglch) - pmglch.quickreflen;
    fread(bufend, c->dh.chunksize - sizeof(pmglch) - pmglch.quickreflen, 1, c->cf);
    bufend += bodylength;
    nchunks++;
  }
  while ((pmglch.next_chunk != -1) && (nchunks < c->dh.ndirchunks));

  nentries = 0;
  
  while (p < bufend) {
    nentries++;
    namelen = getencint(&p);
    p += namelen;
    section = getencint(&p);
    offset = getencint(&p);
    dlength = getencint(&p);
  }

#ifdef DEBUG
  fprintf(stderr, "nentries (calculated): %x\n", nentries);
#endif
  
  c->dir = (chm_dir *)malloc(sizeof(chm_dir) + (nentries-1) * sizeof(direntry));
  p = buf;
  for (i = 0; i < nentries; i++) {
    oldp = p;
    memset(&c->dir->entry[i], 0, sizeof(direntry));
    namelen = *p++;
    memcpy(c->dir->entry[i].name, p, namelen);
    c->dir->entry[i].name[namelen] = 0;
    p+=namelen;
    c->dir->entry[i].section = getencint(&p);
    offset = getencint(&p);
    dlength = getencint(&p);
    c->dir->entry[i].offset = offset;
    c->dir->entry[i].length = dlength;
  }
#ifdef DEBUG
  for (i = 0; i < nentries; i++)
    fprintf(stderr, "%08lx %08lx %08lx %s\n", c->dir->entry[i].section,
	   c->dir->entry[i].offset, c->dir->entry[i].length,
	   c->dir->entry[i].name);
#endif
  c->dir->nentries = nentries;
  free(buf);
  return 0;
}

static direntry *getdirentry(char *name, chm_dir *dir)
{
  int i;

  for (i = 0; i < dir->nentries; i++)
	if (!strcmp(name, dir->entry[i].name))
	  return &dir->entry[i];
  return NULL;
}

int 
chm_getfile(chmfile *c, char *name, ulong *length,
		ubyte **outbuf)
{
  int i, j;
  int section;
  int offset = c->content_offset;
  direntry *de;
  FILE *addf;

  *length = 0;
  *outbuf = NULL;
  de = getdirentry(name, c->dir);
  DPRINTF(stderr, "Getting %s, de = %08x %s\n", name, de, de?de->name:"");
  if (!de)
      return -1;
  section = de->section;
  if (!c->cs || !c->cs->entry[section].iscompressed) {
      if (c->cs)
	  offset += c->cs->entry[section].offset;
      
      fseek(c->cf, de->offset + offset, SEEK_SET);
      *length = de->length;
      *outbuf = malloc(*length);
      fread(*outbuf, *length, 1, c->cf);
  }
  else if (c->cs->entry[section].cache) {
      *length = de->length;
      *outbuf = malloc(*length);
      memcpy(*outbuf,
	     c->cs->entry[section].cache + de->offset, *length);
  }
  else {
      char fname[4096];
      char guid_str[80];
      ubyte *lbp;
      ulong flength;
      ubyte *rtfile;
      ubyte *cdfile;
      ubyte *cbp;
      ubyte *contbuf;
      ubyte *secbuf;
      ulong rtindex;
      ulong uclength, clength;
      ulong contlength;
      ulong rtlength;
      ulong window_size;
      guid_t guid;
      int result;
      
      sprintf(fname, CONTROLDATA_FORMAT, c->cs->entry[section].name);

      /* get controldata */
      chm_getfile(c, fname, &flength, &cdfile);
      if (!cdfile)
	return -1;
      cbp = cdfile;
      if (memcmp(cbp+4, "LZXC", 4)) {
	fprintf(stderr, "Compression method not LZXC: %-4.4s\n", cbp+4);
	free(cdfile);
	return -1;
      }
      window_size = *(ulong *)(cbp+0x10);
      FIXENDIAN32(window_size);
      free(cdfile);
      switch(window_size) {
      case 1: window_size = 15; break;
      case 2: window_size = 16; break;
      case 4: window_size = 17; break;
      case 8: window_size = 18; break;
      case 0x10: window_size = 19; break;
      case 0x20: window_size = 20; break;
      case 0x40: window_size = 21; break;
      default:
	fprintf(stderr, "Window size invalid: %x\n", window_size);
	return -1;
      }
      strcpy(guid_str, "{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}");
      /* hardcoded string because transform list is broken */
      sprintf(fname, RT_FORMAT, c->cs->entry[section].name, guid_str);
      DPRINTF(stderr, "%s\n", fname);
      chm_getfile(c, fname, &rtlength, &rtfile);
      if (rtfile) {
	uclength = (rtfile[0x10]) | (rtfile[0x11]<<8) |
	  (rtfile[0x12]<<16) | (rtfile[0x13] << 24);
	
	clength = (rtfile[0x18]) | (rtfile[0x19]<<8) |
	  (rtfile[0x1a]<<16) | (rtfile[0x1b] << 24);
	DPRINTF(stderr, "uclength = %x, clength = %x\n", uclength, clength);
	sprintf(fname, CONTENT_FORMAT, c->cs->entry[section].name);
	chm_getfile(c,fname, &contlength, &contbuf);
	if (clength != contlength)
	  fprintf(stderr, "Warning: Content Length not same as Compressed Length (without padding) %d %d \n", contlength, clength);
	
	secbuf = malloc(uclength);
	/* uncompress it */
	LZXinit(window_size);
	result = LZXdecompress(contbuf, secbuf, clength, uclength);
	DPRINTF(stderr, "LZXResult: %d\n", result);
	free (contbuf);
	free(rtfile);
	if (result != 0) {
	  free(secbuf);
	  return -1;
	}
	/* and get the file we want out of it */
	DPRINTF(stderr, "offset = %x\n", de->offset);
	DPRINTF(stderr, "length = %x\n", de->length);
	*length = de->length;
	*outbuf = malloc(*length);
	memcpy(*outbuf, secbuf + de->offset, *length);
	//			free(secbuf);
	c->cs->entry[section].cache = secbuf;
	c->cs->entry[section].cachesize = uclength;
      }
  }
  return 0;
}

static int readcontsecs(chmfile *c)
{
  ulong length;
  ubyte *buf;
  ubyte *bufptr;
  int nentries;
  int nmlen;
  int i,j;
  char secname[4096];
  
  chm_getfile(c, NAMELIST, &length, &buf);
  nentries = buf[2] | (buf[3]<<8);
  c->cs = (contsecs *)malloc(sizeof (contsecs) + 
			     (nentries-1)*sizeof(contsecentry));
  c->cs->nentries = nentries;
  bufptr = buf + 4;
  for (i = 0; i < nentries; i++) {
	nmlen = bufptr[0] | (bufptr[1]<<8);
	bufptr += 2;
	for (j = 0; j <= nmlen; j++) {  /* this is the lazy way to do wide characters.  Since the string is pretty much always "MSCompressed" or "Uncompressed", it'll do */
	  c->cs->entry[i].name[j] = *bufptr; 
	  bufptr += 2; 
	}
	DPRINTF(stderr, "name = %s\n", c->cs->entry[i].name);
	if (!strcmp(c->cs->entry[i].name, "MSCompressed")) {
	  c->cs->entry[i].iscompressed = 1;
	  /* this is the wrong way to figure out if a file is compressed.
	     The real way is to examine the transform.  But the transform
	     list is corrupt in most (all?) CHM files, apparently because
	     the length was calculated in characters whereas the guid
	     is recorded as wide characters
	  */
	}
	else {
	  c->cs->entry[i].iscompressed = 0;
	}
	c->cs->entry[i].cache = NULL;
	sprintf(secname, CONTENT_FORMAT, c->cs->entry[i].name);
	c->cs->entry[i].offset = 0;
	if (i == 0) continue;
	for (j = 0; j < c->dir->nentries; j++) {
	  if (!strcmp(secname, c->dir->entry[j].name)) {
		c->cs->entry[i].offset = c->dir->entry[j].offset;
	  }
	}
  }
  free(buf);
  return 0;
}

chmfile *chm_openfile(char *fname)
{
    chmfile *result;
    FILE *f;
    
    f = fopen(fname, "rb");
    if (!f)
	return NULL;
    result = calloc(1, sizeof(chmfile));
    result->cf = f;
    readheader(result);
    readhsectable(result);
    read_chm_dir(result);
    readcontsecs(result);
    return result;
}

void
chm_close(chmfile *c)
{
  int i;

  fclose(c->cf);
  for (i = 0; i < c->cs->nentries; i++) {
    if (c->cs->entry[i].cache)
      free(c->cs->entry[i].cache);
  }
  free(c->cs);
  free(c->dir);
}
