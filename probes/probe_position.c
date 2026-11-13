/*
 * vmsnotify probe: does a read position (file spec with version, FID,
 * RFA of the last record handled) saved by one process let a NEW
 * process continue reading the same file? (design.md, D8)
 *
 *   probe_position create FILE N
 *   probe_position append FILE N
 *   probe_position save   FILE STATE
 *   probe_position resume STATE [EXPECT_AFTER]
 *   probe_position resume-latest STATE
 *
 * save opens FILE exactly as vmsotel's vms_logs.c r_open does: FAC=GET,
 * SHR=GET|PUT|UPD, ROP=NLK|RRL, a NAM block for the resultant name.
 * Nothing is ever written except by create/append, which are for the
 * test file only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <rms.h>
#include <rmsdef.h>
#include <starlet.h>

#define REC_MAX 8192
#define RSS_MAX 255
#define HEAD    48

typedef struct {
    struct FAB fab;
    struct RAB rab;
    struct NAM nam;
    char name[RSS_MAX + 1];
    char rsa[RSS_MAX + 1];
    char esa[RSS_MAX + 1];
    int open;
} rfile;

static unsigned char rec[REC_MAX];

typedef struct {
    unsigned short rfa[3];
    unsigned short len;
    unsigned char head[HEAD];
    unsigned short headlen;
} vpos;

static void fid_of(const rfile *f, unsigned int fid[3])
{
    fid[0] = f->nam.nam$w_fid_num;
    fid[1] = f->nam.nam$w_fid_seq;
    fid[2] = f->nam.nam$b_fid_rvn | ((unsigned int) f->nam.nam$b_fid_nmx << 8);
}

static unsigned int r_open(rfile *f, const char *name, int shared_read)
{
    unsigned int st;

    memset(f, 0, sizeof *f);
    strncpy(f->name, name, sizeof f->name - 1);
    f->fab = cc$rms_fab;
    f->nam = cc$rms_nam;
    f->fab.fab$l_fna = f->name;
    f->fab.fab$b_fns = (unsigned char) strlen(f->name);
    f->fab.fab$b_fac = shared_read ? FAB$M_GET : FAB$M_PUT;
    f->fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD;
    f->fab.fab$l_nam = &f->nam;
    f->nam.nam$l_rsa = f->rsa;
    f->nam.nam$b_rss = RSS_MAX;
    f->nam.nam$l_esa = f->esa;
    f->nam.nam$b_ess = RSS_MAX;
    st = sys$open((void *) &f->fab);
    if (!(st & 1))
        return st;
    f->rsa[f->nam.nam$b_rsl] = '\0';
    f->rab = cc$rms_rab;
    f->rab.rab$l_fab = &f->fab;
    f->rab.rab$l_ubf = (char *) rec;
    f->rab.rab$w_usz = REC_MAX - 1;
    f->rab.rab$l_rop = shared_read ? (RAB$M_NLK | RAB$M_RRL) : RAB$M_EOF;
    f->rab.rab$b_rac = RAB$C_SEQ;
    st = sys$connect((void *) &f->rab);
    if (!(st & 1)) {
        sys$close((void *) &f->fab);
        return st;
    }
    f->open = 1;
    return st;
}

static void r_close(rfile *f)
{
    if (f->open)
        sys$close((void *) &f->fab);
    f->open = 0;
}

static unsigned int r_get(rfile *f, vpos *p)
{
    unsigned int st = sys$get((void *) &f->rab);
    unsigned short n;

    if (!(st & 1))
        return st;
    n = f->rab.rab$w_rsz;
    if (p) {
        memcpy(p->rfa, f->rab.rab$w_rfa, sizeof p->rfa);
        p->len = n;
        p->headlen = n < HEAD ? n : HEAD;
        memcpy(p->head, rec, p->headlen);
    }
    return st;
}

static void print_text(const rfile *f)
{
    unsigned short i, n = f->rab.rab$w_rsz;

    if (n > 100)
        n = 100;
    for (i = 0; i < n; i++)
        putchar(isprint(rec[i]) ? rec[i] : '.');
    putchar('\n');
}

static void hexstr(const unsigned char *p, unsigned short n, char *out)
{
    unsigned short i;

    for (i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02X", p[i]);
    out[2 * n] = '\0';
}

static int unhex(const char *h, unsigned char *out, unsigned short max)
{
    int n = 0;
    unsigned int v;

    while (h[0] && h[1] && n < max) {
        if (sscanf(h, "%2x", &v) != 1)
            break;
        out[n++] = (unsigned char) v;
        h += 2;
    }
    return n;
}

static int make_file(const char *name, int n, int create)
{
    rfile f;
    unsigned int st;
    int i, base = 0;
    char buf[80];

    if (create) {
        memset(&f, 0, sizeof f);
        strncpy(f.name, name, sizeof f.name - 1);
        f.fab = cc$rms_fab;
        f.nam = cc$rms_nam;
        f.fab.fab$l_fna = f.name;
        f.fab.fab$b_fns = (unsigned char) strlen(f.name);
        f.fab.fab$b_fac = FAB$M_PUT;
        f.fab.fab$b_shr = FAB$M_SHRGET | FAB$M_SHRPUT | FAB$M_SHRUPD;
        f.fab.fab$b_rfm = FAB$C_VAR;
        f.fab.fab$b_rat = FAB$M_CR;
        f.fab.fab$b_org = FAB$C_SEQ;
        f.fab.fab$l_nam = &f.nam;
        f.nam.nam$l_rsa = f.rsa;
        f.nam.nam$b_rss = RSS_MAX;
        st = sys$create((void *) &f.fab);
        if (!(st & 1)) {
            printf("FAIL create %s status=%08X\n", name, st);
            return 1;
        }
        f.rsa[f.nam.nam$b_rsl] = '\0';
        f.rab = cc$rms_rab;
        f.rab.rab$l_fab = &f.fab;
        f.rab.rab$l_rop = RAB$M_EOF;
        st = sys$connect((void *) &f.rab);
        if (!(st & 1)) {
            printf("FAIL connect status=%08X\n", st);
            return 1;
        }
        f.open = 1;
    } else {
        st = r_open(&f, name, 0);
        if (!(st & 1)) {
            printf("FAIL open %s status=%08X\n", name, st);
            return 1;
        }
        /* count existing records so numbering continues */
        {
            rfile g;
            if ((r_open(&g, name, 1) & 1)) {
                while (r_get(&g, NULL) & 1)
                    base++;
                r_close(&g);
            }
        }
    }
    for (i = 1; i <= n; i++) {
        int len = sprintf(buf, "RECORD %05d %s", base + i,
                          create ? "created" : "appended");
        f.rab.rab$l_rbf = buf;
        f.rab.rab$w_rsz = (unsigned short) len;
        st = sys$put((void *) &f.rab);
        if (!(st & 1)) {
            printf("FAIL put status=%08X\n", st);
            r_close(&f);
            return 1;
        }
    }
    r_close(&f);
    printf("%s %s: %d records, now %d; resultant %s\n",
           create ? "created" : "appended", name, n, base + n, f.rsa);
    return 0;
}

static int do_save(const char *name, const char *state)
{
    rfile f;
    vpos ring[3], *p;
    unsigned long n = 0;
    unsigned int st, fid[3];
    FILE *out;
    char hex[2 * HEAD + 1];

    st = r_open(&f, name, 1);
    if (!(st & 1)) {
        printf("FAIL save open %s status=%08X\n", name, st);
        return 1;
    }
    printf("save: opened %s\n  resultant: %s\n", name, f.rsa);
    fid_of(&f, fid);
    printf("  fid: (%u,%u,%u)\n", fid[0], fid[1], fid[2]);
    while ((st = r_get(&f, &ring[n % 3])) & 1)
        n++;
    printf("  read %lu records, ended with status=%08X (%s)\n", n, st,
           st == RMS$_EOF ? "RMS$_EOF" : "NOT EOF");
    r_close(&f);
    if (n < 3) {
        printf("FAIL save: fewer than 3 records\n");
        return 1;
    }
    p = &ring[(n - 3) % 3];
    hexstr(p->head, p->headlen, hex);
    out = fopen(state, "w");
    if (!out) {
        printf("FAIL save: cannot write %s\n", state);
        return 1;
    }
    fprintf(out, "SPEC=%s\n", f.rsa);
    fprintf(out, "FID=%u,%u,%u\n", fid[0], fid[1], fid[2]);
    fprintf(out, "RFA=%04X,%04X,%04X\n", p->rfa[0], p->rfa[1], p->rfa[2]);
    fprintf(out, "LEN=%u\n", p->len);
    fprintf(out, "HEAD=%s\n", hex);
    fclose(out);
    printf("  saved record %lu of %lu: rfa=%04X%04X%04X len=%u head=%s\n",
           n - 2, n, p->rfa[0], p->rfa[1], p->rfa[2], p->len, hex);
    printf("PASS save wrote %s\n", state);
    return 0;
}

typedef struct {
    char spec[RSS_MAX + 1];
    unsigned int fid[3];
    vpos pos;
} saved;

static int load_state(const char *state, saved *s)
{
    FILE *in = fopen(state, "r");
    char line[600], hex[2 * HEAD + 8];
    unsigned int a, b, c, len;
    int have = 0;

    if (!in) {
        printf("FAIL cannot read state %s\n", state);
        return 0;
    }
    memset(s, 0, sizeof *s);
    while (fgets(line, sizeof line, in)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "SPEC=", 5) == 0) {
            strncpy(s->spec, line + 5, RSS_MAX);
            have |= 1;
        } else if (sscanf(line, "FID=%u,%u,%u", &a, &b, &c) == 3) {
            s->fid[0] = a; s->fid[1] = b; s->fid[2] = c;
            have |= 2;
        } else if (sscanf(line, "RFA=%x,%x,%x", &a, &b, &c) == 3) {
            s->pos.rfa[0] = (unsigned short) a;
            s->pos.rfa[1] = (unsigned short) b;
            s->pos.rfa[2] = (unsigned short) c;
            have |= 4;
        } else if (sscanf(line, "LEN=%u", &len) == 1) {
            s->pos.len = (unsigned short) len;
            have |= 8;
        } else if (strncmp(line, "HEAD=", 5) == 0) {
            strncpy(hex, line + 5, sizeof hex - 1);
            hex[sizeof hex - 1] = '\0';
            s->pos.headlen = (unsigned short) unhex(hex, s->pos.head, HEAD);
            have |= 16;
        }
    }
    fclose(in);
    if (have != 31) {
        printf("FAIL state file %s incomplete (%d)\n", state, have);
        return 0;
    }
    return 1;
}

static int do_resume(const char *state, const char *expect, int latest)
{
    saved s;
    rfile f;
    unsigned int st, fid[3];
    int bad = 0, same;
    unsigned long after = 0;
    vpos first;
    char *semi;

    if (!load_state(state, &s))
        return 1;
    printf("%s: saved spec %s\n  saved fid (%u,%u,%u) rfa %04X%04X%04X\n",
           latest ? "resume-latest" : "resume", s.spec, s.fid[0], s.fid[1],
           s.fid[2], s.pos.rfa[0], s.pos.rfa[1], s.pos.rfa[2]);
    if (latest) {
        semi = strrchr(s.spec, ';');
        if (semi)
            *semi = '\0';
        printf("  opening without version: %s\n", s.spec);
    }
    st = r_open(&f, s.spec, 1);
    if (!(st & 1)) {
        printf("FAIL open status=%08X (%s)\n", st,
               st == RMS$_FNF ? "RMS$_FNF" :
               st == RMS$_DNF ? "RMS$_DNF" : "other");
        return 1;
    }
    printf("PASS open status=%08X resultant %s\n", st, f.rsa);
    fid_of(&f, fid);
    same = fid[0] == s.fid[0] && fid[1] == s.fid[1] && fid[2] == s.fid[2];
    printf("  opened fid (%u,%u,%u)\n", fid[0], fid[1], fid[2]);
    if (same)
        printf("PASS fid matches the saved one\n");
    else {
        printf("%s fid differs: this is a DIFFERENT FILE (newer version)\n",
               latest ? "DETECTED" : "FAIL");
        if (!latest)
            bad = 1;
    }
    if (latest) {
        r_close(&f);
        return bad;
    }
    memcpy(f.rab.rab$w_rfa, s.pos.rfa, sizeof s.pos.rfa);
    f.rab.rab$b_rac = RAB$C_RFA;
    st = sys$get((void *) &f.rab);
    f.rab.rab$b_rac = RAB$C_SEQ;
    if (!(st & 1)) {
        printf("FAIL get by RFA status=%08X\n", st);
        r_close(&f);
        return 1;
    }
    printf("PASS get by RFA status=%08X, %u bytes: ", st, f.rab.rab$w_rsz);
    print_text(&f);
    if (f.rab.rab$w_rsz == s.pos.len &&
        memcmp(rec, s.pos.head, s.pos.headlen) == 0)
        printf("PASS record matches the saved length and first %u bytes\n",
               s.pos.headlen);
    else {
        printf("FAIL record differs from the saved one (len %u vs %u)\n",
               f.rab.rab$w_rsz, s.pos.len);
        bad = 1;
    }
    while ((st = r_get(&f, after == 0 ? &first : NULL)) & 1) {
        if (after == 0) {
            printf("  first record after it: ");
            print_text(&f);
        }
        after++;
    }
    printf("  %lu records followed, ended with status=%08X (%s)\n", after, st,
           st == RMS$_EOF ? "RMS$_EOF" : "NOT EOF");
    if (st != RMS$_EOF)
        bad = 1;
    if (expect) {
        if ((unsigned long) atol(expect) == after)
            printf("PASS %lu records followed, as expected\n", after);
        else {
            printf("FAIL expected %s records after, got %lu\n", expect, after);
            bad = 1;
        }
    }
    r_close(&f);
    return bad;
}

int main(int argc, char **argv)
{
    if (argc >= 4 && strcmp(argv[1], "create") == 0)
        return make_file(argv[2], atoi(argv[3]), 1);
    if (argc >= 4 && strcmp(argv[1], "append") == 0)
        return make_file(argv[2], atoi(argv[3]), 0);
    if (argc >= 4 && strcmp(argv[1], "save") == 0)
        return do_save(argv[2], argv[3]);
    if (argc >= 3 && strcmp(argv[1], "resume") == 0)
        return do_resume(argv[2], argc >= 4 ? argv[3] : NULL, 0);
    if (argc >= 3 && strcmp(argv[1], "resume-latest") == 0)
        return do_resume(argv[2], NULL, 1);
    fprintf(stderr, "usage: probe_position create|append FILE N | save FILE STATE"
            " | resume STATE [N] | resume-latest STATE\n");
    return 2;
}
