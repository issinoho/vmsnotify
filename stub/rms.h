/*
 * Linux stub of the RMS structures probe_logs and vms_logs.c use: only
 * those fields, with arbitrary codes. The stub's sys$open maps the
 * operator log and the audit journal to files under build/ and makes
 * them if missing; version ;N of each is its own file.
 */
#ifndef STUB_RMS_H
#define STUB_RMS_H

/* The file identification is three words that also have names of their
   own, as in VMS's nam.h (where the overlay is spelled the same way:
   C99 has no anonymous unions). The stub's is the file's inode. */
struct NAM {
    char *nam$l_rsa;
    unsigned char nam$b_rss;
    unsigned char nam$b_rsl;
    union {
        unsigned short nam$w_fid[3];
        struct {
            unsigned short nam$w_fid_num;
            unsigned short nam$w_fid_seq;
            unsigned char nam$b_fid_rvn;
            unsigned char nam$b_fid_nmx;
        } nam$r_fid_fields;
    } nam$r_fid_overlay;
};
#define nam$w_fid     nam$r_fid_overlay.nam$w_fid
#define nam$w_fid_num nam$r_fid_overlay.nam$r_fid_fields.nam$w_fid_num
#define nam$w_fid_seq nam$r_fid_overlay.nam$r_fid_fields.nam$w_fid_seq
#define nam$b_fid_rvn nam$r_fid_overlay.nam$r_fid_fields.nam$b_fid_rvn
#define nam$b_fid_nmx nam$r_fid_overlay.nam$r_fid_fields.nam$b_fid_nmx

struct FAB {
    char *fab$l_fna;
    struct NAM *fab$l_nam;
    unsigned char fab$b_fns;
    unsigned char fab$b_fac;
    unsigned char fab$b_shr;
    unsigned char fab$b_rfm;
    unsigned char fab$b_rat;
    unsigned short fab$w_mrs;
    void *stub_fp;
    int stub_kind;
};

struct RAB {
    struct FAB *rab$l_fab;
    char *rab$l_ubf;
    unsigned short rab$w_usz;
    unsigned short rab$w_rsz;
    char *rab$l_rbf;
    unsigned int rab$l_rop;
    unsigned char rab$b_rac;
    unsigned short rab$w_rfa[3];
};

extern struct FAB cc$rms_fab;
extern struct RAB cc$rms_rab;
extern struct NAM cc$rms_nam;

#define FAB$M_GET    0x02
#define FAB$M_SHRGET 0x02
#define FAB$M_SHRPUT 0x01
#define FAB$M_SHRUPD 0x08
#define FAB$C_UDF   0
#define FAB$C_FIX   1
#define FAB$C_VAR   2
#define FAB$C_VFC   3
#define FAB$C_STM   4
#define FAB$C_STMLF 5
#define FAB$C_STMCR 6
#define RAB$C_SEQ   0
#define RAB$C_RFA   2
#define RAB$M_NLK   0x00200000
#define RAB$M_RRL   0x00100000

#endif
