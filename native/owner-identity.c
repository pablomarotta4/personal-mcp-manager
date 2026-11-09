#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <libproc.h>
#include <stdint.h>
#include <string.h>

/* All OS structures remain on the C side; the ABI returns fixed uint64 fields. */
int pm_peer(int fd, uint64_t *out) {
    pid_t pid = 0;
    struct xucred credentials = {0};
    socklen_t pid_size = sizeof(pid), credentials_size = sizeof(credentials);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &pid_size) != 0 ||
        pid_size != sizeof(pid) ||
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &credentials_size) != 0 ||
        credentials_size != sizeof(credentials) || credentials.cr_version != XUCRED_VERSION || pid < 2)
        return -1;
    out[0] = (uint64_t)pid;
    out[1] = (uint64_t)credentials.cr_uid;
    return 0;
}
int pm_identity(int pid, uint64_t *out, char *path, uint32_t capacity) {
    struct proc_bsdinfo info = {0};
    if (capacity < PROC_PIDPATHINFO_MAXSIZE ||
        proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info) ||
        proc_pidpath(pid, path, capacity) <= 0 || info.pbi_status == SZOMB ||
        (info.pbi_flags & PROC_FLAG_INEXIT) != 0)
        return -1;
    out[0] = info.pbi_pid;
    out[1] = info.pbi_ppid;
    out[2] = info.pbi_uid;
    out[3] = info.pbi_start_tvsec;
    out[4] = info.pbi_start_tvusec;
    out[5] = info.pbi_status;
    return 0;
}
uint32_t pm_path_capacity(void) { return PROC_PIDPATHINFO_MAXSIZE; }
uint32_t pm_zombie_status(void) { return SZOMB; }
uint32_t pm_ev_receipt(void) { return EV_RECEIPT; }

uint32_t pm_cwd_capacity(void) { return sizeof(((struct vnode_info_path *)0)->vip_path); }
int pm_cwd(int pid, uint64_t *out, char *path, uint32_t capacity) {
    struct proc_vnodepathinfo info = {0};
    if (proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, sizeof(info)) != sizeof(info) ||
        !S_ISDIR(info.pvi_cdir.vip_vi.vi_stat.vst_mode))
        return -1;
    size_t length = strnlen(info.pvi_cdir.vip_path, sizeof(info.pvi_cdir.vip_path));
    /* Reject the full-buffer boundary: it cannot prove a non-truncated path. */
    if (length == 0 || length >= sizeof(info.pvi_cdir.vip_path) - 1 ||
        info.pvi_cdir.vip_path[0] != '/' || capacity <= length)
        return -1;
    memcpy(path, info.pvi_cdir.vip_path, length + 1);
    out[0] = info.pvi_cdir.vip_vi.vi_stat.vst_dev;
    out[1] = info.pvi_cdir.vip_vi.vi_stat.vst_ino;
    return 0;
}
