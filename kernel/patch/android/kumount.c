/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2024 sekaiacg. All Rights Reserved.
 * Copyright (C) 2024 GarfieldHan. All Rights Reserved.
 * Copyright (C) 2024 1f2003d5. All Rights Reserved.
 */

#include <accctl.h>
#include <asm/current.h>
#include <linux/fs.h>
#include <hook.h>
#include <ktypes.h>
#include <kumount.h>
#include <predata.h>
#include <sucompat.h>
#include <taskext.h>

static inline bool is_appuid(uid_t uid)
{
#define PER_USER_RANGE 100000
#define FIRST_APPLICATION_UID 10000
#define LAST_APPLICATION_UID 19999
    uid_t appid = uid % PER_USER_RANGE;
    return appid >= FIRST_APPLICATION_UID && appid <= LAST_APPLICATION_UID;
}

static inline bool is_unsupported_uid(uid_t uid)
{
#define LAST_APPLICATION_UID 19999
    uid_t appid = uid % 100000;
    return appid > LAST_APPLICATION_UID;
}

static inline uid_t new_cred_uid() {
    struct cred *cred = prepare_creds();
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    return uid;    
}

static inline void handle_umount(uid_t new_uid, uid_t old_uid) {
   logkfi("[GarfieldHan] new_uid: %d, old_uid: %d\n", new_uid, old_uid);

    if (0 != old_uid) {
        logkfi("[GarfieldHan] old process is not root, ignore it.\n");
        return 0;
    }

    if (!is_appuid(new_uid) || is_unsupported_uid(new_uid)) {
        logkfi("[GarfieldHan] handle setuid ignore non application or isolated uid: %d\n", new_uid);
        return 0;
    }

    if (unlikely(is_su_allow_uid(new_uid))) {
        logkfi("[GarfieldHan] handle setuid ignore allowed application: %d\n", new_uid);
        return 0;
    }

    if (likely(!uid_should_exclude(new_uid))) {
        return 0;
    } else {
        logkfi("[GarfieldHan] uid: %d should umount!\n", current_uid());
    }

    // check old process's selinux context, if it is not zygote, ignore it!
    // because some su apps may setuid to untrusted_app but they are in global mount namespace
    // when we umount for such process, that is a disaster!
    logkfi("[GarfieldHan] check zygote");
    bool is_zygote_child = is_zygote(current);
    if (!is_zygote_child) {
        logkfi("[GarfieldHan] handle umount ignore non zygote child: %d\n", current_ext->pid);
        return 0;
    }
    logkfi("[GarfieldHan] zygote check is ok");

    // umount the target mnt
    logkfi("[GarfieldHan] handle umount for uid: %d, pid: %d\n", new_uid, current_ext->pid);

    // fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
    // filter the mountpoint whose target is `/data/adb`
    try_umount("/system", true, 0);
    try_umount("/vendor", true, 0);
    try_umount("/product", true, 0);
    try_umount("/data/adb/modules", false, MNT_DETACH);

    // try umount temp path
    try_umount("/debug_ramdisk", false, MNT_DETACH);
    try_umount("/sbin", false, MNT_DETACH);

    logkfi("[GarfieldHan] kp umount is done!\n");
}

static long before_sys_setalluid(hook_fargs3_t *args, void *udata)
{
    //logkfi("[GarfieldHan] enter sys_setXuid, uid: %d \n", (uid_t) args->arg0);
    handle_umount((uid_t) args->arg0, current_uid());
    return 0;
}

int kp_umount_init()
{
    hook_err_t ret = 0;
    hook_err_t rc = HOOK_NO_ERR;

    unsigned long sys_setuid_addr = get_preset_patch_sym()->sys_setuid;
    log_boot("sys_setuid is at: %llx", sys_setuid_addr);
    if (likely(sys_setuid_addr)) {
        log_boot("sys_setuid is at: %llx", sys_setuid_addr);
        rc = hook_wrap3((void *)sys_setuid_addr, before_sys_setalluid, 0, 0);
        ret |= rc;
        log_boot("hook sys_setuid rc: %d\n", rc);
    }

    unsigned long sys_setreuid_addr = get_preset_patch_sym()->sys_setreuid;
    log_boot("sys_setreuid is at: %llx", sys_setreuid_addr);
    if (likely(sys_setreuid_addr)) {
        log_boot("sys_setreuid is at: %llx", sys_setreuid_addr);
        rc = hook_wrap3((void *)sys_setreuid_addr, before_sys_setalluid, 0, 0);
        ret |= rc;
        log_boot("hook sys_setreuid rc: %d\n", rc);
    }

    unsigned long sys_setresuid_addr = get_preset_patch_sym()->sys_setresuid;
    log_boot("sys_setresuid is at: %llx", sys_setresuid_addr);
    if (likely(sys_setresuid_addr)) {
        log_boot("sys_setresuid is at: %llx", sys_setresuid_addr);
        rc = hook_wrap3((void *)sys_setresuid_addr, before_sys_setalluid, 0, 0);
        ret |= rc;
        log_boot("hook sys_setresuid rc: %d\n", rc);
    }

    unsigned long sys_setfsuid_addr = get_preset_patch_sym()->sys_setfsuid;
    log_boot("sys_setfsuid is at: %llx", sys_setfsuid_addr);
    if (likely(sys_setfsuid_addr)) {
        log_boot("sys_setfsuid is at: %llx", sys_setfsuid_addr);
        rc = hook_wrap3((void *)sys_setfsuid_addr, before_sys_setalluid, 0, 0);
        ret |= rc;
        log_boot("hook sys_setfsuid rc: %d\n", rc);
    }

    return ret;
}
