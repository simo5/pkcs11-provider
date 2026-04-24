/* Copyright (C) 2023 Jakub Jelen <jjelen@redhat.com>
   Copyright (C) 2026 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <string.h>

static void *(*fwd_dlopen)(const char *filename, int flags);

extern void *police_dlopen(const char *filename, int flags);

void *police_dlopen(const char *filename, int flags)
{
    flags &= ~RTLD_DEEPBIND;
    flags |= RTLD_NODELETE;

    return fwd_dlopen(filename, flags);
}

unsigned int la_version(unsigned int version)
{
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
    if (strstr(map->l_name, "libasan")) {
        return LA_FLG_BINDTO | LA_FLG_BINDFROM;
    }
    return 0;
}

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                       uintptr_t *refcook, uintptr_t *defcook,
                       unsigned int *flags, const char *symname)
{
    if (strcmp(symname, "dlopen") == 0) {
        fwd_dlopen = (void * (*)(const char *, int))sym->st_value;
        return (uintptr_t)police_dlopen;
    }

    return sym->st_value;
}
