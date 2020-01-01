/*
 * Copyright 2017 Stefan Dösinger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Include this only in your main file. */

#include "callback_helper.h"

struct callback_entry_table
{
    unsigned int count;
    size_t entry_size;
    BYTE entries[1];
};

void callback_init(struct callback_entry *entry, unsigned int params, void *proc)
{
#ifdef __aarch64__
    size_t offset;

    /* Note: A maximum of 4 parameters are supported. */

    offset = offsetof(struct callback_entry, selfptr) - offsetof(struct callback_entry, ldr_self);
    /* The load offset is stored in bits 5-24. The stored offset is left-shifted by 2 to generate the 21
     * bit real offset. So to place it in the right place we need our offset (multiple of 4, unless the
     * compiler screwed up terribly) shifted by another 3 bits.
     *
     * the register index is in the bottom bits, so for a callback that receives 4 parameters (in x0-x3)
     * we just OR 4 to store the selfptr in the 5th parameter (x4). */
    entry->ldr_self = 0x58000000 | params | (offset << 3); /* ldr x[params], offset */

    offset = offsetof(struct callback_entry, host_proc) - offsetof(struct callback_entry, ldr_proc);
    entry->ldr_proc = 0x58000000 | (params + 1) | (offset << 3);   /* ldr x[params + 1], offset */

    entry->br = 0xd61f0000 | ((params + 1) << 5); /* br x[params + 1] */

    entry->selfptr = entry;

    __clear_cache(&entry->ldr_self, &entry->br + 1);
#elif __arm__
    /* Note: A maximum of 4 parameters are supported. */

    static const char wrapper_code4[] =
    {
        0x04, 0x40, 0x2d, 0xe5,                     /* push {r4}          - Backup r4 so that we can use it          */
        0x10, 0xd0, 0x4d, 0xe2,                     /* sub sp, 0x10       - Allocate stack space for one value       */
        0x10, 0x40, 0x9f, 0xe5,                     /* ldr r4, =selfptr   - Load first parameter                     */ // NOTE: Offset is 20
        0x00, 0x40, 0x8d, 0xe5,                     /* str r4, [sp]       - Push to stack                            */
        0x0c, 0x40, 0x9f, 0xe5,                     /* ldr r4, =host_proc - Load first parameter                     */ // NOTE: Offset is 16
        0x14, 0xff, 0x2f, 0xe1,                     /* bx r4              - Branch into host_proc                    */
        0x04, 0x40, 0x9d, 0xe4,                     /* pop {r4}           - Pop r4 to clean up                       */
        0x00, 0xf0, 0x20, 0xe3,                     /* nop                - nop to fill byte count of entry->code    */
    };
    static const char wrapper_code3[] =
    {
        0x18, 0x30, 0x9f, 0xe5,                     /* ldr r3, =selfptr   - Load selfptr using relative memory load   */ // NOTE: Offset is 28
        0x18, 0x40, 0x9f, 0xe5,                     /* ldr r4, =host_proc - Load host_proc using relative memory load */ // NOTE: Offset is 28
        0x14, 0xff, 0x2f, 0xe1,                     /* bx r4              - Call host_proc                            */
        0x00, 0xf0, 0x20, 0xe3,                     /* nop                - nop to fill byte count of entry->code     */
        0x00, 0xf0, 0x20, 0xe3,                     /* nop                - nop to fill byte count of entry->code     */
        0x00, 0xf0, 0x20, 0xe3,                     /* nop                - nop to fill byte count of entry->code     */
        0x00, 0xf0, 0x20, 0xe3,                     /* nop                - nop to fill byte count of entry->code     */
        0x00, 0xf0, 0x20, 0xe3,                     /* nop                - nop to fill byte count of entry->code     */
    };

    if (params == 4)
    {
        memcpy(entry->code, wrapper_code4, sizeof(wrapper_code4));
    }
    else if (params == 3)
    {
        memcpy(entry->code, wrapper_code3, sizeof(wrapper_code3));
    }
    entry->selfptr = entry;
#elif defined(__x86_64__)
    /* See init_reverse_wndproc in dlls/user32/main.c for details. The only difference
     * is the offset of the function to call with the extra parameter. */
    static const char wrapper_code4[] =
    {
        /* 27 bytes */
        0x48, 0x83, 0xec, 0x38,                     /* sub    $0x38,%rsp        - Reserve stack space   */
        0x48, 0x8d, 0x05, 0xf5, 0xff, 0xff, 0xff,   /* lea    -0xb(%rip),%rax   - Get self ptr          */
        0x48, 0x89, 0x44, 0x24, 0x20,               /* mov    %rax,0x20(%rsp)   - push self ptr         */
        0xff, 0x15, 0x12, 0x00, 0x00, 0x00,         /* callq  *0x12(%rip)       - Call host_proc        */
        0x48, 0x83, 0xc4, 0x38,                     /* add    $0x38,%rsp        - Clean up stack        */
        0xc3,                                       /* retq                     - return                */
    };
    static const char wrapper_code3[] =
    {
        0x4c, 0x8d, 0x0d, 0xf9, 0xff, 0xff, 0xff,   /* lea    -0x7(%rip),%r9    - selfptr in 4th param  */
        0x48, 0xff, 0x25, 0x1a, 0x00, 0x00, 0x00,   /* rex.W jmpq *0x1a(%rip)   - call host_proc        */
    };

    if (params == 4)
    {
        memset(entry->code, 0xcc, sizeof(entry->code));
        memcpy(entry->code, wrapper_code4, sizeof(wrapper_code4));
    }
    else if (params == 3)
    {
        memset(entry->code, 0xcc, sizeof(entry->code));
        memcpy(entry->code, wrapper_code3, sizeof(wrapper_code3));
    }
    entry->selfptr = entry; /* Note that this is not read by the asm code, but put it in place anyway. */
#else
#error callback helper not supported on your platform
#endif

    entry->host_proc = proc;
    entry->guest_proc = 0;
}

BOOL callback_alloc_table(struct callback_entry_table **table, unsigned int count,
        size_t entry_size, void *func, unsigned int params)
{
    struct callback_entry_table *ret;
    unsigned int i;

    ret = VirtualAlloc(NULL, FIELD_OFFSET(struct callback_entry_table, entries[entry_size * count]),
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!ret)
        return FALSE;

    for (i = 0; i < count; ++i)
        callback_init((struct callback_entry *)&ret->entries[i * entry_size], params, func);

    ret->count = count;
    ret->entry_size = entry_size;
    *table = ret;
    return TRUE;
}

struct callback_entry *callback_get(struct callback_entry_table *table, uint64_t guest_proc, BOOL *is_new)
{
    unsigned int i;
    struct callback_entry *entry;

    /* Note that I cannot sort this thing because once a callback has been passed to Wine, it
     * needs to start at the same address. If the search speed becomes an issue a possible choice
     * is to create a separate rbtree that points to entries in this table. */
    for (i = 0; i < table->count; ++i)
    {
        entry = (struct callback_entry *)&table->entries[i * table->entry_size];
        if (entry->guest_proc == guest_proc)
        {
            if (is_new)
                *is_new = FALSE;

            return (struct callback_entry *)entry;
        }

        if (!entry->guest_proc)
        {
            if (is_new)
                *is_new = TRUE;

            entry->guest_proc = guest_proc;
            return entry;
        }
    }

    return NULL;
}

BOOL callback_is_in_table(const struct callback_entry_table *table, const struct callback_entry *entry)
{
    return (ULONG_PTR)entry >= (ULONG_PTR)&table->entries[0]
            && (ULONG_PTR)entry <= (ULONG_PTR)&table->entries[table->entry_size * table->count];
}
