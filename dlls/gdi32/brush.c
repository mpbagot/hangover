/*
 * Copyright 2017 André Hentschel
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

/* NOTE: The guest side uses mingw's headers. The host side uses Wine's headers. */

#include <windows.h>
#include <stdio.h>

#include "thunk/qemu_windows.h"

#include "windows-user-services.h"
#include "dll_list.h"
#include "qemu_gdi32.h"

#ifndef QEMU_DLL_GUEST
#include <wine/debug.h>
WINE_DEFAULT_DEBUG_CHANNEL(qemu_gdi32);
#endif


struct qemu_CreateBrushIndirect
{
    struct qemu_syscall super;
    uint64_t brush;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI HBRUSH WINAPI CreateBrushIndirect(const LOGBRUSH * brush)
{
    struct qemu_CreateBrushIndirect call;
    call.super.id = QEMU_SYSCALL_ID(CALL_CREATEBRUSHINDIRECT);
    call.brush = (ULONG_PTR)brush;

    qemu_syscall(&call.super);

    return (HBRUSH)(ULONG_PTR)call.super.iret;
}

#else

void qemu_CreateBrushIndirect(struct qemu_syscall *call)
{
    struct qemu_CreateBrushIndirect *c = (struct qemu_CreateBrushIndirect *)call;
    LOGBRUSH stack, *brush = &stack;
    WINE_TRACE("\n");

#if GUEST_BIT == HOST_BIT
    brush = QEMU_G2H(c->brush);
#else
    if (c->brush)
        LOGBRUSH_g2h(brush, QEMU_G2H(c->brush));
    else
        brush = NULL;
#endif

    c->super.iret = (ULONG_PTR)CreateBrushIndirect(brush);
}

#endif

struct qemu_CreateHatchBrush
{
    struct qemu_syscall super;
    uint64_t style;
    uint64_t color;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI HBRUSH WINAPI CreateHatchBrush(INT style, COLORREF color)
{
    struct qemu_CreateHatchBrush call;
    call.super.id = QEMU_SYSCALL_ID(CALL_CREATEHATCHBRUSH);
    call.style = (ULONG_PTR)style;
    call.color = (ULONG_PTR)color;

    qemu_syscall(&call.super);

    return (HBRUSH)(ULONG_PTR)call.super.iret;
}

#else

void qemu_CreateHatchBrush(struct qemu_syscall *call)
{
    struct qemu_CreateHatchBrush *c = (struct qemu_CreateHatchBrush *)call;
    WINE_TRACE("\n");
    c->super.iret = (ULONG_PTR)CreateHatchBrush(c->style, c->color);
}

#endif

struct qemu_CreatePatternBrush
{
    struct qemu_syscall super;
    uint64_t hbitmap;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI HBRUSH WINAPI CreatePatternBrush(HBITMAP hbitmap)
{
    struct qemu_CreatePatternBrush call;
    call.super.id = QEMU_SYSCALL_ID(CALL_CREATEPATTERNBRUSH);
    call.hbitmap = (ULONG_PTR)hbitmap;

    qemu_syscall(&call.super);

    return (HBRUSH)(ULONG_PTR)call.super.iret;
}

#else

void qemu_CreatePatternBrush(struct qemu_syscall *call)
{
    struct qemu_CreatePatternBrush *c = (struct qemu_CreatePatternBrush *)call;
    WINE_TRACE("\n");
    c->super.iret = (ULONG_PTR)CreatePatternBrush(QEMU_G2H(c->hbitmap));
}

#endif

struct qemu_CreateDIBPatternBrush
{
    struct qemu_syscall super;
    uint64_t hbitmap;
    uint64_t coloruse;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI HBRUSH WINAPI CreateDIBPatternBrush(HGLOBAL hbitmap, UINT coloruse)
{
    struct qemu_CreateDIBPatternBrush call;
    call.super.id = QEMU_SYSCALL_ID(CALL_CREATEDIBPATTERNBRUSH);
    call.hbitmap = (ULONG_PTR)hbitmap;
    call.coloruse = (ULONG_PTR)coloruse;

    qemu_syscall(&call.super);

    return (HBRUSH)(ULONG_PTR)call.super.iret;
}

#else

void qemu_CreateDIBPatternBrush(struct qemu_syscall *call)
{
    struct qemu_CreateDIBPatternBrush *c = (struct qemu_CreateDIBPatternBrush *)call;
    WINE_TRACE("\n");
    c->super.iret = (ULONG_PTR)CreateDIBPatternBrush(QEMU_G2H(c->hbitmap), c->coloruse);
}

#endif

struct qemu_CreateDIBPatternBrushPt
{
    struct qemu_syscall super;
    uint64_t data;
    uint64_t coloruse;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI HBRUSH WINAPI CreateDIBPatternBrushPt(const void* data, UINT coloruse)
{
    struct qemu_CreateDIBPatternBrushPt call;
    call.super.id = QEMU_SYSCALL_ID(CALL_CREATEDIBPATTERNBRUSHPT);
    call.data = (ULONG_PTR)data;
    call.coloruse = (ULONG_PTR)coloruse;

    qemu_syscall(&call.super);

    return (HBRUSH)(ULONG_PTR)call.super.iret;
}

#else

void qemu_CreateDIBPatternBrushPt(struct qemu_syscall *call)
{
    struct qemu_CreateDIBPatternBrushPt *c = (struct qemu_CreateDIBPatternBrushPt *)call;
    WINE_TRACE("\n");
    c->super.iret = (ULONG_PTR)CreateDIBPatternBrushPt(QEMU_G2H(c->data), c->coloruse);
}

#endif

struct qemu_CreateSolidBrush
{
    struct qemu_syscall super;
    uint64_t color;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI HBRUSH WINAPI CreateSolidBrush(COLORREF color)
{
    struct qemu_CreateSolidBrush call;
    call.super.id = QEMU_SYSCALL_ID(CALL_CREATESOLIDBRUSH);
    call.color = (ULONG_PTR)color;

    qemu_syscall(&call.super);

    return (HBRUSH)(ULONG_PTR)call.super.iret;
}

#else

void qemu_CreateSolidBrush(struct qemu_syscall *call)
{
    struct qemu_CreateSolidBrush *c = (struct qemu_CreateSolidBrush *)call;
    WINE_TRACE("\n");
    c->super.iret = (ULONG_PTR)CreateSolidBrush(c->color);
}

#endif

struct qemu_SetBrushOrgEx
{
    struct qemu_syscall super;
    uint64_t hdc;
    uint64_t x;
    uint64_t y;
    uint64_t oldorg;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI BOOL WINAPI SetBrushOrgEx(HDC hdc, INT x, INT y, LPPOINT oldorg)
{
    struct qemu_SetBrushOrgEx call;
    call.super.id = QEMU_SYSCALL_ID(CALL_SETBRUSHORGEX);
    call.hdc = (ULONG_PTR)hdc;
    call.x = (ULONG_PTR)x;
    call.y = (ULONG_PTR)y;
    call.oldorg = (ULONG_PTR)oldorg;

    qemu_syscall(&call.super);

    return call.super.iret;
}

#else

void qemu_SetBrushOrgEx(struct qemu_syscall *call)
{
    struct qemu_SetBrushOrgEx *c = (struct qemu_SetBrushOrgEx *)call;
    WINE_TRACE("\n");
    c->super.iret = SetBrushOrgEx(QEMU_G2H(c->hdc), c->x, c->y, QEMU_G2H(c->oldorg));
}

#endif

struct qemu_FixBrushOrgEx
{
    struct qemu_syscall super;
    uint64_t hdc;
    uint64_t x;
    uint64_t y;
    uint64_t oldorg;
};

#ifdef QEMU_DLL_GUEST

WINBASEAPI BOOL WINAPI FixBrushOrgEx(HDC hdc, INT x, INT y, LPPOINT oldorg)
{
    struct qemu_FixBrushOrgEx call;
    call.super.id = QEMU_SYSCALL_ID(CALL_FIXBRUSHORGEX);
    call.hdc = (ULONG_PTR)hdc;
    call.x = (ULONG_PTR)x;
    call.y = (ULONG_PTR)y;
    call.oldorg = (ULONG_PTR)oldorg;

    qemu_syscall(&call.super);

    return call.super.iret;
}

#else

void qemu_FixBrushOrgEx(struct qemu_syscall *call)
{
    struct qemu_FixBrushOrgEx *c = (struct qemu_FixBrushOrgEx *)call;
    WINE_FIXME("Unverified!\n");
    c->super.iret = FixBrushOrgEx(QEMU_G2H(c->hdc), c->x, c->y, QEMU_G2H(c->oldorg));
}

#endif

