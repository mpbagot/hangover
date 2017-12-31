#ifndef HAVE_QEMU_D3D9TYPES_H
#define HAVE_QEMU_D3D9TYPES_H

#include "thunk/qemu_defines.h"

struct qemu_D3DPRESENT_PARAMETERS
{
    UINT                    BackBufferWidth;
    UINT                    BackBufferHeight;
    D3DFORMAT               BackBufferFormat;
    UINT                    BackBufferCount;

    D3DMULTISAMPLE_TYPE     MultiSampleType;
    DWORD                   MultiSampleQuality;

    D3DSWAPEFFECT           SwapEffect;
    qemu_handle             hDeviceWindow;
    BOOL                    Windowed;
    BOOL                    EnableAutoDepthStencil;
    D3DFORMAT               AutoDepthStencilFormat;
    DWORD                   Flags;

    UINT                    FullScreen_RefreshRateInHz;
    UINT                    PresentationInterval;

};

static inline void D3DPRESENT_PARAMETERS_g2h(D3DPRESENT_PARAMETERS *host, const struct qemu_D3DPRESENT_PARAMETERS *guest)
{
    host->BackBufferWidth = guest->BackBufferWidth;
    host->BackBufferHeight = guest->BackBufferHeight;
    host->BackBufferFormat = guest->BackBufferFormat;
    host->BackBufferCount = guest->BackBufferCount;
    host->MultiSampleType = guest->MultiSampleType;
    host->MultiSampleQuality = guest->MultiSampleQuality;
    host->SwapEffect = guest->SwapEffect;
    host->hDeviceWindow = (HWND)(ULONG_PTR)guest->hDeviceWindow;
    host->Windowed = guest->Windowed;
    host->EnableAutoDepthStencil = guest->EnableAutoDepthStencil;
    host->AutoDepthStencilFormat = guest->AutoDepthStencilFormat;
    host->Flags = guest->Flags;
    host->FullScreen_RefreshRateInHz = guest->FullScreen_RefreshRateInHz;
    host->PresentationInterval = guest->PresentationInterval;
}

static inline void D3DPRESENT_PARAMETERS_h2g(struct qemu_D3DPRESENT_PARAMETERS *guest, const D3DPRESENT_PARAMETERS *host)
{
    guest->BackBufferWidth = host->BackBufferWidth;
    guest->BackBufferHeight = host->BackBufferHeight;
    guest->BackBufferFormat = host->BackBufferFormat;
    guest->BackBufferCount = host->BackBufferCount;
    guest->MultiSampleType = host->MultiSampleType;
    guest->MultiSampleQuality = host->MultiSampleQuality;
    guest->SwapEffect = host->SwapEffect;
    guest->hDeviceWindow = (ULONG_PTR)host->hDeviceWindow;
    guest->Windowed = host->Windowed;
    guest->EnableAutoDepthStencil = host->EnableAutoDepthStencil;
    guest->AutoDepthStencilFormat = host->AutoDepthStencilFormat;
    guest->Flags = host->Flags;
    guest->FullScreen_RefreshRateInHz = host->FullScreen_RefreshRateInHz;
    guest->PresentationInterval = host->PresentationInterval;
}

#endif