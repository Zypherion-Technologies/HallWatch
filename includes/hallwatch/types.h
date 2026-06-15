// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#ifndef HALLWATCH_TYPES_H
#define HALLWATCH_TYPES_H

#include <Windows.h>
#include "common.h"

namespace HaW
{
    struct Hook
    {
        UINT64  StubEntry;
        UINT64  SyscallAddress;
        UINT64  TrampolineAddress;
        UINT32  ExpectedSsn;
        BYTE    OriginalByte;
        BOOL    Armed;
        CHAR    Name[ 64 ];
    };

    struct ModuleRange
    {
        UINT64 Start;
        UINT64 End;
        CHAR   ModuleName[ 32 ];
    };

    using NtProtectVirtualMemory_t = LONG ( NTAPI* )(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG );
}

#endif
