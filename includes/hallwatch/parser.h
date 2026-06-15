// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#ifndef HALLWATCH_PARSER_H
#define HALLWATCH_PARSER_H

#include "types.h"

namespace HaW
{
    class Parser
    {
    public:
        static Hook        Hooks[ MAX_HOOKS ];
        static UINT32      HookCount;
        static ModuleRange TrustedRanges[ MAX_TRUSTED_MODULES ];
        static UINT32      TrustedRangeCount;
        static ModuleRange ModuleRanges[ MAX_MODULE_RANGES ];
        static UINT32      ModuleRangeCount;

        static BOOL GetModuleTextRange(
            HMODULE Module,
            UINT64* Start,
            UINT64* End
        );

        static BOOL ParseStub(
            VOID*   StubStart,
            UINT64* SyscallAddress,
            UINT32* Ssn
        );

        static VOID   BuildTrustedRanges( VOID );
        static VOID   SnapshotLoadedModules( VOID );
        static UINT32 EnumerateNtStubs( VOID );
    };
}

#endif
