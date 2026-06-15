// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#ifndef HALLWATCH_CONSOLE_H
#define HALLWATCH_CONSOLE_H

#include "types.h"

namespace HaW
{
    constexpr UINT32 REASON_UNTRUSTED_CALLER = 0x01;
    constexpr UINT32 REASON_SSN_MISMATCH     = 0x02;
    constexpr UINT32 REASON_SPOOFED_STACK    = 0x04;
    constexpr UINT32 REASON_PATCHED_SYSCALL  = 0x08;
    constexpr UINT32 REASON_DIRECT_SYSCALL   = 0x10;
    constexpr UINT32 REASON_NO_CALL_SITE     = 0x20;

    constexpr UINT32 EVT_DETECTION = 1;
    constexpr UINT32 EVT_NOTICE    = 2;

    constexpr UINT32 RING_SIZE = 256;
    constexpr UINT32 RING_MASK = RING_SIZE - 1;

    struct Event
    {
        UINT32 Kind;
        UINT32 ThreadId;
        UINT32 HookIndex;
        UINT32 Reasons;
        UINT32 RaxSsn;
        UINT32 BadFrame;
        UINT64 SyscallRip;
        UINT64 ReturnAddress;
        CHAR   Text[ 192 ];
    };

    struct RingSlot
    {
        Event         Slot;
        volatile LONG Published;
    };

    class Console
    {
    public:
        static BOOL Init( VOID );
        static VOID StartDrain( VOID );
        static VOID Shutdown( VOID );
        static VOID DrainOnce( VOID );

        static VOID PushDetection(
            UINT32 HookIndex,
            UINT32 RaxSsn,
            UINT32 Reasons,
            UINT32 BadFrame,
            UINT64 SyscallRip,
            UINT64 ReturnAddress
        );

        static VOID Notice( CONST CHAR* Text );
        static LONG DetectionCount( VOID );
    };
}

#endif
