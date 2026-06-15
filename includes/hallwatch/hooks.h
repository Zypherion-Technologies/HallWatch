// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#ifndef HALLWATCH_HOOKS_H
#define HALLWATCH_HOOKS_H

#include "types.h"

namespace HaW
{
    class Guards
    {
    public:
        static BYTE*                    TrampolinePool;
        static DWORD                    TlsInternalCall;
        static NtProtectVirtualMemory_t PrivateNtProtect;
        static volatile LONG            ShutdownPending;
        static volatile LONG            ActiveHandlers;

        static VOID InternalEnter( VOID );
        static VOID InternalExit( VOID );
        static BOOL InternalActive( VOID );

        static BOOL HandlerEnter( VOID );
        static VOID HandlerExit( VOID );
        static VOID WaitForHandlersIdle( VOID );

        static BOOL AllocateTlsSlots( VOID );
        static VOID ReleaseTlsSlots( VOID );

        static BOOL   AllocateTrampolinePool( VOID );
        static VOID   FreeTrampolinePool( VOID );
        static UINT64 BuildTrampoline( UINT32 Index, UINT32 Ssn );
        static BOOL   BuildPrivateStubs( VOID );
        static VOID   LockTrampolinePool( VOID );

        static UINT32 PatchAllSyscalls( VOID );
        static VOID   RestoreAllSyscalls( VOID );
        static BOOL   PatchSyscallByte( UINT64 SyscallAddress, BYTE* OriginalOut );
        static BOOL   RestoreSyscallByte( UINT64 SyscallAddress, BYTE Original );

        static VOID StartIntegrityWorker( VOID );
        static VOID StopIntegrityWorker( VOID );
    };
}

#endif
