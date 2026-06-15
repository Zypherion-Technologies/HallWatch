// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#include "hallwatch/console.h"
#include "hallwatch/parser.h"
#include "hallwatch/hooks.h"
#include <stdio.h>
#include <string.h>

namespace HaW
{
    STATIC RingSlot         Ring[ RING_SIZE ] = { };
    STATIC volatile LONG    RingHead          = 0;
    STATIC volatile LONG    RingTail          = 0;
    STATIC volatile LONG    DetectionCounter  = 0;
    STATIC volatile LONG    DrainRun          = 0;
    STATIC HANDLE           DrainThread       = nullptr;
    STATIC BOOL             OwnsConsole       = FALSE;
    STATIC SRWLOCK          DrainLock         = { };
    STATIC volatile LONG    DrainLockInited   = 0;

    STATIC VOID
    EnsureDrainLock(
        VOID
    )
    {
        if ( InterlockedCompareExchange( &DrainLockInited, 2, 0 ) == 0 )
        {
            InitializeSRWLock( &DrainLock );
            InterlockedExchange( &DrainLockInited, 1 );
        }
        else
        {
            while ( InterlockedCompareExchange( &DrainLockInited, 1, 1 ) != 1 )
            {
                YieldProcessor( );
            }
        }
    }

    BOOL
    Console::Init(
        VOID
    )
    {
        if ( GetConsoleWindow( ) != nullptr )
        {
            return TRUE;
        }
        if ( AllocConsole( ) )
        {
            OwnsConsole = TRUE;
            FILE* Fp = nullptr;
            freopen_s( &Fp, "CONOUT$", "w", stdout );
            setvbuf( stdout, nullptr, _IONBF, 0 );
            SetConsoleTitleA( "hallwatch" );
        }
        return TRUE;
    }

    VOID
    Console::PushDetection(
        UINT32 HookIndex,
        UINT32 RaxSsn,
        UINT32 Reasons,
        UINT32 BadFrame,
        UINT64 SyscallRip,
        UINT64 ReturnAddress
    )
    {
        InterlockedIncrement( &DetectionCounter );
        LONG      S = InterlockedIncrement( &RingHead ) - 1;
        RingSlot* R = &Ring[ S & RING_MASK ];
        for ( UINT32 Spins = 0; Spins < 200; Spins++ )
        {
            if ( InterlockedCompareExchange( &R->Published, 0, 0 ) == 0 )
            {
                break;
            }
            YieldProcessor( );
        }
        R->Slot.Kind          = EVT_DETECTION;
        R->Slot.ThreadId      = GetCurrentThreadId( );
        R->Slot.HookIndex     = HookIndex;
        R->Slot.Reasons       = Reasons;
        R->Slot.RaxSsn        = RaxSsn;
        R->Slot.BadFrame      = BadFrame;
        R->Slot.SyscallRip    = SyscallRip;
        R->Slot.ReturnAddress = ReturnAddress;
        InterlockedExchange( &R->Published, 1 );
    }

    VOID
    Console::Notice(
        CONST CHAR* Text
    )
    {
        LONG      S = InterlockedIncrement( &RingHead ) - 1;
        RingSlot* R = &Ring[ S & RING_MASK ];
        for ( UINT32 Spins = 0; Spins < 200; Spins++ )
        {
            if ( InterlockedCompareExchange( &R->Published, 0, 0 ) == 0 )
            {
                break;
            }
            YieldProcessor( );
        }
        R->Slot.Kind     = EVT_NOTICE;
        R->Slot.ThreadId = GetCurrentThreadId( );
        strncpy_s( R->Slot.Text, sizeof( R->Slot.Text ), Text, _TRUNCATE );
        InterlockedExchange( &R->Published, 1 );
    }

    LONG
    Console::DetectionCount(
        VOID
    )
    {
        return InterlockedCompareExchange( &DetectionCounter, 0, 0 );
    }

    STATIC VOID
    FormatDetection(
        Event* E
    )
    {
        CONST CHAR* Name        = "?";
        UINT32      ExpectedSsn = 0;
        if ( E->HookIndex < Parser::HookCount )
        {
            Name        = Parser::Hooks[ E->HookIndex ].Name;
            ExpectedSsn = Parser::Hooks[ E->HookIndex ].ExpectedSsn;
        }
        else if ( E->Reasons & REASON_PATCHED_SYSCALL )
        {
            Name = "(patched 0F 05 - not a known stub)";
        }
        else if ( E->Reasons & REASON_DIRECT_SYSCALL )
        {
            Name = "(syscall instruction not in any loaded module)";
        }

        CHAR Reason[ 192 ] = "indirect syscall (";
        BOOL First = TRUE;
        if ( E->Reasons & REASON_PATCHED_SYSCALL )
        {
            strcat_s( Reason, sizeof( Reason ), "patched syscall on guarded page" );
            First = FALSE;
        }
        if ( E->Reasons & REASON_DIRECT_SYSCALL )
        {
            if ( !First )
            {
                strcat_s( Reason, sizeof( Reason ), ", " );
            }
            strcat_s( Reason, sizeof( Reason ), "direct syscall from outside any module" );
            First = FALSE;
        }
        if ( E->Reasons & REASON_UNTRUSTED_CALLER )
        {
            if ( !First )
            {
                strcat_s( Reason, sizeof( Reason ), ", " );
            }
            strcat_s( Reason, sizeof( Reason ), "untrusted caller" );
            First = FALSE;
        }
        if ( E->Reasons & REASON_SSN_MISMATCH )
        {
            if ( !First )
            {
                strcat_s( Reason, sizeof( Reason ), ", " );
            }
            strcat_s( Reason, sizeof( Reason ), "wrong ssn for this stub" );
            First = FALSE;
        }
        if ( E->Reasons & REASON_SPOOFED_STACK )
        {
            if ( !First )
            {
                strcat_s( Reason, sizeof( Reason ), ", " );
            }
            CHAR Fm[ 64 ];
            sprintf_s( Fm, sizeof( Fm ), "spoofed stack at frame %u", E->BadFrame );
            strcat_s( Reason, sizeof( Reason ), Fm );
            First = FALSE;
        }
        if ( E->Reasons & REASON_NO_CALL_SITE )
        {
            if ( !First )
            {
                strcat_s( Reason, sizeof( Reason ), ", " );
            }
            strcat_s( Reason, sizeof( Reason ), "no CALL instruction before return address (VEH-syscall pattern)" );
        }
        strcat_s( Reason, sizeof( Reason ), ")" );

        printf( "\n[!! hallwatch !!] %s\n"
                "    syscall      : %s\n"
                "    syscall rip  : 0x%016llX\n"
                "    return addr  : 0x%016llX\n"
                "    rax (ssn)    : 0x%08X (stub encodes 0x%08X)\n"
                "    thread       : %lu\n\n",
                Reason, Name, E->SyscallRip, E->ReturnAddress, E->RaxSsn, ExpectedSsn, E->ThreadId );
    }

    STATIC VOID
    DrainPending(
        VOID
    )
    {
        EnsureDrainLock( );
        AcquireSRWLockExclusive( &DrainLock );
        LONG Head = InterlockedCompareExchange( &RingHead, 0, 0 );
        while ( RingTail < Head )
        {
            RingSlot* R = &Ring[ RingTail & RING_MASK ];
            if ( InterlockedCompareExchange( &R->Published, 0, 0 ) == 0 )
            {
                break;
            }
            if ( R->Slot.Kind == EVT_DETECTION )
            {
                FormatDetection( &R->Slot );
            }
            else if ( R->Slot.Kind == EVT_NOTICE )
            {
                printf( "%s", R->Slot.Text );
            }
            InterlockedExchange( &R->Published, 0 );
            RingTail++;
        }
        ReleaseSRWLockExclusive( &DrainLock );
    }

    VOID
    Console::DrainOnce(
        VOID
    )
    {
        Guards::InternalEnter( );
        DrainPending( );
        Guards::InternalExit( );
    }

    STATIC DWORD WINAPI
    DrainThreadProc(
        LPVOID
    )
    {
        Guards::InternalEnter( );
        while ( InterlockedCompareExchange( &DrainRun, 1, 1 ) != 0 )
        {
            Sleep( 50 );
            DrainPending( );
        }
        return 0;
    }

    VOID
    Console::StartDrain(
        VOID
    )
    {
        InterlockedExchange( &DrainRun, 1 );
        DrainThread = CreateThread( nullptr, 0, DrainThreadProc, nullptr, 0, nullptr );
    }

    VOID
    Console::Shutdown(
        VOID
    )
    {
        InterlockedExchange( &DrainRun, 0 );
        if ( DrainThread != nullptr )
        {
            WaitForSingleObject( DrainThread, 2000 );
            CloseHandle( DrainThread );
            DrainThread = nullptr;
        }
        if ( OwnsConsole )
        {
            FreeConsole( );
            OwnsConsole = FALSE;
        }
    }
}
