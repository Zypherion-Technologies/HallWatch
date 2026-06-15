// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#include "hallwatch.h"
#include "hallwatch/common.h"
#include "hallwatch/parser.h"
#include "hallwatch/ctx.h"
#include "hallwatch/hooks.h"
#include "hallwatch/console.h"
#include <stdio.h>

namespace HaW
{
    extern PVOID   VehReRegisterHandle;
    extern PVOID   VehReRegisterCallback;
    extern PVOID ( WINAPI *VehReRegisterFn )( ULONG, PVECTORED_EXCEPTION_HANDLER );
    extern ULONG ( WINAPI *VehReRemoveFn )( PVOID );
}

namespace HaW
{
    STATIC PVOID            VehHandle       = nullptr;
    STATIC volatile LONG    InitializedFlg  = 0;
    STATIC CRITICAL_SECTION LifecycleLock   = { };
    STATIC volatile LONG    LifecycleInited = 0;

    STATIC VOID
    EnsureLifecycleLock(
        VOID
    )
    {
        if ( InterlockedCompareExchange( &LifecycleInited, 2, 0 ) == 0 )
        {
            InitializeCriticalSection( &LifecycleLock );
            InterlockedExchange( &LifecycleInited, 1 );
        }
        else
        {
            while ( InterlockedCompareExchange( &LifecycleInited, 1, 1 ) != 1 )
            {
                YieldProcessor( );
            }
        }
    }

    STATIC Hook*
    FindHookBySyscallRip(
        UINT64 Rip
    )
    {
        for ( UINT32 i = 0; i < Parser::HookCount; i++ )
        {
            if ( Parser::Hooks[ i ].SyscallAddress == Rip )
            {
                return &Parser::Hooks[ i ];
            }
        }
        return nullptr;
    }

    STATIC LONG WINAPI
    VectoredHandler(
        LPEXCEPTION_POINTERS Ep
    )
    {
        PCONTEXT          Context = Ep->ContextRecord;
        PEXCEPTION_RECORD Record  = Ep->ExceptionRecord;

        if ( Record->ExceptionCode != EXCEPTION_BREAKPOINT )
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if ( !Guards::HandlerEnter( ) )
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        UINT64 BpExc = ( UINT64 )Record->ExceptionAddress;
        UINT64 BpRipMinus1 = Context->Rip >= 1 ? Context->Rip - 1 : 0;
        Hook*  H = FindHookBySyscallRip( BpExc );
        if ( H == nullptr )
        {
            H = FindHookBySyscallRip( BpRipMinus1 );
        }
        if ( H == nullptr )
        {
            H = FindHookBySyscallRip( Context->Rip );
        }
        if ( H == nullptr )
        {
            Guards::HandlerExit( );
            return EXCEPTION_CONTINUE_SEARCH;
        }
        Context->Rip = H->SyscallAddress;

        if ( !Guards::InternalActive( ) )
        {
            UINT64 RetAddr = 0;
            __try
            {
                RetAddr = *( PUINT64 )Context->Rsp;
            }
            __except ( EXCEPTION_EXECUTE_HANDLER )
            {
                RetAddr = 0;
            }

            UINT32 RaxSsn   = ( UINT32 )Context->Rax;
            BOOL   Untrust  = !Ctx::IsTrustedCaller( RetAddr );
            BOOL   BadSsn   = ( H->ExpectedSsn != 0 && RaxSsn != H->ExpectedSsn );
            UINT32 BadFrame = Ctx::FirstSuspiciousFrame( Context );

            if ( Untrust || BadSsn || BadFrame != 0 )
            {
                UINT32 Reasons = 0;
                if ( Untrust )  { Reasons |= REASON_UNTRUSTED_CALLER; }
                if ( BadSsn )   { Reasons |= REASON_SSN_MISMATCH;     }
                if ( BadFrame ) { Reasons |= REASON_SPOOFED_STACK;    }
                UINT32 HookIndex = ( UINT32 )( H - Parser::Hooks );
                Console::PushDetection( HookIndex, RaxSsn, Reasons, BadFrame, Context->Rip, RetAddr );
            }
        }

        Context->Rip = H->TrampolineAddress;
        Guards::HandlerExit( );
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    BOOL
    Detector::Initialize(
        VOID
    )
    {
        EnsureLifecycleLock( );
        EnterCriticalSection( &LifecycleLock );

        if ( InterlockedCompareExchange( &InitializedFlg, 1, 0 ) != 0 )
        {
            LeaveCriticalSection( &LifecycleLock );
            return TRUE;
        }

        InterlockedExchange( &Guards::ShutdownPending, 0 );
        InterlockedExchange( &Guards::ActiveHandlers, 0 );

        Console::Init( );

        if ( !Guards::AllocateTlsSlots( ) )
        {
            InterlockedExchange( &InitializedFlg, 0 );
            LeaveCriticalSection( &LifecycleLock );
            return FALSE;
        }

        Guards::InternalEnter( );

        Parser::BuildTrustedRanges( );
        Parser::SnapshotLoadedModules( );

        if ( Parser::EnumerateNtStubs( ) == 0 )
        {
            Guards::InternalExit( );
            Guards::ReleaseTlsSlots( );
            InterlockedExchange( &InitializedFlg, 0 );
            LeaveCriticalSection( &LifecycleLock );
            return FALSE;
        }

        if ( !Guards::AllocateTrampolinePool( ) )
        {
            Guards::InternalExit( );
            Guards::ReleaseTlsSlots( );
            InterlockedExchange( &InitializedFlg, 0 );
            LeaveCriticalSection( &LifecycleLock );
            return FALSE;
        }

        for ( UINT32 i = 0; i < Parser::HookCount; i++ )
        {
            Parser::Hooks[ i ].TrampolineAddress = Guards::BuildTrampoline( i, Parser::Hooks[ i ].ExpectedSsn );
        }

        if ( !Guards::BuildPrivateStubs( ) )
        {
            Guards::InternalExit( );
            Guards::FreeTrampolinePool( );
            Guards::ReleaseTlsSlots( );
            InterlockedExchange( &InitializedFlg, 0 );
            LeaveCriticalSection( &LifecycleLock );
            return FALSE;
        }

        VehHandle = AddVectoredExceptionHandler( TRUE, VectoredHandler );
        if ( VehHandle == nullptr )
        {
            Guards::InternalExit( );
            Guards::FreeTrampolinePool( );
            Guards::ReleaseTlsSlots( );
            InterlockedExchange( &InitializedFlg, 0 );
            LeaveCriticalSection( &LifecycleLock );
            return FALSE;
        }

        Guards::LockTrampolinePool( );

        VehReRegisterHandle   = VehHandle;
        VehReRegisterCallback = ( PVOID )VectoredHandler;
        VehReRegisterFn       = AddVectoredExceptionHandler;
        VehReRemoveFn         = RemoveVectoredExceptionHandler;

        Console::StartDrain( );

        CHAR Banner[ 192 ];
        sprintf_s( 
            Banner, 
            sizeof( Banner ),
            "[hallwatch] INT3 mode: %u Nt* hooks enumerated, %u modules snapshotted, patch deferred to worker\n",
            Parser::HookCount, Parser::ModuleRangeCount
        );
        Console::Notice( Banner );

        Guards::StartIntegrityWorker( );

        Guards::InternalExit( );
        LeaveCriticalSection( &LifecycleLock );
        return TRUE;
    }

    LONG
    Detector::DetectionCount(
        VOID
    )
    {
        return Console::DetectionCount( );
    }

    VOID
    Detector::Flush(
        VOID
    )
    {
        Console::DrainOnce( );
    }

    VOID
    Detector::Shutdown(
        VOID
    )
    {
        EnsureLifecycleLock( );
        EnterCriticalSection( &LifecycleLock );

        if ( InterlockedCompareExchange( &InitializedFlg, 0, 0 ) == 0 )
        {
            LeaveCriticalSection( &LifecycleLock );
            return;
        }

        Guards::WaitForHandlersIdle( );
        Guards::InternalEnter( );
        Guards::StopIntegrityWorker( );

        Guards::RestoreAllSyscalls( );

        PVOID Latest = ( PVOID )InterlockedExchangePointer( &VehReRegisterHandle, nullptr );
        if ( Latest != nullptr )
        {
            RemoveVectoredExceptionHandler( Latest );
        }
        VehHandle = nullptr;

        Console::Shutdown( );
        Guards::ReleaseTlsSlots( );

        InterlockedExchange( &InitializedFlg, 0 );
        LeaveCriticalSection( &LifecycleLock );
    }
}

extern "C" BOOLEAN IscInitialize( VOID )
{
    return HaW::Detector::Initialize( ) ? TRUE : FALSE;
}

extern "C" LONG IscGetDetectionCount( VOID )
{
    return HaW::Detector::DetectionCount( );
}

extern "C" VOID IscShutdown( VOID )
{
    HaW::Detector::Shutdown( );
}

extern "C" VOID IscFlush( VOID )
{
    HaW::Detector::Flush( );
}
