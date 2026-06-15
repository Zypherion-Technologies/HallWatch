// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#include "hallwatch/hooks.h"
#include "hallwatch/parser.h"
#include "hallwatch/console.h"
#include "hallwatch/ctx.h"
#include <stdio.h>
#include <string.h>

namespace HaW
{
    BYTE*                    Guards::TrampolinePool   = nullptr;
    DWORD                    Guards::TlsInternalCall  = TLS_OUT_OF_INDEXES;
    NtProtectVirtualMemory_t Guards::PrivateNtProtect = nullptr;
    volatile LONG            Guards::ShutdownPending  = 0;
    volatile LONG            Guards::ActiveHandlers   = 0;

    STATIC HANDLE        IntegrityWorker = nullptr;
    STATIC volatile LONG IntegrityRun    = 1;

    VOID
    Guards::InternalEnter(
        VOID
    )
    {
        if ( TlsInternalCall != TLS_OUT_OF_INDEXES )
        {
            TlsSetValue( TlsInternalCall, ( PVOID )1 );
        }
    }

    VOID
    Guards::InternalExit(
        VOID
    )
    {
        if ( TlsInternalCall != TLS_OUT_OF_INDEXES )
        {
            TlsSetValue( TlsInternalCall, nullptr );
        }
    }

    BOOL
    Guards::InternalActive(
        VOID
    )
    {
        if ( TlsInternalCall == TLS_OUT_OF_INDEXES )
        {
            return FALSE;
        }
        return TlsGetValue( TlsInternalCall ) != nullptr;
    }

    BOOL
    Guards::HandlerEnter(
        VOID
    )
    {
        InterlockedIncrement( &ActiveHandlers );
        if ( InterlockedCompareExchange( &ShutdownPending, 1, 1 ) != 0 )
        {
            InterlockedDecrement( &ActiveHandlers );
            return FALSE;
        }
        return TRUE;
    }

    VOID
    Guards::HandlerExit(
        VOID
    )
    {
        InterlockedDecrement( &ActiveHandlers );
    }

    VOID
    Guards::WaitForHandlersIdle(
        VOID
    )
    {
        InterlockedExchange( &ShutdownPending, 1 );
        for ( UINT32 Spins = 0; Spins < 5000; Spins++ )
        {
            if ( InterlockedCompareExchange( &ActiveHandlers, 0, 0 ) == 0 )
            {
                return;
            }
            Sleep( 1 );
        }
    }

    BOOL
    Guards::AllocateTlsSlots(
        VOID
    )
    {
        TlsInternalCall = TlsAlloc( );
        return TlsInternalCall != TLS_OUT_OF_INDEXES;
    }

    VOID
    Guards::ReleaseTlsSlots(
        VOID
    )
    {
        if ( TlsInternalCall != TLS_OUT_OF_INDEXES )
        {
            TlsFree( TlsInternalCall );
            TlsInternalCall = TLS_OUT_OF_INDEXES;
        }
    }

    BOOL
    Guards::AllocateTrampolinePool(
        VOID
    )
    {
        SIZE_T Sz = ( SIZE_T )MAX_HOOKS * TRAMPOLINE_SLOT;
        TrampolinePool = ( BYTE* )VirtualAlloc( nullptr, Sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        return TrampolinePool != nullptr;
    }

    VOID
    Guards::FreeTrampolinePool(
        VOID
    )
    {
        if ( TrampolinePool != nullptr )
        {
            VirtualFree( TrampolinePool, 0, MEM_RELEASE );
            TrampolinePool = nullptr;
        }
    }

    UINT64
    Guards::BuildTrampoline(
        UINT32 Index,
        UINT32 Ssn
    )
    {
        BYTE* T = TrampolinePool + ( Index * TRAMPOLINE_SLOT );
        T[ 0 ]  = 0xF3;
        T[ 1 ]  = 0x0F;
        T[ 2 ]  = 0x1E;
        T[ 3 ]  = 0xFA;
        T[ 4 ]  = 0x49;
        T[ 5 ]  = 0x89;
        T[ 6 ]  = 0xCA;
        T[ 7 ]  = 0xB8;
        *( UINT32* )( T + 8 ) = Ssn;
        T[ 12 ] = 0x0F;
        T[ 13 ] = 0x05;
        T[ 14 ] = 0xC3;
        return ( UINT64 )T;
    }

    VOID
    Guards::LockTrampolinePool(
        VOID
    )
    {
        if ( TrampolinePool == nullptr )
        {
            return;
        }
        DWORD  Old = 0;
        SIZE_T Sz  = ( SIZE_T )MAX_HOOKS * TRAMPOLINE_SLOT;
        VirtualProtect( TrampolinePool, Sz, PAGE_EXECUTE_READ, &Old );
    }

    BOOL
    Guards::BuildPrivateStubs(
        VOID
    )
    {
        UINT32 ProtSsn = 0;
        for ( UINT32 i = 0; i < Parser::HookCount; i++ )
        {
            if ( strcmp( Parser::Hooks[ i ].Name, "NtProtectVirtualMemory" ) == 0 )
            {
                ProtSsn = Parser::Hooks[ i ].ExpectedSsn;
                break;
            }
        }
        if ( ProtSsn == 0 )
        {
            return FALSE;
        }

        PrivateNtProtect = ( NtProtectVirtualMemory_t )BuildTrampoline( MAX_HOOKS - 1, ProtSsn );
        FlushInstructionCache( GetCurrentProcess( ), TrampolinePool, ( SIZE_T )MAX_HOOKS * TRAMPOLINE_SLOT );
        return TRUE;
    }

    BOOL
    Guards::PatchSyscallByte(
        UINT64 SyscallAddress,
        BYTE*  OriginalOut
    )
    {
        if ( SyscallAddress == 0 )
        {
            return FALSE;
        }

        PVOID  Addr = ( PVOID )SyscallAddress;
        SIZE_T Sz   = 1;
        ULONG  Old  = 0;
        LONG   St;

        if ( PrivateNtProtect != nullptr )
        {
            St = PrivateNtProtect( GetCurrentProcess( ), &Addr, &Sz, PAGE_EXECUTE_READWRITE, &Old );
            if ( St < 0 )
            {
                return FALSE;
            }
        }
        else
        {
            DWORD OldD = 0;
            if ( !VirtualProtect( ( PVOID )SyscallAddress, 1, PAGE_EXECUTE_READWRITE, &OldD ) )
            {
                return FALSE;
            }
            Old = ( ULONG )OldD;
        }

        BYTE* P = ( BYTE* )SyscallAddress;
        if ( OriginalOut != nullptr )
        {
            *OriginalOut = P[ 0 ];
        }
        P[ 0 ] = BP_BYTE;

        if ( PrivateNtProtect != nullptr )
        {
            Addr = ( PVOID )SyscallAddress;
            Sz   = 1;
            ULONG Restored = 0;
            PrivateNtProtect( GetCurrentProcess( ), &Addr, &Sz, Old, &Restored );
        }
        else
        {
            DWORD OldD = 0;
            VirtualProtect( ( PVOID )SyscallAddress, 1, Old, &OldD );
        }

        FlushInstructionCache( GetCurrentProcess( ), ( PVOID )SyscallAddress, 1 );
        return TRUE;
    }

    BOOL
    Guards::RestoreSyscallByte(
        UINT64 SyscallAddress,
        BYTE   Original
    )
    {
        if ( SyscallAddress == 0 )
        {
            return FALSE;
        }

        PVOID  Addr = ( PVOID )SyscallAddress;
        SIZE_T Sz   = 1;
        ULONG  Old  = 0;
        if ( PrivateNtProtect != nullptr )
        {
            if ( PrivateNtProtect( GetCurrentProcess( ), &Addr, &Sz, PAGE_EXECUTE_READWRITE, &Old ) < 0 )
            {
                return FALSE;
            }
        }
        else
        {
            DWORD OldD = 0;
            if ( !VirtualProtect( ( PVOID )SyscallAddress, 1, PAGE_EXECUTE_READWRITE, &OldD ) )
            {
                return FALSE;
            }
            Old = ( ULONG )OldD;
        }

        ( ( BYTE* )SyscallAddress )[ 0 ] = Original;

        if ( PrivateNtProtect != nullptr )
        {
            Addr = ( PVOID )SyscallAddress;
            Sz   = 1;
            ULONG Restored = 0;
            PrivateNtProtect( GetCurrentProcess( ), &Addr, &Sz, Old, &Restored );
        }
        else
        {
            DWORD OldD = 0;
            VirtualProtect( ( PVOID )SyscallAddress, 1, Old, &OldD );
        }

        FlushInstructionCache( GetCurrentProcess( ), ( PVOID )SyscallAddress, 1 );
        return TRUE;
    }

    STATIC CONST CHAR* PatchAllowlist[ ] =
    {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtFreeVirtualMemory",
        "NtClose",
        "NtCreateFile",
        "NtOpenFile",
        "NtReadFile",
        "NtWriteFile",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtSetContextThread",
        "NtGetContextThread",
        "NtOpenProcess",
        "NtOpenThread",
        "NtCreateProcess",
        "NtCreateProcessEx",
        "NtTerminateProcess",
        "NtSuspendThread",
        "NtResumeThread",
        "NtAdjustPrivilegesToken",
        "NtOpenProcessToken",
        "NtDuplicateObject",
        "NtCreateUserProcess",
    };

    STATIC BOOL
    OnPatchAllowlist(
        CONST CHAR* Name
    )
    {
        for ( SIZE_T i = 0; i < ARRAYSIZE( PatchAllowlist ); i++ )
        {
            if ( strcmp( Name, PatchAllowlist[ i ] ) == 0 )
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    STATIC CONST CHAR* OffensiveAllowlist[ ] =
    {
        "NtAllocateVirtualMemory",
        "NtAllocateVirtualMemoryEx",
        "NtProtectVirtualMemory",
        "NtFreeVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtMapViewOfSection",
        "NtMapViewOfSectionEx",
        "NtUnmapViewOfSection",
        "NtUnmapViewOfSectionEx",
        "NtCreateSection",
        "NtCreateSectionEx",
        "NtOpenSection",
        "NtCreateProcess",
        "NtCreateProcessEx",
        "NtCreateUserProcess",
        "NtOpenProcess",
        "NtTerminateProcess",
        "NtSuspendProcess",
        "NtResumeProcess",
        "NtQueryInformationProcess",
        "NtSetInformationProcess",
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtOpenThread",
        "NtSuspendThread",
        "NtResumeThread",
        "NtTerminateThread",
        "NtSetContextThread",
        "NtGetContextThread",
        "NtQueueApcThread",
        "NtQueueApcThreadEx",
        "NtAlertResumeThread",
        "NtSetInformationThread",
        "NtOpenProcessToken",
        "NtOpenProcessTokenEx",
        "NtAdjustPrivilegesToken",
        "NtCreateFile",
        "NtOpenFile",
        "NtDeviceIoControlFile",
        "NtClose",
        "NtDuplicateObject",
    };

    STATIC BOOL
    OnAllowlist(
        CONST CHAR* Name
    )
    {
        for ( SIZE_T k = 0; k < ARRAYSIZE( OffensiveAllowlist ); k++ )
        {
            if ( strcmp( Name, OffensiveAllowlist[ k ] ) == 0 )
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    UINT32
    Guards::PatchAllSyscalls(
        VOID
    )
    {
        UINT32 Patched = 0;
        for ( UINT32 i = 0; i < Parser::HookCount; i++ )
        {
            if ( !OnAllowlist( Parser::Hooks[ i ].Name ) )
            {
                continue;
            }
            BYTE Original = 0;
            if ( PatchSyscallByte( Parser::Hooks[ i ].SyscallAddress, &Original ) )
            {
                Parser::Hooks[ i ].OriginalByte = Original;
                Parser::Hooks[ i ].Armed        = TRUE;
                Patched++;
            }
        }
        return Patched;
    }

    VOID
    Guards::RestoreAllSyscalls(
        VOID
    )
    {
        for ( UINT32 i = 0; i < Parser::HookCount; i++ )
        {
            if ( Parser::Hooks[ i ].Armed )
            {
                BYTE Orig = Parser::Hooks[ i ].OriginalByte;
                if ( Orig == 0 )
                {
                    Orig = SYSCALL_BYTE0;
                }
                RestoreSyscallByte( Parser::Hooks[ i ].SyscallAddress, Orig );
                Parser::Hooks[ i ].Armed = FALSE;
            }
        }
    }

    extern PVOID   VehReRegisterHandle;
    extern PVOID ( WINAPI *VehReRegisterFn )( ULONG, PVECTORED_EXCEPTION_HANDLER );
    extern PVOID   VehReRegisterCallback;
    extern ULONG ( WINAPI *VehReRemoveFn )( PVOID );

    PVOID   VehReRegisterHandle   = nullptr;
    PVOID   VehReRegisterCallback = nullptr;
    PVOID ( WINAPI *VehReRegisterFn )( ULONG, PVECTORED_EXCEPTION_HANDLER ) = nullptr;
    ULONG ( WINAPI *VehReRemoveFn )( PVOID )                                = nullptr;

    STATIC BOOL
    IsAddressInLoadedModule(
        UINT64 Address
    )
    {
        for ( UINT32 i = 0; i < Parser::ModuleRangeCount; i++ )
        {
            UINT64 ModBase = Parser::ModuleRanges[ i ].Start & PAGE_MASK_;
            UINT64 ModEnd  = ( Parser::ModuleRanges[ i ].End + PAGE_SZ - 1 ) & PAGE_MASK_;
            if ( Address >= ModBase && Address < ModEnd )
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    STATIC UINT64 ReportedForeign[ MAX_FOREIGN_RWX ] = { };
    STATIC UINT32 ReportedForeignCount               = 0;

    STATIC BOOL
    AlreadyReported(
        UINT64 Address
    )
    {
        for ( UINT32 i = 0; i < ReportedForeignCount; i++ )
        {
            if ( ReportedForeign[ i ] == Address )
            {
                return TRUE;
            }
        }
        if ( ReportedForeignCount < MAX_FOREIGN_RWX )
        {
            ReportedForeign[ ReportedForeignCount++ ] = Address;
        }
        return FALSE;
    }

    STATIC CONST CHAR* TrustedSyscallModules[ ] =
    {
        "ntdll.dll",
        "win32u.dll",
        "wow64cpu.dll",
    };

    STATIC BOOL
    IsTrustedSyscallModule(
        CONST CHAR* Name
    )
    {
        if ( Name == nullptr || Name[ 0 ] == 0 )
        {
            return FALSE;
        }
        for ( SIZE_T i = 0; i < ARRAYSIZE( TrustedSyscallModules ); i++ )
        {
            if ( _stricmp( Name, TrustedSyscallModules[ i ] ) == 0 )
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    STATIC VOID
    ScanModuleTextSyscalls(
        VOID
    )
    {
        UINT32 Hits = 0;
        for ( UINT32 i = 0; i < Parser::ModuleRangeCount && Hits < MAX_FOREIGN_RWX; i++ )
        {
            if ( IsTrustedSyscallModule( Parser::ModuleRanges[ i ].ModuleName ) )
            {
                continue;
            }
            UINT64 Base = Parser::ModuleRanges[ i ].Start;
            UINT64 End  = Parser::ModuleRanges[ i ].End;
            if ( End <= Base )
            {
                continue;
            }
            UINT64 Span = End - Base;
            if ( Span > 0x200000 )
            {
                Span = 0x200000;
            }
            UINT64 ScanEnd = Base + Span;

            __try
            {
                for ( UINT64 P = Base; P + 4 < ScanEnd; P++ )
                {
                    BYTE* B = ( BYTE* )P;
                    if ( B[ 0 ] != SYSCALL_BYTE0 || B[ 1 ] != SYSCALL_BYTE1 )
                    {
                        continue;
                    }
                    BOOL LooksLikeStub =
                        B[ 2 ] == 0xC3 ||
                        B[ 3 ] == 0xC3 ||
                        B[ 4 ] == 0xC3;
                    if ( !LooksLikeStub )
                    {
                        continue;
                    }
                    if ( AlreadyReported( P ) )
                    {
                        continue;
                    }
                    CHAR Note[ 240 ];
                    sprintf_s(
                        Note,
                        sizeof( Note ),
                        "[hallwatch] scan: module-text syscall stub at 0x%016llX in %s -- Hell's Gate inside loaded module .text\n",
                        ( UINT64 )P,
                        Parser::ModuleRanges[ i ].ModuleName
                    );
                    Console::Notice( Note );
                    Hits++;
                    if ( Hits >= MAX_FOREIGN_RWX )
                    {
                        break;
                    }
                }
            }
            __except ( EXCEPTION_EXECUTE_HANDLER )
            {
            }
        }
    }

    STATIC VOID
    ScanForeignRwxSyscalls(
        VOID
    )
    {
        MEMORY_BASIC_INFORMATION Mbi = { };
        UINT64 Cursor   = 0x10000;
        UINT64 MaxAddr  = ( UINT64 )0x7FFFFFFFFFFF;
        UINT32 Hits     = 0;

        while ( Cursor < MaxAddr && Hits < MAX_FOREIGN_RWX )
        {
            SIZE_T Got = VirtualQuery( ( PVOID )Cursor, &Mbi, sizeof( Mbi ) );
            if ( Got == 0 )
            {
                break;
            }
            UINT64 RegionBase = ( UINT64 )Mbi.BaseAddress;
            UINT64 RegionSize = ( UINT64 )Mbi.RegionSize;
            UINT64 NextCursor = RegionBase + RegionSize;
            if ( NextCursor <= Cursor )
            {
                break;
            }
            Cursor = NextCursor;

            if ( Mbi.State != MEM_COMMIT )
            {
                continue;
            }
            ULONG Prot = Mbi.Protect & 0xFF;
            BOOL  IsExec =
                ( Prot == PAGE_EXECUTE )           ||
                ( Prot == PAGE_EXECUTE_READ )      ||
                ( Prot == PAGE_EXECUTE_READWRITE ) ||
                ( Prot == PAGE_EXECUTE_WRITECOPY );
            
            if ( !IsExec )
            {
                continue;
            }
            if ( IsAddressInLoadedModule( RegionBase ) )
            {
                continue;
            }
            if ( Guards::TrampolinePool != nullptr &&
                 RegionBase >= ( UINT64 )Guards::TrampolinePool &&
                 RegionBase < ( UINT64 )Guards::TrampolinePool + ( UINT64 )MAX_HOOKS * TRAMPOLINE_SLOT
            )
            {
                continue;
            }

            UINT64 ScanEnd = RegionSize > 0x10000 ? RegionBase + 0x10000 : RegionBase + RegionSize;
            __try
            {
                for ( UINT64 P = RegionBase; P + 1 < ScanEnd; P++ )
                {
                    BYTE* B = ( BYTE* )P;
                    if ( B[ 0 ] == SYSCALL_BYTE0 && B[ 1 ] == SYSCALL_BYTE1 )
                    {
                        if ( AlreadyReported( P ) )
                        {
                            continue;
                        }
                        CHAR Note[ 192 ];
                        sprintf_s( 
                            Note, 
                            sizeof( Note ),
                            "[hallwatch] scan: foreign 0F 05 at 0x%016llX (protect=0x%lX, region 0x%016llX+0x%llX) -- possible Hell's Gate\n",
                            ( UINT64 )P, 
                            Prot, 
                            RegionBase, 
                            ( UINT64 )RegionSize
                        );
                        Console::Notice( Note );
                        Hits++;
                        if ( Hits >= MAX_FOREIGN_RWX )
                        {
                            break;
                        }
                    }
                }
            }
            __except ( EXCEPTION_EXECUTE_HANDLER )
            {
            }
        }
    }

    STATIC DWORD WINAPI
    IntegrityThread(
        LPVOID
    )
    {
        Guards::InternalEnter( );
        Sleep( 50 );

        UINT32 Patched = Guards::PatchAllSyscalls( );
        CHAR Note[ 160 ];
        sprintf_s( 
            Note, 
            sizeof( Note ),
            "[hallwatch] worker patched %u/%u syscalls with INT3, scanner armed\n",
            Patched, 
            Parser::HookCount
        );
        Console::Notice( Note );

        UINT32 Tick = 0;
        while ( InterlockedCompareExchange( &IntegrityRun, 1, 1 ) != 0 )
        {
            Sleep( INTEGRITY_INTERVAL_MS );
            Tick++;

            UINT32 ReHooks = 0;
            for ( UINT32 i = 0; i < Parser::HookCount; i++ )
            {
                if ( !Parser::Hooks[ i ].Armed )
                {
                    continue;
                }
                BYTE Cur = 0;
                __try
                {
                    Cur = *( BYTE* )Parser::Hooks[ i ].SyscallAddress;
                }
                __except ( EXCEPTION_EXECUTE_HANDLER )
                {
                    continue;
                }
                if ( Cur == BP_BYTE )
                {
                    continue;
                }

                CHAR Buf[ 192 ];
                sprintf_s( 
                    Buf, 
                    sizeof( Buf ),
                    "[hallwatch] integrity: %s syscall at 0x%016llX restored to 0x%02X by attacker -- re-patching\n",
                    Parser::Hooks[ i ].Name, 
                    Parser::Hooks[ i ].SyscallAddress, 
                    Cur
                );
                Console::Notice( Buf );
                BYTE Discard = 0;
                if ( Guards::PatchSyscallByte( Parser::Hooks[ i ].SyscallAddress, &Discard ) )
                {
                    ReHooks++;
                }
            }

            ScanForeignRwxSyscalls( );
            ScanModuleTextSyscalls( );

            if ( ( Tick % 50 ) == 0 && VehReRegisterFn != nullptr && VehReRegisterCallback != nullptr )
            {
                PVOID Fresh = VehReRegisterFn( 1, ( PVECTORED_EXCEPTION_HANDLER )VehReRegisterCallback );
                PVOID OldH  = ( PVOID )InterlockedExchangePointer( &VehReRegisterHandle, Fresh );
                if ( OldH != nullptr && OldH != Fresh && VehReRemoveFn != nullptr )
                {
                    VehReRemoveFn( OldH );
                }
            }
        }
        return 0;
    }

    VOID
    Guards::StartIntegrityWorker(
        VOID
    )
    {
        InterlockedExchange( &IntegrityRun, 1 );
        IntegrityWorker = CreateThread( nullptr, 0, IntegrityThread, nullptr, 0, nullptr );
    }

    VOID
    Guards::StopIntegrityWorker(
        VOID
    )
    {
        InterlockedExchange( &IntegrityRun, 0 );
        if ( IntegrityWorker != nullptr )
        {
            WaitForSingleObject( IntegrityWorker, 2000 );
            CloseHandle( IntegrityWorker );
            IntegrityWorker = nullptr;
        }
    }
}
