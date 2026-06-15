// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#include "hallwatch/parser.h"
#include <tlhelp32.h>
#include <string.h>

namespace HaW
{
    Hook        Parser::Hooks[ MAX_HOOKS ]                   = { };
    UINT32      Parser::HookCount                            = 0;
    ModuleRange Parser::TrustedRanges[ MAX_TRUSTED_MODULES ] = { };
    UINT32      Parser::TrustedRangeCount                    = 0;
    ModuleRange Parser::ModuleRanges[ MAX_MODULE_RANGES ]    = { };
    UINT32      Parser::ModuleRangeCount                     = 0;

    STATIC CONST CHAR* TrustedModuleNames[ ] =
    {
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "user32.dll",
        "gdi32.dll",
        "win32u.dll",
        "advapi32.dll",
    };

    BOOL
    Parser::GetModuleTextRange(
        HMODULE Module,
        UINT64* Start,
        UINT64* End
    )
    {
        PIMAGE_DOS_HEADER Dos = ( PIMAGE_DOS_HEADER )Module;
        if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
        {
            return FALSE;
        }

        PIMAGE_NT_HEADERS Nt = ( PIMAGE_NT_HEADERS )( ( PBYTE )Module + Dos->e_lfanew );
        if ( Nt->Signature != IMAGE_NT_SIGNATURE )
        {
            return FALSE;
        }

        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION( Nt );
        for ( UINT32 i = 0; i < Nt->FileHeader.NumberOfSections; i++ )
        {
            if ( memcmp( Section[ i ].Name, ".text\0\0\0", 8 ) == 0 )
            {
                *Start = ( UINT64 )Module + Section[ i ].VirtualAddress;
                *End   = *Start + Section[ i ].Misc.VirtualSize;
                return TRUE;
            }
        }
        return FALSE;
    }

    BOOL
    Parser::ParseStub(
        VOID*   StubStart,
        UINT64* SyscallAddress,
        UINT32* Ssn
    )
    {
        PBYTE Bytes = ( PBYTE )StubStart;
        *SyscallAddress = 0;
        *Ssn            = 0;

        __try
        {
            if ( Bytes[ 0 ] == 0x4C && Bytes[ 1 ] == 0x8B && Bytes[ 2 ] == 0xD1 && Bytes[ 3 ] == 0xB8 )
            {
                *Ssn = *( PUINT32 )( Bytes + 4 );
            }
            for ( UINT32 i = 0; i < STUB_SCAN_LIMIT - 1; i++ )
            {
                if ( Bytes[ i ] == 0x0F && Bytes[ i + 1 ] == 0x05 )
                {
                    *SyscallAddress = ( UINT64 )( Bytes + i );
                    return TRUE;
                }
            }
        }
        __except ( EXCEPTION_EXECUTE_HANDLER )
        {
            return FALSE;
        }
        return FALSE;
    }

    VOID
    Parser::BuildTrustedRanges(
        VOID
    )
    {
        TrustedRangeCount = 0;
        for ( SIZE_T i = 0; i < ARRAYSIZE( TrustedModuleNames ); i++ )
        {
            if ( TrustedRangeCount >= MAX_TRUSTED_MODULES )
            {
                break;
            }

            HMODULE M = GetModuleHandleA( TrustedModuleNames[ i ] );
            if ( M == nullptr )
            {
                continue;
            }

            UINT64 S = 0;
            UINT64 E = 0;
            if ( !GetModuleTextRange( M, &S, &E ) )
            {
                continue;
            }

            TrustedRanges[ TrustedRangeCount ].Start = S;
            TrustedRanges[ TrustedRangeCount ].End   = E;
            strncpy_s( TrustedRanges[ TrustedRangeCount ].ModuleName, sizeof( TrustedRanges[ 0 ].ModuleName ), TrustedModuleNames[ i ], _TRUNCATE );
            TrustedRangeCount++;
        }
    }

    VOID
    Parser::SnapshotLoadedModules(
        VOID
    )
    {
        ModuleRangeCount = 0;
        HANDLE Snap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId( ) );
        if ( Snap == INVALID_HANDLE_VALUE )
        {
            return;
        }

        MODULEENTRY32W Me = { };
        Me.dwSize = sizeof( Me );
        if ( Module32FirstW( Snap, &Me ) )
        {
            do
            {
                if ( ModuleRangeCount >= MAX_MODULE_RANGES )
                {
                    break;
                }

                UINT64 S = 0;
                UINT64 E = 0;
                if ( GetModuleTextRange( Me.hModule, &S, &E ) )
                {
                    ModuleRanges[ ModuleRangeCount ].Start = S;
                    ModuleRanges[ ModuleRangeCount ].End   = E;
                    WideCharToMultiByte(
                        CP_ACP, 0, Me.szModule, -1,
                        ModuleRanges[ ModuleRangeCount ].ModuleName,
                        ( int )sizeof( ModuleRanges[ 0 ].ModuleName ),
                        nullptr, nullptr );
                    ModuleRanges[ ModuleRangeCount ].ModuleName[ sizeof( ModuleRanges[ 0 ].ModuleName ) - 1 ] = 0;
                    ModuleRangeCount++;
                }
            } while ( Module32NextW( Snap, &Me ) );
        }
        CloseHandle( Snap );
    }

    UINT32
    Parser::EnumerateNtStubs(
        VOID
    )
    {
        HMODULE Ntdll = GetModuleHandleA( "ntdll.dll" );
        if ( Ntdll == nullptr )
        {
            return 0;
        }

        PIMAGE_DOS_HEADER     Dos    = ( PIMAGE_DOS_HEADER )Ntdll;
        PIMAGE_NT_HEADERS     Nt     = ( PIMAGE_NT_HEADERS )( ( PBYTE )Ntdll + Dos->e_lfanew );
        PIMAGE_DATA_DIRECTORY ExpDir = &Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
        if ( ExpDir->VirtualAddress == 0 )
        {
            return 0;
        }

        PIMAGE_EXPORT_DIRECTORY Exp   = ( PIMAGE_EXPORT_DIRECTORY )( ( PBYTE )Ntdll + ExpDir->VirtualAddress );
        PDWORD                  Funcs = ( PDWORD )( ( PBYTE )Ntdll + Exp->AddressOfFunctions );
        PDWORD                  Names = ( PDWORD )( ( PBYTE )Ntdll + Exp->AddressOfNames );
        PWORD                   Ords  = ( PWORD  )( ( PBYTE )Ntdll + Exp->AddressOfNameOrdinals );

        HookCount = 0;
        for ( DWORD i = 0; i < Exp->NumberOfNames && HookCount < MAX_HOOKS; i++ )
        {
            CONST CHAR* Name = ( CONST CHAR* )( ( PBYTE )Ntdll + Names[ i ] );
            if ( Name[ 0 ] != 'N' || Name[ 1 ] != 't' )
            {
                continue;
            }

            DWORD  Rva  = Funcs[ Ords[ i ] ];
            VOID*  Stub = ( PBYTE )Ntdll + Rva;
            UINT64 Sa   = 0;
            UINT32 Sn   = 0;
            if ( !ParseStub( Stub, &Sa, &Sn ) )
            {
                continue;
            }

            Hooks[ HookCount ].StubEntry      = ( UINT64 )Stub;
            Hooks[ HookCount ].SyscallAddress = Sa;
            Hooks[ HookCount ].ExpectedSsn    = Sn;
            Hooks[ HookCount ].Armed          = FALSE;
            strncpy_s( Hooks[ HookCount ].Name, sizeof( Hooks[ 0 ].Name ), Name, _TRUNCATE );
            HookCount++;
        }
        return HookCount;
    }
}
