// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#ifndef HALLWATCH_COMMON_H
#define HALLWATCH_COMMON_H

#include <Windows.h>

#ifndef STATIC
#define STATIC static
#endif

namespace HaW
{
    constexpr UINT32 MAX_HOOKS               = 600;
    constexpr UINT32 MAX_TRUSTED_MODULES     = 16;
    constexpr UINT32 MAX_MODULE_RANGES       = 128;
    constexpr UINT32 MAX_FOREIGN_RWX         = 256;

    constexpr UINT32 STUB_SCAN_LIMIT         = 32;
    constexpr UINT32 STUB_LENGTH             = 0x20;
    constexpr UINT64 MIN_VALID_ADDRESS       = 0x10000;
    constexpr UINT64 PAGE_SZ                 = 0x1000;
    constexpr UINT64 PAGE_MASK_              = ~( PAGE_SZ - 1 );
    constexpr UINT32 TRAMPOLINE_SLOT         = 32;
    constexpr UINT32 STACK_WALK_DEPTH        = 5;
    constexpr UINT32 INTEGRITY_INTERVAL_MS   = 250;
    constexpr BYTE   BP_BYTE                 = 0xCC;
    constexpr BYTE   SYSCALL_BYTE0           = 0x0F;
    constexpr BYTE   SYSCALL_BYTE1           = 0x05;
}

#ifndef STATUS_GUARD_PAGE_VIOLATION
#define STATUS_GUARD_PAGE_VIOLATION ( ( DWORD )0x80000001L )
#endif

#endif
