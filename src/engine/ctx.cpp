// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#include "hallwatch/ctx.h"
#include "hallwatch/parser.h"
#include "hallwatch/hooks.h"

namespace HaW
{
    BOOL
    Ctx::IsTrustedCaller(
        UINT64 Address
    )
    {
        if ( Address < MIN_VALID_ADDRESS )
        {
            return FALSE;
        }
        for ( UINT32 i = 0; i < Parser::TrustedRangeCount; i++ )
        {
            if ( Address >= Parser::TrustedRanges[ i ].Start && Address < Parser::TrustedRanges[ i ].End )
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    BOOL
    Ctx::IsKnownImageRip(
        UINT64 Address
    )
    {
        if ( Address < MIN_VALID_ADDRESS )
        {
            return FALSE;
        }
        for ( UINT32 i = 0; i < Parser::ModuleRangeCount; i++ )
        {
            if ( Address >= Parser::ModuleRanges[ i ].Start && Address < Parser::ModuleRanges[ i ].End )
            {
                return TRUE;
            }
        }
        return FALSE;
    }

    UINT32
    Ctx::FirstSuspiciousFrame(
        PCONTEXT StartContext
    )
    {
        CONTEXT Walk = *StartContext;
        for ( UINT32 Depth = 0; Depth < STACK_WALK_DEPTH; Depth++ )
        {
            if ( Walk.Rip == 0 )
            {
                return 0;
            }
            if ( !IsKnownImageRip( Walk.Rip ) )
            {
                return Depth + 1;
            }

            UINT64            ImageBase = 0;
            PRUNTIME_FUNCTION Rf        = RtlLookupFunctionEntry( Walk.Rip, &ImageBase, nullptr );
            if ( Rf == nullptr )
            {
                if ( Depth > 0 )
                {
                    return Depth + 1;
                }
                return 0;
            }

            PVOID  HandlerData      = nullptr;
            UINT64 EstablisherFrame = 0;
            __try
            {
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, ImageBase, Walk.Rip, Rf, &Walk, &HandlerData, &EstablisherFrame, nullptr );
            }
            __except ( EXCEPTION_EXECUTE_HANDLER )
            {
                return Depth + 1;
            }
        }
        return 0;
    }
}
