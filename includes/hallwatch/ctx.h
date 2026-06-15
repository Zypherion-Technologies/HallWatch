// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#ifndef HALLWATCH_CTX_H
#define HALLWATCH_CTX_H

#include "types.h"

namespace HaW
{
    class Ctx
    {
    public:
        static BOOL   IsTrustedCaller( UINT64 Address );
        static BOOL   IsKnownImageRip( UINT64 Address );
        static UINT32 FirstSuspiciousFrame( PCONTEXT StartContext );
    };
}

#endif
