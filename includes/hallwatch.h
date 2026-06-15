// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#ifndef HALLWATCH_H
#define HALLWATCH_H

#include <Windows.h>

namespace HaW
{
    class Detector
    {
    public:
        static BOOL Initialize( VOID );
        static LONG DetectionCount( VOID );
        static VOID Shutdown( VOID );
        static VOID Flush( VOID );
    };
}

extern "C" BOOLEAN IscInitialize( VOID );
extern "C" LONG    IscGetDetectionCount( VOID );
extern "C" VOID    IscShutdown( VOID );
extern "C" VOID    IscFlush( VOID );

#endif
