// HallWatch — indirect-syscall detector
// Copyright (C) 2026 Adam Zypherion <adam@zypherion.tech>
// Licensed under GPL-3.0.
// Site: https://www.zypherion.tech  |  Discord: https://discord.gg/JXx32jKJXY
// Telegram: https://t.me/zypherion_technologies  |  X: https://x.com/Zypherion_Tech

#include "hallwatch.h"
#include "hallwatch/console.h"
#include <Windows.h>

BOOL APIENTRY
DllMain(
    HMODULE Module,
    DWORD   Reason,
    LPVOID  Reserved
)
{
    UNREFERENCED_PARAMETER( Reserved );

    switch ( Reason )
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls( Module );
        HaW::Detector::Initialize( );
        HaW::Console::Notice( "[hallwatch] active and monitoring\n" );
        break;

    case DLL_PROCESS_DETACH:
        HaW::Detector::Shutdown( );
        break;
    }
    return TRUE;
}
