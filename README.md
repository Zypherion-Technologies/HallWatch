# HallWatch
[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-A42E2B?logo=gnu&logoColor=white)](LICENSE)
[![Website](https://img.shields.io/badge/zypherion.tech-1f6feb?logo=googlechrome&logoColor=white)](https://www.zypherion.tech)
[![Discord](https://img.shields.io/badge/Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/JXx32jKJXY)
[![Telegram](https://img.shields.io/badge/Telegram-26A5E4?logo=telegram&logoColor=white)](https://t.me/zypherion_technologies)
[![X](https://img.shields.io/badge/Follow-000000?logo=x&logoColor=white)](https://x.com/Zypherion_Tech)

> Copyright (C) 2026 Adam Zypherion &lt;adam@zypherion.tech&gt; — licensed under GPL-3.0.
---

Indirect syscalls are simple once you have seen one. The loader walks ntdll, reads the SSN out of `Nt*` prologue, finds the `0F 05` two bytes further in, sets r10/rax/rdx/r8/r9 itself, and `jmp`s straight at those two bytes. The syscall happens from inside ntdll. Your hook on the kernel32 export is never touched. Your hook on the ntdll export is never touched. `[RSP]` at the moment of the SYSCALL points back into the loaders RWX page, but nothing about the call looks unusual from outside.

```asm
HellHall proc
    mov  r10, rcx
    mov  eax, dwSSN
    jmp  qword ptr [qAddr]
    ret
HellHall endp
```

The variants have names. Tartarus' Gate and RecycledGate use the syscall instruction belonging to one stub but the SSN of a different one, so even if you log the stub name your hook reports, it is a lie. VEH syscall triggers an access violation intentionally and uses its own VEH to rewrite the context so RIP lands on ntdll's syscall instruction with the registers already prepped. Hell's Gate does not use ntdll at all. The loader writes `0F 05` into its own RWX page and runs from there.

The kernel mode (KM) answer is a driver, i might actually get to this overtime and release an project but not happening anytime soon :D 

---

PAGE_GUARD looks like it should work. Mark the page that holds the syscall bytes with `PAGE_GUARD`, catch the `STATUS_GUARD_PAGE_VIOLATION` in a VEH, inspect, redirect to a private trampoline, set the trap flag, single-step out, arm the page back. One trap per Nt call, no matter how the loader got there. It works against everything except Hell's Gate.

The problem is the OS does not cooperate. PAGE_GUARD is a one shot what does that mean? every time it fires the bit is cleared and you have to put it back. Your handler does syscalls (NtProtect to put the guard back, NtContinue to resume) and those syscalls have stubs and those stubs are on the page you just guarded. i worked around most of that with private syscall stubs built on a separate page we owned (allocate RWX, write `mov r10,rcx; mov eax,SSN; syscall; ret`, lock RX, never touch ntdll's), but it was fragile. Every Windows minor version changed the timing. Every thread the sample spawned was another race against the integrity worker that was rebuilding the guard. Demo success was around 30 to 50 percent across ten runs on the same machine .

Eventually I stopped trying to convince Windows that PAGE_GUARD should behave the way I wanted, and tried overwriting the byte instead.

---

<p align="center">
  <video src="https://github.com/Zypherion-Technologies/HallWatch/raw/main/hallwatch.mp4"
         width="720"
         controls
         muted
         playsinline>
  </video>
</p>

---

The byte at the syscall instruction is `0F 05`. The first byte alone (`0F`) is the prefix for a family of two byte opcodes including SYSCALL, CPUID, and RDTSC. By itself it is not executable; the CPU needs the second byte to decode. If you replace the first byte with `0xCC` (INT3), the pair becomes `CC 05`, which the CPU decodes as INT3 followed by a stray byte it never reaches. Any code path that lands on that address raises `EXCEPTION_BREAKPOINT`.

That is the whole mechanism. Our VEH catches the breakpoint, looks up which stub the address belongs to (we build the map at init time by enumerating ntdll's exports), runs three checks on whoever turned up, and sets `Context->Rip` to a private trampoline that does the real syscall and returns. The byte stays `CC`. The next caller hits it the same way so no page protection flipping back and forth.

To be clear: yes, this is hooking by byte overwrite. it is just not at the byte people usually mean by "ntdll hook". the classic EDR hook overwrites the *first* bytes of the stub with a `JMP <my_func>`:

```asm
ntdll!NtAllocateVirtualMemory:
  E9 ?? ?? ?? ??       jmp my_hook     ; overwrites "mov r10, rcx"
  ...
  0F 05                syscall
  C3                   ret
```

that is exactly what indirect syscalls walk around. the loader reads the SSN itself and jumps straight at the `0F 05`, the prologue (and your jmp) never runs, the hook never fires. what we do is overwrite the *syscall byte itself*:

```asm
ntdll!NtAllocateVirtualMemory:
  4C 8B D1             mov r10, rcx     ; untouched
  B8 18 00 00 00       mov eax, 18h     ; untouched
  CC 05                int3 / 05        ; was 0F 05, we wrote CC over the 0F
  C3                   ret
```

now it does not matter how you got to that address. through the prologue, through an indirect jump that skips the prologue, through a VEH-syscall context rewrite that drops RIP there, whatever. if the CPU executes that byte, it traps. same family of technique as the classic hook, different location, completely different coverage.

The trampoline looks like this:

```asm
F3 0F 1E FA              endbr64
49 89 CA                 mov r10, rcx
B8 <stub SSN>            mov eax, ssn
0F 05                    syscall
C3                       ret
```

---

The three checks are unchanged from the PAGE_GUARD version because they were the right three checks; they just needed somewhere reliable to live.

Return address. `[RSP]` is where the syscall would have returned to. For a real call it is inside `ntdll`, `kernel32`, `kernelbase`, or one of the related runtime DLLs. For Hell's Hall it is inside whatever RWX page the loader is running from. We have a short list of trusted return targets built at init by calling `GetModuleHandle` for those names and reading the `.text` ranges out of their PE headers.

SSN. The stub's prologue has already run before it reaches the syscall byte, so `eax` holds whatever value was loaded into it. If the loader did a Tartarus swap, that value will not match the SSN we read out of this same stub at enumeration. We log the mismatch, and the trampoline writes the correct SSN before its own syscall, so the kernel function that runs is the one that belongs to the byte rather than the one the loader wanted. The technique gets logged and neutralised in the same step.

Stack walk. `RtlVirtualUnwind` from the current context, five frames up. Every frame's RIP should be inside a known module and should have a `RUNTIME_FUNCTION` entry. Shellcode and ROP gadgets fail this even when `[RSP]` itself looks trusted, which a loader can fake (it can predict roughly where its caller will be in memory and forge a believable return address there).

If any check fails, we push a small struct into a lock free ring and the drain thread prints it the next time it wakes

```
[!! hallwatch !!] indirect syscall (untrusted caller, wrong ssn for this stub)
    syscall      : NtAllocateVirtualMemory
    syscall rip  : 0x00007FF827660372
    return addr  : 0x00007FF7EED719D6
    rax (ssn)    : 0x0000000F (stub encodes 0x00000018)
    thread       : 26388
```

---

Hell's Gate is where INT3 stops helping. We never patched the loader's RWX page because we never knew it existed.

What we do instead is the simplest scanner that could work. Every 250 ms the integrity worker walks the address space with `VirtualQuery`, looking at any `MEM_COMMIT` region with an executable page protection. If the region is inside a loaded module it gets skipped. If it is inside our own trampoline pool it gets skipped. Whatever remains is foreign executable memory. We scan up to 64 KB of it for `0F 05` byte pairs, dedupe by address, log each unique hit once, i know its dumb and u also waste cpu cycles but its a poc which shouldnt downplay the situation but does currently.

That catches Hell's Gate in a fresh RWX allocation and it catches shadow ntdll (a loader doing `NtMapViewOfSection` on `ntdll.dll` to get a private copy at a new address). The shadow case is a fun one. The mapping is not in our module snapshot so its syscall instructions show up as foreign executable bytes, even though they came from a perfectly legitimate signed DLL on disk.


---

The integrity worker has two other small jobs. It reads the byte at every patched stub each tick and writes `CC` back if it is not `CC`. That is the simplest possible unhook: sample reads the original `0F` from somewhere (a fresh ntdll mapping, the on-disk PE, a known-good byte table) and writes it back over our patch. We notice on the next tick and patch over again.

Every fiftieth tick (about 12.5 seconds) the worker installs our VEH again at the head of the chain and removes the previous handle. A sample can walk `LdrpVectorHandlerList` and unregister us; the worker bounds how long that gap stays open. Twelve and a half seconds is a long window if you are being attacked and a short one if you are running malware in a sandbox. I will probably shorten it once I have measured the cost of doing it more often.

The worker thread runs with a TLS flag set that the VEH checks. The worker's own syscalls (NtProtect for patching, NtQuery for the scan) trip our breakpoints like anything else, but the flag tells the VEH to skip the detection logic and silently redirect through the trampoline.

---

The critical section initialises itself the first time anyone calls in, via a three-state compare-exchange (0 = uninit, 2 = busy, 1 = ready). It is ugly but it avoids needing a static constructor inside a DLL, which on Windows is a separate set of problems involving the loader lock etc

One ABI thing worth flagging. INT3 is a trap, which means `Context->Rip` points to the *next* instruction when our VEH gets called, not the trap itself. If we patched the byte at `0x7FF827660372`, `Context->Rip` arrives at the VEH as `0x7FF827660373`. The `Record->ExceptionAddress` points to the trap, but we have to reset `Context->Rip = ExceptionAddress` before redirecting it to the trampoline, otherwise the trampoline starts one byte late and the syscall does nothing useful, telling u this beacuse it was a bug that took me bunch of time to find

---

There are four exports. `IscInitialize` arms the detector; DllMain calls it automatically but you can call it from a host process if you want a return value. `IscGetDetectionCount` returns a monotonically-increasing counter. `IscShutdown` waits for in-flight handlers and restores the `0F` bytes. `IscFlush` synchronously drains the ring, useful if you are embedding the detector in a sandbox that needs the events out before the sample exits.

Minimum integration is `LoadLibrary`. DllMain handles init and starts both background threads from there.
> Isc = Indirect Syscalls

---

Things we do not catch yet.

A sample that does integrity checks 

A sample using stubs we did not patch. The current allowlist is about 40 names covering offensive memory, process, thread, section, token, and file primitives. Adding more is incremental as long as DllMain finishes promptly. Patching all 488 stubs from inside the loader lock which is just ehh...

A sample running with kernel privileges. Not a usermode problem.

---

INT3 is what we ended up picking, but the trap mechanism is not the interesting part. The reason it works better than PAGE_GUARD is that the trap does not require an ongoing negotiation with the OS. The byte is `CC`. It stays `CC`. The OS does not have an opinion about which bytes live in ntdll.

