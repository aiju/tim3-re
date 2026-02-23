# Ghidra Reverse Engineering Conventions

## Binary Info

- **Game:** The Incredible Machine 3 (Windows, Sierra Entertainment)
- **Platform:** Win32s (Win32 subset running on Windows 3.1 — cooperative multitasking)
- **Compiler:** Borland C (not C++ — hand-rolled polymorphism, no vtables in objects, all __cdecl)
- **Types:** No native `bool` — boolean functions return `int` (0/1). Use `int` not `bool` in prototypes.
- **SEH:** `_sehSetup` at top of many functions is Borland's structured exception handling boilerplate — ignore it

## Naming Conventions

- **Functions:** `fooBar` camelCase (avoids clashing with Win32 PascalCase like `GetPrivateProfileStringA`)
- **Globals:** `g_fooBar`
- **Local variables/parameters:** `snake_case`
- **libc functions:** Use standard names (`strcpy`, `strrchr`, `strcmp`, etc.)
- **CRT/compiler-generated functions:** Prefix with `_` (e.g., `_crtExit`, `_runStaticDestructors`)
- **Uncertain names:** Suffix with `_MAYBE` when evidence is suggestive but not conclusive (e.g., `g_hasCustomGravity_MAYBE`)
- **Duplicate functions:** Suffix with `_DUP` when Borland C emitted identical code at two addresses (e.g., `getHandleUserData_DUP`)
- **PartType descriptors:** `partFooBar` for the PartType data (e.g., `partConveyorBelt`). Type the data at the address as `PartType`
- **Part-specific callbacks:** `partFooBarCallback` pattern (e.g., `partConveyorBeltCollision`, `partConveyorBeltTick`, `partConveyorBeltPerPartInit`, `partConveyorBeltCreate`, `partConveyorBeltPlacePart`). Use the PartType field name as the suffix: `Collision`, `Tick`, `PerPartInit`, `ActivatePart`, `PlacePart`, `Create`
- **Function pointer struct fields:** Ghidra can't parse inline function pointer syntax in struct definitions. Define a typedef first (e.g., `typedef int (*CollisionFn)(Part *, Part *);`), then use the typedef name as the field type in the struct

## Workflow

- Use Ghidra MCP to decompile and rename functions/variables/globals
- When exploring a function, recursively dig into subfunctions before naming — understand the full context first
- Name things confidently when the evidence is clear; flag uncertainty when guessing
- Use `set_data_type` to type globals, strings, arrays, etc. Always try without `force` first — on conflict it reports what's already defined, so you can decide whether to override with `force=true`
- For `rename_data` to stick, the address must have a defined data type first. Use `set_data_type` to define it, then rename
- Rename parameters and locals alongside functions — don't leave param_1/param_2 behind
- **Local variable rename order:** When renaming auto-generated locals (e.g., `iVar1`, `iVar4`, `iVar8`), rename from highest number to lowest. Ghidra reshuffles variable names after each rename, so renaming `iVar1` first can cause `iVar4` to become `iVar3`, invalidating subsequent renames
- To set parameter names and types, use `set_function_prototype` — but omit the calling convention (e.g., `__cdecl`), as a Ghidra bug causes it to be treated as part of the name
- **`__fastcall` misdetection:** Ghidra sometimes marks functions as `__fastcall` when ECX/EDX values leak through from callers. In this codebase everything is `__cdecl`. Symptoms: unused `param_1`/`param_2` in ECX/EDX, `extraout_ECX`/`extraout_EDX` noise, `in_stack_` references after prototype change. Fix: user must manually change calling convention to `__cdecl` in Ghidra's function editor before setting the prototype via API
- Prefer specific names over generic ones (e.g., `showSierraLogo` over `playIntro`)
- **Custom structs:** Use `create_data_type` to define structs directly from C definitions (e.g., `struct Foo { int x; char name[16]; };`). Use `update=true` to overwrite an existing type. For partially-understood structs, use anonymous fields (`int;`) for unknown members — Ghidra auto-names these as `field4_0x10` etc. in decompilation. Apply structs via `set_function_prototype` or `set_data_type`. Verify field names resolve correctly in decompiled output after applying

## Matched Decompilation

Recompiled C source lives in `src/`. The goal is to produce .obj files whose code is byte-identical to the original binary.

### Workflow

1. **Decompile** the target function via Ghidra MCP (`decompile_function`)
2. **Get original disassembly** via Ghidra MCP (`disassemble_function`) — this is the ground truth
3. **Write a rough first draft** in `src/` — don't overthink it, just clean up the decompilation into readable C and compile it. Seeing what the compiler actually produces is more useful than theorizing about codegen
4. **Compile** with `make` (runs `./bcc` — Borland C 4.5 via Wine)
5. **Compare disassembly** — use `obj-extract/target/debug/obj-extract disasm --compact --with-symbols symbols.jsonl src/foo.obj symbol` to get output in the same format as Ghidra, then compare. Without `--compact`, the output includes hex bytes and uses a more detailed layout, useful for inspecting encodings
6. **Iterate** — adjust the C source until disassembly matches
7. **Sync Ghidra names** — rename globals/functions/data in Ghidra to match names chosen in the C source

### Codegen Pitfalls

Things that affect whether Borland C 4.5 output matches the original:

- **Expression nesting vs. temp variables** — `strcpy(strrchr(buf, '\\'), NULL)` as one expression causes the compiler to pre-push args across calls; splitting into `p = strrchr(...); strcpy(p, NULL);` changes push ordering
- **Globals vs. locals/parameters** — e.g., `GetModuleFileNameA(g_instance, ...)` re-reads from the global, while `GetModuleFileNameA(hInstance, ...)` uses a register
- **Precomputed flags** — `can_evict = (flags & 2) != 0` produces SETNZ+AND; testing `flags & 2` inline each iteration produces different code
- **Variable declaration order** can affect register allocation
- **Borland libc quirks** — e.g., `strcpy` is NULL-safe (writes `'\0'` to dst if src is NULL)
- **`while` with comma operator** — `while (c = *p, c != '\0' && c != ' ')` generates a boolean intermediate (XOR/MOV/TEST). Use `while ((c = *p) != '\0' && c != ' ')` instead for clean short-circuit jumps matching the original
- **Register allocation mismatch** — our Borland C 4.5 sometimes picks different variables for ESI/EDI than the original binary (e.g., putting `argc` in ESI when the original has it on the stack with `i` in ESI). Tried `volatile`, `register`, declaration reordering, `-r-`, pragma options — nothing fixes it. Might be a slightly wrong compiler version or unknown compiler flags. This cascades to which registers hold pointers (EAX vs EDX) and character temps (DL vs AL). Structural code still matches

### Symbol Names

- `__cdecl` functions get a `_` prefix in the object file (e.g., `gameAlloc` → `_gameAlloc`)
- `__stdcall` functions have no prefix (e.g., `WinMain` → `WinMain`)

## Documentation

- **doc.md** — accumulated reverse engineering notes (architecture, structs, subsystem docs). Consult when exploring unfamiliar code areas. These are best-effort guesses from ongoing RE work, not authoritative — always verify against the actual binary before relying on them.

## res-extract Tool

- CLI tool at `res-extract/target/debug/res-extract`, extracts files from RESOURCE.MAP archives
- `res-extract ls` / `res-extract ls -l` — list files (default game dir: `./TIM3/TIMWIN`)
- `res-extract cat <file> ...` — dump file contents to stdout
- `res-extract extract <file> ...` — extract to disk
- `res-extract itf <file> ...` — parse and display ITF interface files (shows control types, IDs, positions, sizes, events)
- `res-extract string <id> ...` — look up strings by getString ID. Group (id/1000) maps to .RES file, index (id%1000) selects the line. E.g., `res-extract string 7008` → group 7 = INFO.RES, line 8 = Pulley. Part names/descriptions: `7001 + typeId` (tab-delimited `index\tName\tDescription`)
- `res-extract string --label <code> ...` — decode UI label codes (SSFNNN format: SS=scale, F=font, NNN=string index). Resolves getString(NNN+2000) from INTRFACE.RES and strips `~` markup (`~C`=color, `~JL/JC/JR`=justify, `~S`=scale, `~F`=font). E.g., `res-extract string --label 31074` → "Not in Solution"
- `res-extract -d <game_dir> ...` — override game directory
