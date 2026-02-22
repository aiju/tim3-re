# TIM3 — The Incredible Machine 3 Reverse Engineering

## Build Environment Setup

The original game was compiled with Borland C++ 4.5 targeting Win32s. To set up the compiler under Wine:

### Prerequisites

- Wine (tested with Wine Stable on macOS)
- Contents of the Borland C++ 4.5 CD (specifically the `BC45` directory)

### Steps

1. **Create a Wine prefix:**

   ```
   WINEPREFIX=./wine wineboot --init
   ```

2. **Copy the BC45 directory from the CD into the prefix:**

   ```
   cp -r /path/to/cd/BC45 wine/drive_c/BC45
   ```

3. **Fix the config files** to point to `C:\BC45` instead of `D:\BC45` (the CD drive):

   Edit these files in `wine/drive_c/BC45/BIN/`:

   - `TURBOC.CFG` — change `-ID:\BC45\INCLUDE` / `-LD:\BC45\LIB` to `-IC:\BC45\INCLUDE` / `-LC:\BC45\LIB`
   - `TLINK.CFG` — change `-LD:\BC45\LIB` to `-LC:\BC45\LIB`
   - `BCC32.CFG` — same as TURBOC.CFG
   - `TLINK32.CFG` — same as TLINK.CFG

4. **Symlink the game directory into the prefix:**

   ```
   ln -s "$(pwd)/TIM3" wine/drive_c/TIM3
   ```

5. **Test the compiler:**

   ```
   WINEPREFIX=./wine wine C:\\BC45\\BIN\\BCC32.EXE -c C:\\test.c
   ```

### Notes

- Only the 32-bit tools (`BCC32.EXE`, `TLINK32.EXE`) work under Wine. The 16-bit DOS tools (`BCC.EXE`, `TLINK.EXE`) require DOSBox.
- The original game was compiled as a Win32s application (32-bit), so `BCC32` is the correct compiler.
