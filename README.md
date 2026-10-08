# pe-walker

A small command-line inspector for Portable Executable (PE) files on Windows.
Opens a `.exe` or `.dll`, parses the DOS and NT headers, enumerates sections,
and walks the import and export directories.

Written for anyone learning the PE/COFF format or wanting a quick-look
utility that doesn't require a full reverse engineering suite.

## Build

Requires CMake 3.15+ and either MSVC or MinGW-w64 with C++17 support.

```powershell
cmake -S . -B build
cmake --build build --config Release
```

The resulting binary lives at `build/Release/pe-walker.exe` (MSVC) or
`build/pe-walker.exe` (MinGW).

## Usage

```powershell
pe-walker.exe path\to\file.exe
pe-walker.exe --summary path\to\file.exe
```

### Flags

| flag | effect |
|------|--------|
| `--summary`, `-s` | print headers and section list only; skip the import/export dumps. useful for a quick overview without pages of symbol names. |

## Example output

```
DOS header
  e_magic   : 0x5a4d ('MZ')
  e_lfanew  : 0x000000f8
File header
  machine        : x64 (AMD64) (0x8664)
  sections       : 6
  timestamp      : 0x62f4a1c3
  characteristics: 0x0022
Optional header
  entry point    : 0x00001820
  image base     : 0x0000000140000000
  section align  : 0x00001000
  file align     : 0x00000200
  subsystem      : Windows CUI (console) (3)
  size of image  : 0x00017000
Sections (6)
  name       virt_size  virt_addr   raw_size raw_offset characteristics
  .text     0x00007e4a 0x00001000 0x00008000 0x00000400 0x60000020
  .rdata    0x00003c20 0x00009000 0x00003e00 0x00008400 0x40000040
  ...
Imports
  KERNEL32.dll
      GetProcAddress
      LoadLibraryA
      ...
```

## What it covers

- DOS header (`IMAGE_DOS_HEADER`)
- NT signature and file header (`IMAGE_FILE_HEADER`)
- 32- and 64-bit optional headers (`IMAGE_OPTIONAL_HEADER32/64`)
- Section headers (`IMAGE_SECTION_HEADER`)
- Import directory with per-DLL function lists (name and ordinal imports)
- Export directory with function names and ordinals

## What it doesn't cover (yet)

- Resources (`.rsrc` tree walking)
- Relocations (`.reloc`)
- TLS callbacks
- Debug directory / PDB info extraction
- Delay-loaded imports
- Digital signatures

Contributions welcome.

## License

MIT — see [LICENSE](LICENSE).
