// pe-walker — inspect the structure of a Portable Executable file.
//
// Reads a .exe or .dll from disk and prints the DOS header, NT headers,
// section layout, import directory, and export directory. Intended as a
// small reference tool for anyone learning the PE/COFF format or needing
// a quick-look utility that doesn't require spinning up a full RE suite.
//
// Build: see CMakeLists.txt (Windows / MSVC or MinGW-w64 / C++17).

#include <windows.h>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "error: cannot open '%s'\n", path.c_str());
        std::exit(1);
    }
    in.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<unsigned char> bytes(size);
    in.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

const char* machine_name(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86 (i386)";
        case IMAGE_FILE_MACHINE_AMD64: return "x64 (AMD64)";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        case IMAGE_FILE_MACHINE_IA64:  return "Itanium";
        default:                       return "unknown";
    }
}

const char* subsystem_name(WORD subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "Windows CUI (console)";
        case IMAGE_SUBSYSTEM_NATIVE:      return "Native (kernel)";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI application";
        default:                          return "unknown";
    }
}

template <typename T>
const T* at(const std::vector<unsigned char>& image, std::size_t offset) {
    if (offset + sizeof(T) > image.size()) {
        std::fprintf(stderr, "error: offset 0x%zx exceeds file size\n", offset);
        std::exit(1);
    }
    return reinterpret_cast<const T*>(image.data() + offset);
}

std::size_t rva_to_offset(const std::vector<unsigned char>& image,
                          const IMAGE_SECTION_HEADER* sections, WORD count,
                          DWORD rva) {
    for (WORD i = 0; i < count; ++i) {
        const auto& s = sections[i];
        if (rva >= s.VirtualAddress &&
            rva < s.VirtualAddress + s.Misc.VirtualSize) {
            return s.PointerToRawData + (rva - s.VirtualAddress);
        }
    }
    return 0;
}

void dump_dos(const IMAGE_DOS_HEADER* dos) {
    std::printf("DOS header\n");
    std::printf("  e_magic   : 0x%04x ('%c%c')\n", dos->e_magic,
                dos->e_magic & 0xff, (dos->e_magic >> 8) & 0xff);
    std::printf("  e_lfanew  : 0x%08lx\n", static_cast<unsigned long>(dos->e_lfanew));
}

void dump_file_header(const IMAGE_FILE_HEADER& fh) {
    std::printf("File header\n");
    std::printf("  machine        : %s (0x%04x)\n", machine_name(fh.Machine), fh.Machine);
    std::printf("  sections       : %u\n", fh.NumberOfSections);
    std::printf("  timestamp      : 0x%08lx\n", static_cast<unsigned long>(fh.TimeDateStamp));
    std::printf("  symtab offset  : 0x%08lx\n", static_cast<unsigned long>(fh.PointerToSymbolTable));
    std::printf("  characteristics: 0x%04x\n", fh.Characteristics);
}

template <typename OptHeader>
void dump_opt_header(const OptHeader& oh) {
    std::printf("Optional header\n");
    std::printf("  entry point    : 0x%08lx\n", static_cast<unsigned long>(oh.AddressOfEntryPoint));
    std::printf("  image base     : 0x%016" PRIx64 "\n", static_cast<std::uint64_t>(oh.ImageBase));
    std::printf("  section align  : 0x%08lx\n", static_cast<unsigned long>(oh.SectionAlignment));
    std::printf("  file align     : 0x%08lx\n", static_cast<unsigned long>(oh.FileAlignment));
    std::printf("  subsystem      : %s (%u)\n", subsystem_name(oh.Subsystem), oh.Subsystem);
    std::printf("  dll chars      : 0x%04x\n", oh.DllCharacteristics);
    std::printf("  size of image  : 0x%08lx\n", static_cast<unsigned long>(oh.SizeOfImage));
    std::printf("  size of headers: 0x%08lx\n", static_cast<unsigned long>(oh.SizeOfHeaders));
}

void dump_sections(const IMAGE_SECTION_HEADER* sections, WORD count) {
    std::printf("Sections (%u)\n", count);
    std::printf("  %-9s %10s %10s %10s %10s %s\n",
                "name", "virt_size", "virt_addr", "raw_size", "raw_offset", "characteristics");
    for (WORD i = 0; i < count; ++i) {
        const auto& s = sections[i];
        char name[9] = {};
        std::memcpy(name, s.Name, 8);
        std::printf("  %-9s 0x%08lx 0x%08lx 0x%08lx 0x%08lx 0x%08lx\n",
                    name,
                    static_cast<unsigned long>(s.Misc.VirtualSize),
                    static_cast<unsigned long>(s.VirtualAddress),
                    static_cast<unsigned long>(s.SizeOfRawData),
                    static_cast<unsigned long>(s.PointerToRawData),
                    static_cast<unsigned long>(s.Characteristics));
    }
}

void dump_imports(const std::vector<unsigned char>& image,
                  const IMAGE_SECTION_HEADER* sections, WORD count,
                  DWORD import_rva, bool is_64) {
    if (!import_rva) {
        std::printf("Imports: (none)\n");
        return;
    }
    const auto imp_off = rva_to_offset(image, sections, count, import_rva);
    if (!imp_off) {
        std::printf("Imports: (RVA 0x%lx not in any section)\n",
                    static_cast<unsigned long>(import_rva));
        return;
    }
    std::printf("Imports\n");
    const auto* desc = at<IMAGE_IMPORT_DESCRIPTOR>(image, imp_off);
    for (std::size_t i = 0; desc[i].Name; ++i) {
        const auto name_off = rva_to_offset(image, sections, count, desc[i].Name);
        if (!name_off) continue;
        const auto* dll_name = reinterpret_cast<const char*>(image.data() + name_off);
        std::printf("  %s\n", dll_name);

        const auto thunk_rva = desc[i].OriginalFirstThunk ? desc[i].OriginalFirstThunk
                                                          : desc[i].FirstThunk;
        const auto thunk_off = rva_to_offset(image, sections, count, thunk_rva);
        if (!thunk_off) continue;

        if (is_64) {
            const auto* thunks = at<ULONGLONG>(image, thunk_off);
            for (std::size_t j = 0; thunks[j]; ++j) {
                if (thunks[j] & 0x8000000000000000ULL) {
                    std::printf("      #%u\n", static_cast<unsigned>(thunks[j] & 0xffff));
                } else {
                    const auto hint_off = rva_to_offset(
                        image, sections, count, static_cast<DWORD>(thunks[j]));
                    if (hint_off && hint_off + 2 < image.size()) {
                        std::printf("      %s\n", reinterpret_cast<const char*>(
                                                      image.data() + hint_off + 2));
                    }
                }
            }
        } else {
            const auto* thunks = at<DWORD>(image, thunk_off);
            for (std::size_t j = 0; thunks[j]; ++j) {
                if (thunks[j] & 0x80000000U) {
                    std::printf("      #%u\n", thunks[j] & 0xffff);
                } else {
                    const auto hint_off = rva_to_offset(image, sections, count, thunks[j]);
                    if (hint_off && hint_off + 2 < image.size()) {
                        std::printf("      %s\n", reinterpret_cast<const char*>(
                                                      image.data() + hint_off + 2));
                    }
                }
            }
        }
    }
}

void dump_exports(const std::vector<unsigned char>& image,
                  const IMAGE_SECTION_HEADER* sections, WORD count,
                  DWORD export_rva) {
    if (!export_rva) {
        std::printf("Exports: (none)\n");
        return;
    }
    const auto exp_off = rva_to_offset(image, sections, count, export_rva);
    if (!exp_off) return;
    const auto* dir = at<IMAGE_EXPORT_DIRECTORY>(image, exp_off);
    std::printf("Exports (%lu by name, %lu by ordinal)\n",
                static_cast<unsigned long>(dir->NumberOfNames),
                static_cast<unsigned long>(dir->NumberOfFunctions));

    const auto name_table_off  = rva_to_offset(image, sections, count, dir->AddressOfNames);
    const auto ord_table_off   = rva_to_offset(image, sections, count, dir->AddressOfNameOrdinals);
    if (!name_table_off || !ord_table_off) return;

    const auto* name_rvas = at<DWORD>(image, name_table_off);
    const auto* ords      = at<WORD>(image, ord_table_off);
    for (DWORD i = 0; i < dir->NumberOfNames; ++i) {
        const auto n_off = rva_to_offset(image, sections, count, name_rvas[i]);
        if (!n_off) continue;
        std::printf("  [%4u] %s\n", ords[i] + dir->Base,
                    reinterpret_cast<const char*>(image.data() + n_off));
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <file.exe|file.dll>\n",
                     argc ? argv[0] : "pe-walker");
        return 2;
    }

    auto image = read_file(argv[1]);

    const auto* dos = at<IMAGE_DOS_HEADER>(image, 0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::fprintf(stderr, "error: not a PE file (bad DOS magic)\n");
        return 1;
    }
    dump_dos(dos);

    const auto nt_off = static_cast<std::size_t>(dos->e_lfanew);
    const auto* sig = at<DWORD>(image, nt_off);
    if (*sig != IMAGE_NT_SIGNATURE) {
        std::fprintf(stderr, "error: missing PE signature\n");
        return 1;
    }

    const auto* fh = at<IMAGE_FILE_HEADER>(image, nt_off + sizeof(DWORD));
    dump_file_header(*fh);

    const auto opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto* magic = at<WORD>(image, opt_off);
    const bool is_64 = (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    DWORD import_rva = 0;
    DWORD export_rva = 0;

    if (is_64) {
        const auto* oh = at<IMAGE_OPTIONAL_HEADER64>(image, opt_off);
        dump_opt_header(*oh);
        import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        export_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } else {
        const auto* oh = at<IMAGE_OPTIONAL_HEADER32>(image, opt_off);
        dump_opt_header(*oh);
        import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        export_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }

    const auto* sections = at<IMAGE_SECTION_HEADER>(
        image, opt_off + fh->SizeOfOptionalHeader);
    dump_sections(sections, fh->NumberOfSections);

    dump_imports(image, sections, fh->NumberOfSections, import_rva, is_64);
    dump_exports(image, sections, fh->NumberOfSections, export_rva);
    return 0;
}
