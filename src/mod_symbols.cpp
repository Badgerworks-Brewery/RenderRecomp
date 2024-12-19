#include <cstring>

#include "n64recomp.h"

struct FileHeader {
    char magic[8]; // N64RSYMS
    uint32_t version;
};

struct FileSubHeaderV1 {
    uint32_t num_sections;
    uint32_t num_dependencies;
    uint32_t num_imports;
    uint32_t num_dependency_events;
    uint32_t num_replacements;
    uint32_t num_exports;
    uint32_t num_callbacks;
    uint32_t num_provided_events;
    uint32_t string_data_size;
};

struct SectionHeaderV1 {
    uint32_t flags;
    uint32_t file_offset;
    uint32_t vram;
    uint32_t rom_size;
    uint32_t bss_size;
    uint32_t num_funcs;
    uint32_t num_relocs;
};

struct FuncV1 {
    uint32_t section_offset;
    uint32_t size;
};

// Local section flag, if set then the reloc is pointing to a section within the mod and the vrom is the section index.
constexpr uint32_t SectionSelfVromFlagV1 = 0x80000000;

// Special sections
constexpr uint32_t SectionImportVromV1 = 0xFFFFFFFE;
constexpr uint32_t SectionEventVromV1 = 0xFFFFFFFD;

struct RelocV1 {
    uint32_t section_offset;
    uint32_t type;
    uint32_t target_section_offset_or_index; // If this reloc references a special section (see above), this indicates the section's symbol index instead
    uint32_t target_section_vrom;
};

struct DependencyV1 {
    uint8_t reserved;
    uint32_t mod_id_start;
    uint32_t mod_id_size;
};

struct ImportV1 {
    uint32_t name_start;
    uint32_t name_size;
    uint32_t dependency;
};

struct DependencyEventV1 {
    uint32_t name_start;
    uint32_t name_size;
    uint32_t dependency;
};

struct ReplacementV1 {
    uint32_t func_index;
    uint32_t original_section_vrom;
    uint32_t original_vram;
    uint32_t flags; // force
};

struct ExportV1 {
    uint32_t func_index;
    uint32_t name_start; // offset into the string data
    uint32_t name_size;
};

struct CallbackV1 {
    uint32_t dependency_event_index;
    uint32_t function_index;
};

struct EventV1 {
    uint32_t name_start;
    uint32_t name_size;
};

template <typename T>
const T* reinterpret_data(std::span<const char> data, size_t& offset, size_t count = 1) {
    if (offset + (sizeof(T) * count) > data.size()) {
        return nullptr;
    }

    size_t original_offset = offset;
    offset += sizeof(T) * count;
    return reinterpret_cast<const T*>(data.data() + original_offset);
}

bool check_magic(const FileHeader* header) {
    static const char good_magic[] = {'N','6','4','R','S','Y','M','S'};
    static_assert(sizeof(good_magic) == sizeof(FileHeader::magic));

    return memcmp(header->magic, good_magic, sizeof(good_magic)) == 0;
}

static inline uint32_t round_up_4(uint32_t value) {
    return (value + 3) & (~3);
}

bool parse_v1(std::span<const char> data, const std::unordered_map<uint32_t, uint16_t>& sections_by_vrom, Renderware::Context& mod_context) {
    size_t offset = sizeof(FileHeader);
    const FileSubHeaderV1* subheader = reinterpret_data<FileSubHeaderV1>(data, offset);
    if (subheader == nullptr) {
        return false;
    }

    size_t num_sections = subheader->num_sections;
    size_t num_dependencies = subheader->num_dependencies;
    size_t num_imports = subheader->num_imports;
    size_t num_dependency_events = subheader->num_dependency_events;
    size_t num_replacements = subheader->num_replacements;
    size_t num_exports = subheader->num_exports;
    size_t num_callbacks = subheader->num_callbacks;
    size_t num_provided_events = subheader->num_provided_events;
    size_t string_data_size = subheader->string_data_size;

    if (string_data_size & 0b11) {
        printf("String data size of %zu is not a multiple of 4\n", string_data_size);
        return false;
    }

    const char* string_data = reinterpret_data<char>(data, offset, string_data_size);
    if (string_data == nullptr) {
        return false;
    }

    mod_context.sections.resize(num_sections);
    mod_context.dependencies_by_name.reserve(num_dependencies);
    mod_context.import_symbols.reserve(num_imports);
    mod_context.dependency_events.reserve(num_dependency_events);
    mod_context.replacements.resize(num_replacements);
    mod_context.exported_funcs.resize(num_exports);
    mod_context.callbacks.reserve(num_callbacks);
    mod_context.event_symbols.reserve(num_provided_events);

    for (size_t section_index = 0; section_index < num_sections; section_index++) {
        const SectionHeaderV1* section_header = reinterpret_data<SectionHeaderV1>(data, offset);
        if (section_header == nullptr) {
            return false;
        }

        Renderware::Section& cur_section = mod_context.sections[section_index];

        cur_section.rom_addr = section_header->file_offset;
        cur_section.ram_addr = section_header->vram;
        cur_section.size = section_header->rom_size;
        cur_section.bss_size = section_header->bss_size;
        cur_section.name = "mod_section_" + std::to_string(section_index);
        cur_section.relocatable = true;
        uint32_t num_funcs = section_header->num_funcs;
        uint32_t num_relocs = section_header->num_relocs;

        const FuncV1* funcs = reinterpret_data<FuncV1>(data, offset, num_funcs);
        if (funcs == nullptr) {
            printf("Failed to read funcs (count: %d)\n", num_funcs);
            return false;
        }

        const RelocV1* relocs = reinterpret_data<RelocV1>(data, offset, num_relocs);
        if (relocs == nullptr) {
            printf("Failed to read relocs (count: %d)\n", num_relocs);
            return false;
        }

        size_t start_func_index = mod_context.functions.size();
        mod_context.functions.resize(mod_context.functions.size() + num_funcs);
        cur_section.relocs.resize(num_relocs);

        for (size_t func_index = 0; func_index < num_funcs; func_index++) {
            uint32_t func_rom_addr = cur_section.rom_addr + funcs[func_index].section_offset;
            if ((func_rom_addr & 0b11) != 0) {
                printf("Function %zu in section %zu file offset is not a multiple of 4\n", func_index, section_index);
                return false;
            }

            if ((funcs[func_index].size & 0b11) != 0) {
                printf("Function %zu in section %zu size is not a multiple of 4\n", func_index, section_index);
                return false;
            }

            Renderware::Function& cur_func = mod_context.functions[start_func_index + func_index];
            cur_func.vram = cur_section.ram_addr + funcs[func_index].section_offset;
            cur_func.rom = cur_section.rom_addr + funcs[func_index].section_offset;
            cur_func.words.resize(funcs[func_index].size / sizeof(uint32_t));
            cur_func.section_index = section_index;

            mod_context.functions_by_vram[cur_func.vram].emplace_back(start_func_index + func_index);
        }

        for (size_t reloc_index = 0; reloc_index < num_relocs; reloc_index++) {
            Renderware::Reloc& cur_reloc = cur_section.relocs[reloc_index];
            const RelocV1& reloc_in = relocs[reloc_index];
            cur_reloc.address = cur_section.ram_addr + reloc_in.section_offset;
            cur_reloc.type = static_cast<Renderware::RelocType>(reloc_in.type);
            uint32_t target_section_vrom = reloc_in.target_section_vrom;
            uint16_t reloc_target_section;
            uint32_t reloc_target_section_offset;
            uint32_t reloc_symbol_index;
            if (target_section_vrom == 0) {
                reloc_target_section = 0;
                reloc_target_section_offset = 0;
                reloc_symbol_index = 0;
            }
        }
    }
    return true;
}

Renderware::ModSymbolsError Renderware::parse_mod_symbols(std::span<const char> data, std::span<const uint8_t> binary, const std::unordered_map<uint32_t, uint16_t>& sections_by_vrom, Context& mod_context_out) {
    size_t offset = 0;
    mod_context_out = {};
    const FileHeader* header = reinterpret_data<FileHeader>(data, offset);

    if (header == nullptr) {
        return ModSymbolsError::NotASymbolFile;
    }

    if (!check_magic(header)) {
        return ModSymbolsError::NotASymbolFile;
    }

    bool valid = false;

    switch (header->version) {
        case 1:
            valid = parse_v1(data, sections_by_vrom, mod_context_out);
            break;
        default:
            return ModSymbolsError::UnknownSymbolFileVersion;
    }

    if (!valid) {
        mod_context_out = {};
        return ModSymbolsError::CorruptSymbolFile;
    }

    // Fill in the words for each function.
    for (auto& cur_func : mod_context_out.functions) {
        if (cur_func.rom + cur_func.words.size() * sizeof(cur_func.words[0]) > binary.size()) {
            mod_context_out = {};
            return ModSymbolsError::FunctionOutOfBounds;
        }
        const uint32_t* func_rom = reinterpret_cast<const uint32_t*>(binary.data() + cur_func.rom);
        for (size_t word_index = 0; word_index < cur_func.words.size(); word_index++) {
            cur_func.words[word_index] = func_rom[word_index];
        }
    }

    return ModSymbolsError::Good;
}

template <typename T>
void vec_put(std::vector<uint8_t>& vec, const T* data) {
    size_t start_size = vec.size();
    vec.resize(vec.size() + sizeof(T));
    memcpy(vec.data() + start_size, data, sizeof(T));
}

void vec_put(std::vector<uint8_t>& vec, const std::string& data) {
    size_t start_size = vec.size();
    vec.resize(vec.size() + data.size());
    memcpy(vec.data() + start_size, data.data(), data.size());
}

std::vector<uint8_t> Renderware::symbols_to_bin_v1(const Renderware::Context& context) {
    std::vector<uint8_t> ret{};
    ret.reserve(1024);

    const static FileHeader header {
        .magic = {'N', '6', '4', 'R', 'S', 'Y', 'M', 'S'},
        .version = 1
    };

    vec_put(ret, &header);

    size_t num_dependencies = context.dependencies_by_name.size();
    size_t num_imported_funcs = context.import_symbols.size();
    size_t num_dependency_events = context.dependency_events.size();

    size_t num_exported_funcs = context.exported_funcs.size();
    size_t num_events = context.event_symbols.size();
    size_t num_callbacks = context.callbacks.size();
    size_t num_provided_events = context.event_symbols.size();

    FileSubHeaderV1 sub_header {
        .num_sections = static_cast<uint32_t>(context.sections.size()),
        .num_dependencies = static_cast<uint32_t>(num_dependencies),
        .num_imports = static_cast<uint32_t>(num_imported_funcs),
        .num_dependency_events = static_cast<uint32_t>(num_dependency_events),
        .num_replacements = static_cast<uint32_t>(context.replacements.size()),
        .num_exports = static_cast<uint32_t>(num_exported_funcs),
        .num_callbacks = static_cast<uint32_t>(num_callbacks),
        .num_provided_events = static_cast<uint32_t>(num_provided_events),
        .string_data_size = 0,
    };

    // Record the sub-header offset so the string data size can be filled in later.
    size_t sub_header_offset = ret.size();
    vec_put(ret, &sub_header);

    // Build the string data from the exports and imports.
    size_t strings_start = ret.size();
    
    // Order the dependencies by their index. This isn't necessary, but it makes the dependency name order
    // in the symbol file match the indices of the dependencies makes debugging easier.
    std::vector<std::string> dependencies_ordered{};
    dependencies_ordered.resize(context.dependencies_by_name.size());

    for (const auto& [dependency, dependency_index] : context.dependencies_by_name) {
        dependencies_ordered[dependency_index] = dependency;
    }

    // Track the start of every dependency's name in the string data.
    std::vector<uint32_t> dependency_name_positions{};
    dependency_name_positions.resize(num_dependencies);
    for (size_t dependency_index = 0; dependency_index < num_dependencies; dependency_index++) {
        const std::string& dependency = dependencies_ordered[dependency_index];

        dependency_name_positions[dependency_index] = static_cast<uint32_t>(ret.size() - strings_start);
        vec_put(ret, dependency);
    }

    // Track the start of every imported function's name in the string data.
    std::vector<uint32_t> imported_func_name_positions{};
    imported_func_name_positions.resize(num_imported_funcs);
    for (size_t import_index = 0; import_index < num_imported_funcs; import_index++) {
        const ImportSymbol& imported_func = context.import_symbols[import_index];

        // Write this import's name into the strings data.
        imported_func_name_positions[import_index] = static_cast<uint32_t>(ret.size() - strings_start);
        vec_put(ret, imported_func.base.name);
    }

    // Track the start of every dependency event's name in the string data.
    std::vector<uint32_t> dependency_event_name_positions{};
    dependency_event_name_positions.resize(num_dependency_events);
    for (size_t dependency_event_index = 0; dependency_event_index < num_dependency_events; dependency_event_index++) {
        const DependencyEvent& dependency_event = context.dependency_events[dependency_event_index];

        dependency_event_name_positions[dependency_event_index] = static_cast<uint32_t>(ret.size() - strings_start);
        vec_put(ret, dependency_event.event_name);
    }
    
    // Track the start of every exported function's name in the string data.
    std::vector<uint32_t> exported_func_name_positions{};
    exported_func_name_positions.resize(num_exported_funcs);
    for (size_t export_index = 0; export_index < num_exported_funcs; export_index++) {
        size_t function_index = context.exported_funcs[export_index];
        const Function& exported_func = context.functions[function_index];

        exported_func_name_positions[export_index] = static_cast<uint32_t>(ret.size() - strings_start);
        vec_put(ret, exported_func.name);
    }

    // Track the start of every provided event's name in the string data.
    std::vector<uint32_t> event_name_positions{};
    event_name_positions.resize(num_events);
    for (size_t event_index = 0; event_index < num_events; event_index++) {
        const EventSymbol& event_symbol = context.event_symbols[event_index];

        // Write this event's name into the strings data.
        event_name_positions[event_index] = static_cast<uint32_t>(ret.size() - strings_start);
        vec_put(ret, event_symbol.base.name);
    }

    // Align the data after the strings to 4 bytes.
    size_t strings_size = round_up_4(ret.size() - strings_start);
    ret.resize(strings_size + strings_start);

    // Fill in the string data size in the sub-header.
    reinterpret_cast<FileSubHeaderV1*>(ret.data() + sub_header_offset)->string_data_size = strings_size;

    for (size_t section_index = 0; section_index < context.sections.size(); section_index++) {
        const Section& cur_section = context.sections[section_index];
        SectionHeaderV1 section_out {
            .file_offset = cur_section.rom_addr,
            .vram = cur_section.ram_addr,
            .rom_size = cur_section.size,
            .bss_size = cur_section.bss_size,
            .num_funcs = static_cast<uint32_t>(context.section_functions[section_index].size()),
            .num_relocs = static_cast<uint32_t>(cur_section.relocs.size())
        };

        vec_put(ret, &section_out);

        for (size_t func_index : context.section_functions[section_index]) {
            const Function& cur_func = context.functions[func_index];
            FuncV1 func_out {
                .section_offset = cur_func.vram - cur_section.ram_addr,
                .size = (uint32_t)(cur_func.words.size() * sizeof(cur_func.words[0])) 
            };

            vec_put(ret, &func_out);
        }

        for (size_t reloc_index = 0; reloc_index < cur_section.relocs.size(); reloc_index++) {
            const Reloc& cur_reloc = cur_section.relocs[reloc_index];
            uint32_t target_section_vrom;
            uint32_t target_section_offset_or_index = cur_reloc.target_section_offset;
            if (cur_reloc.target_section == SectionAbsolute) {
                printf("Internal error: reloc %zu in section %zu references an absolute symbol and should have been relocated already. Please report this issue.\n",
                    reloc_index, section_index);
                return {};
            }
            else if (cur_reloc.target_section == SectionImport) {
                target_section_vrom = SectionImportVromV1;
                target_section_offset_or_index = cur_reloc.symbol_index;
            }
            else if (cur_reloc.target_section == SectionEvent) {
                target_section_vrom = SectionEventVromV1;
                target_section_offset_or_index = cur_reloc.symbol_index;
            }
            else if (cur_reloc.reference_symbol) {
                target_section_vrom = context.get_reference_section_rom(cur_reloc.target_section);
            }
            else {
                if (cur_reloc.target_section >= context.sections.size()) {
                    printf("Internal error: reloc %zu in section %zu references section %u, but only %zu exist. Please report this issue.\n",
                        reloc_index, section_index, cur_reloc.target_section, context.sections.size());
                    return {};
                }
                target_section_vrom = SectionSelfVromFlagV1 | cur_reloc.target_section;
            }
            RelocV1 reloc_out {
                .section_offset = cur_reloc.address - cur_section.ram_addr,
                .type = static_cast<uint32_t>(cur_reloc.type),
                .target_section_offset_or_index = target_section_offset_or_index,
                .target_section_vrom = target_section_vrom
            };

            vec_put(ret, &reloc_out);
        }
    }

    // Write the dependencies.
    for (size_t dependency_index = 0; dependency_index < num_dependencies; dependency_index++) {
        const std::string& dependency = dependencies_ordered[dependency_index];

        DependencyV1 dependency_out {
            .mod_id_start = dependency_name_positions[dependency_index],
            .mod_id_size = static_cast<uint32_t>(dependency.size())
        };

        vec_put(ret, &dependency_out);
    }

    // Write the imported functions.
    for (size_t import_index = 0; import_index < num_imported_funcs; import_index++) {
        // Get the index of the reference symbol for this import.
        const ImportSymbol& imported_func = context.import_symbols[import_index];

        ImportV1 import_out {
            .name_start = imported_func_name_positions[import_index],
            .name_size = static_cast<uint32_t>(imported_func.base.name.size()),
            .dependency = static_cast<uint32_t>(imported_func.dependency_index)
        };

        vec_put(ret, &import_out);
    }

    // Write the dependency events.
    for (size_t dependency_event_index = 0; dependency_event_index < num_dependency_events; dependency_event_index++) {
        const DependencyEvent& dependency_event = context.dependency_events[dependency_event_index];

        DependencyEventV1 dependency_event_out {
            .name_start = dependency_event_name_positions[dependency_event_index],
            .name_size = static_cast<uint32_t>(dependency_event.event_name.size()),
            .dependency = static_cast<uint32_t>(dependency_event.dependency_index)
        };

        vec_put(ret, &dependency_event_out);
    }

    // Write the function replacements.
    for (const FunctionReplacement& cur_replacement : context.replacements) {
        uint32_t flags = 0;
        if ((cur_replacement.flags & ReplacementFlags::Force) == ReplacementFlags::Force) {
            flags |= 0x1;
        }

        ReplacementV1 replacement_out {
            .func_index = cur_replacement.func_index,
            .original_section_vrom = cur_replacement.original_section_vrom,
            .original_vram = cur_replacement.original_vram,
            .flags = flags
        };

        vec_put(ret, &replacement_out);
    };

    // Write the exported functions.
    for (size_t export_index = 0; export_index < num_exported_funcs; export_index++) {
        size_t function_index = context.exported_funcs[export_index];
        const Function& exported_func = context.functions[function_index];

        ExportV1 export_out {
            .func_index = static_cast<uint32_t>(function_index),
            .name_start = exported_func_name_positions[export_index],
            .name_size = static_cast<uint32_t>(exported_func.name.size())
        };

        vec_put(ret, &export_out);
    }

    // Write the callbacks.
    for (size_t callback_index = 0; callback_index < num_callbacks; callback_index++) {
        const Callback& callback = context.callbacks[callback_index];

        CallbackV1 callback_out {
            .dependency_event_index = static_cast<uint32_t>(callback.dependency_event_index),
            .function_index = static_cast<uint32_t>(callback.function_index)
        };

        vec_put(ret, &callback_out);
    }

    // Write the provided events.
    for (size_t event_index = 0; event_index < num_events; event_index++) {
        const EventSymbol& event_symbol = context.event_symbols[event_index];

        EventV1 event_out {
            .name_start = event_name_positions[event_index],
            .name_size = static_cast<uint32_t>(event_symbol.base.name.size())
        };

        vec_put(ret, &event_out);
    }

    return ret;
}
