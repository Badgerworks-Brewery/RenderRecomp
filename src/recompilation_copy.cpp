#include <vector>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <cassert>

#include "rabbitizer.hpp"
#include "fmt/format.h"
#include "fmt/ostream.h"
#include "Renderware.h" // Include Renderware headers

enum class JalResolutionResult {
    NoMatch,
    Match,
    CreateStatic,
    Ambiguous,
    Error
};

JalResolutionResult resolve_jal(const Renderware::Context& context, size_t cur_section_index, uint32_t target_func_vram, size_t& matched_function_index) {
    // Placeholder implementation for resolve_jal
    // TODO: Implement logic for resolving jal instructions
    // Add your logic here
    // Look for symbols with the target vram address
    const Renderware::Section& cur_section = context.sections[cur_section_index];
    const auto matching_funcs_find = context.functions_by_vram.find(target_func_vram);
    uint32_t section_vram_start = cur_section.ram_addr;
    uint32_t section_vram_end = cur_section.ram_addr + cur_section.size;
    bool in_current_section = target_func_vram >= section_vram_start && target_func_vram < section_vram_end;
    bool needs_static = false;
    bool exact_match_found = false;

    thread_local std::vector<size_t> matched_funcs{};
    matched_funcs.clear();

    if (matching_funcs_find != context.functions_by_vram.end()) {
        for (size_t target_func_index : matching_funcs_find->second) {
            const auto& target_func = context.functions[target_func_index];
            if (target_func.words.empty()) {
                if (target_func.vram < 0x8F000000 || target_func.vram > 0x90000000) {
                    continue;
                }
            }
            if (target_func.section_index == cur_section_index) {
                exact_match_found = true;
                matched_funcs.clear();
                matched_funcs.push_back(target_func_index);
                break;
            }
            const auto& target_func_section = context.sections[target_func.section_index];
            if (!target_func_section.relocatable) {
                matched_funcs.push_back(target_func_index);
            }
        }
    }

    if (in_current_section) {
        if (exact_match_found) {
            matched_function_index = matched_funcs[0];
            return JalResolutionResult::Match;
        }
        else {
            return JalResolutionResult::CreateStatic;
        }
    }
    else {
        if (matched_funcs.size() == 0) {
            return JalResolutionResult::NoMatch;
        }
        else if (matched_funcs.size() == 1) {
            matched_function_index = matched_funcs[0];
            return JalResolutionResult::Match;
        }
        else {
            return JalResolutionResult::Ambiguous;
        }
    }
}

bool Renderware::recompile_function(const Renderware::Context& context, const Renderware::Function& func, std::ofstream& output_file, std::span<std::vector<uint32_t>> static_funcs_out, bool tag_reference_relocs) {
    //fmt::print("Recompiling {}\n", func.name);
    std::vector<Renderware::InstructionCpu> instructions;

    fmt::print(output_file,
        "RECOMP_FUNC void {}(uint8_t* rdram, recomp_context* ctx) {{\n"
        // these variables shouldn't need to be preserved across function boundaries, so make them local for more efficient output
        "    uint64_t hi = 0, lo = 0, result = 0;\n"
        "    unsigned int rounding_mode = DEFAULT_ROUNDING_MODE;\n"
        "    int c1cs = 0;\n", // cop1 conditional signal
        func.name);

    // Skip analysis and recompilation of this function is stubbed.
    if (!func.stubbed) {
        // Use a set to sort and deduplicate labels
        std::set<uint32_t> branch_labels;
        instructions.reserve(func.words.size());

        auto hook_find = func.function_hooks.find(-1);
        if (hook_find != func.function_hooks.end()) {
            fmt::print(output_file, "    {}\n", hook_find->second);
        }

        // First pass, disassemble each instruction and collect branch labels
        uint32_t vram = func.vram;
        for (uint32_t word : func.words) {
            const auto& instr = instructions.emplace_back(byteswap(word), vram);

            // If this is a branch or a direct jump, add it to the local label list
            if (instr.isBranch() || instr.getUniqueId() == rabbitizer::InstrId::UniqueId::cpu_j) {
                branch_labels.insert((uint32_t)instr.getBranchVramGeneric());
            }

            // Advance the vram address by the size of one instruction
            vram += 4;
        }

        // Analyze function
        Renderware::FunctionStats stats{};
        if (!Renderware::analyze_function(context, func, instructions, stats)) {
            fmt::print(stderr, "Failed to analyze {}\n", func.name);
            output_file.clear();
            return false;
        }

        std::unordered_set<uint32_t> skipped_insns{};

        // Add jump table labels into function
        for (const auto& jtbl : stats.jump_tables) {
            skipped_insns.insert(jtbl.lw_vram);
            for (uint32_t jtbl_entry : jtbl.entries) {
                branch_labels.insert(jtbl_entry);
            }
        }

        // Second pass, emit code for each instruction and emit labels
        auto cur_label = branch_labels.cbegin();
        vram = func.vram;
        int num_link_branches = 0;
        int num_likely_branches = 0;
        bool needs_link_branch = false;
        bool in_likely_delay_slot = false;
        const auto& section = context.sections[func.section_index];
        size_t reloc_index = 0;
        for (size_t instr_index = 0; instr_index < instructions.size(); ++instr_index) {
            bool had_link_branch = needs_link_branch;
            bool is_branch_likely = false;
            // If we're in the delay slot of a likely instruction, emit a goto to skip the instruction before any labels
            if (in_likely_delay_slot) {
                fmt::print(output_file, "    goto skip_{};\n", num_likely_branches);
            }
            // If there are any other branch labels to insert and we're at the next one, insert it
            if (cur_label != branch_labels.end() && vram >= *cur_label) {
                fmt::print(output_file, "L_{:08X}:\n", *cur_label);
                ++cur_label;
            }

            // Advance the reloc index until we reach the last one or until we get to/pass the current instruction
            while ((reloc_index + 1) < section.relocs.size() && section.relocs[reloc_index].address < vram) {
                reloc_index++;
            }

            // Process the current instruction and check for errors
            if (process_instruction(context, func, stats, skipped_insns, instr_index, instructions, output_file, false, needs_link_branch, num_link_branches, reloc_index, needs_link_branch, is_branch_likely, tag_reference_relocs, static_funcs_out) == false) {
                fmt::print(stderr, "Error in recompiling {}, clearing output file\n", func.name);
                output_file.clear();
                return false;
            }
            // If a link return branch was generated, advance the number of link return branches
            if (had_link_branch) {
                num_link_branches++;
            }
            // Now that the instruction has been processed, emit a skip label for the likely branch if needed
            if (in_likely_delay_slot) {
                fmt::print(output_file, "    skip_{}:\n", num_likely_branches);
                num_likely_branches++;
            }
            // Mark the next instruction as being in a likely delay slot if the 
            in_likely_delay_slot = is_branch_likely;
            // Advance the vram address by the size of one instruction
            vram += 4;
        }
    }

    // Terminate the function
    fmt::print(output_file, ";}}\n");
    
    return true;
}

bool process_instruction(const Renderware::Context& context, const Renderware::Function& func, const Renderware::FunctionStats& stats, const std::unordered_set<uint32_t>& skipped_insns, size_t instr_index, const std::vector<Renderware::InstructionCpu>& instructions, std::ofstream& output_file, bool indent, bool emit_link_branch, int link_branch_index, size_t reloc_index, bool& needs_link_branch, bool& is_branch_likely, bool tag_reference_relocs, std::span<std::vector<uint32_t>> static_funcs_out) {
    using namespace Renderware;

    const auto& section = context.sections[func.section_index];
    const auto& instr = instructions[instr_index];
    needs_link_branch = false;
    is_branch_likely = false;
    uint32_t instr_vram = instr.getVram();

    auto print_indent = [&]() {
        fmt::print(output_file, "    ");
    };

    auto hook_find = func.function_hooks.find(instr_index);
    if (hook_find != func.function_hooks.end()) {
        fmt::print(output_file, "    {}\n", hook_find->second);
        if (indent) {
            print_indent();
        }
    }

    // Output a comment with the original instruction
    if (instr.isBranch() || instr.getUniqueId() == InstrId::cpu_j) {
        fmt::print(output_file, "    // 0x{:08X}: {}\n", instr_vram, instr.disassemble(0, fmt::format("L_{:08X}", (uint32_t)instr.getBranchVramGeneric())));
    } else if (instr.getUniqueId() == InstrId::cpu_jal) {
        fmt::print(output_file, "    // 0x{:08X}: {}\n", instr_vram, instr.disassemble(0, fmt::format("0x{:08X}", (uint32_t)instr.getBranchVramGeneric())));
    } else {
        fmt::print(output_file, "    // 0x{:08X}: {}\n", instr_vram, instr.disassemble(0));
    }

    if (skipped_insns.contains(instr_vram)) {
        return true;
    }

    Renderware::RelocType reloc_type = Renderware::RelocType::R_MIPS_NONE;
    uint32_t reloc_section = 0;
    uint32_t reloc_target_section_offset = 0;
    size_t reloc_reference_symbol = (size_t)-1;

    uint32_t func_vram_end = func.vram + func.words.size() * sizeof(func.words[0]);

    uint16_t imm = instr.Get_immediate();

    // Check if this instruction has a reloc.
    if (section.relocs.size() > 0 && section.relocs[reloc_index].address == instr_vram) {
        // Get the reloc data for this instruction
        const auto& reloc = section.relocs[reloc_index];
        reloc_section = reloc.target_section;

        // Check if the relocation references a relocatable section.
        bool target_relocatable = false;
        if (!reloc.reference_symbol && reloc_section != Renderware::SectionAbsolute) {
            const auto& target_section = context.sections[reloc_section];
            target_relocatable = target_section.relocatable;
        }

        // Only process this relocation if the target section is relocatable or if this relocation targets a reference symbol.
        if (target_relocatable || reloc.reference_symbol) {
            // Record the reloc's data.
            reloc_type = reloc.type;
            reloc_target_section_offset = reloc.target_section_offset;
            // Ignore all relocs that aren't MIPS_HI16, MIPS_LO16 or MIPS_26.
            if (reloc_type == Renderware::RelocType::R_MIPS_HI16 || reloc_type == Renderware::RelocType::R_MIPS_LO16 || reloc_type == Renderware::RelocType::R_MIPS_26) {
                if (reloc.reference_symbol) {
                    reloc_reference_symbol = reloc.symbol_index;
                    // Don't try to relocate special section symbols.
                    if (context.is_regular_reference_section(reloc.target_section) || reloc_section == Renderware::SectionAbsolute) {
                        bool ref_section_relocatable = context.is_reference_section_relocatable(reloc.target_section);
                        uint32_t ref_section_vram = context.get_reference_section_vram(reloc.target_section);
                        // Resolve HI16 and LO16 reference symbol relocs to non-relocatable sections by patching the instruction immediate.
                        if (!ref_section_relocatable && (reloc_type == Renderware::RelocType::R_MIPS_HI16 || reloc_type == Renderware::RelocType::R_MIPS_LO16)) {
                            imm = (imm & 0xFFFF) | ((ref_section_vram >> 16) & 0xFFFF0000);
                        }
                    }
                }
            }
        }
    }

    auto print_line = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts ...args) {
        print_indent();
        fmt::vprint(output_file, fmt_str, fmt::make_format_args(args...));
        fmt::print(output_file, ";\n");
    };

    auto print_unconditional_branch = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts ...args) {
        if (instr_index < instructions.size() - 1) {
            bool dummy_needs_link_branch;
            bool dummy_is_branch_likely;
            size_t next_reloc_index = reloc_index;
            uint32_t next_vram = instr_vram + 4;
            if (reloc_index + 1 < section.relocs.size() && next_vram > section.relocs[reloc_index].address) {
                next_reloc_index++;
            }
            if (!process_instruction(context, func, stats, skipped_insns, instr_index + 1, instructions, output_file, false, false, link_branch_index, next_reloc_index, dummy_needs_link_branch, dummy_is_branch_likely, tag_reference_relocs, static_funcs_out)) {
                return false;
            }
        }
        print_indent();
        fmt::vprint(output_file, fmt_str, fmt::make_format_args(args...));
        if (needs_link_branch) {
            fmt::print(output_file, ";\n    goto after_{};\n", link_branch_index);
        } else {
            fmt::print(output_file, ";\n");
        }
        return true;
    };

    auto print_func_call = [reloc_target_section_offset, reloc_section, reloc_reference_symbol, reloc_type, &context, &section, &func, &static_funcs_out, &needs_link_branch, &print_unconditional_branch]
        (uint32_t target_func_vram, bool link_branch = true, bool indent = false)
    {
        // Event symbol, emit a call to the runtime to trigger this event.
        if (reloc_section == Renderware::SectionEvent) {
            needs_link_branch = link_branch;
            if (indent) {
                if (!print_unconditional_branch("    recomp_trigger_event(rdram, ctx, base_event_index + {})", reloc_reference_symbol)) {
                    return false;
                }
            } else {
                if (!print_unconditional_branch("recomp_trigger_event(rdram, ctx, base_event_index + {})", reloc_reference_symbol)) {
                    return false;
                }
            }
        }
        // Normal symbol or reference symbol,
        else {
            std::string jal_target_name{};
            if (reloc_reference_symbol != (size_t)-1) {
                const auto& ref_symbol = context.get_reference_symbol(reloc_section, reloc_reference_symbol);

                if (reloc_type != Renderware::RelocType::R_MIPS_26) {
                    fmt::print(stderr, "Unsupported reloc type {} on jal instruction in {}\n", (int)reloc_type, func.name);
                    return false;
                }

                if (ref_symbol.section_offset != reloc_target_section_offset) {
                    fmt::print(stderr, "Function {} uses a MIPS_R_26 addend, which is not supported yet\n", func.name);
                    return false;
                }

                jal_target_name = ref_symbol.name;
            }
            else {
                size_t matched_func_index = 0;
                JalResolutionResult jal_result = resolve_jal(context, func.section_index, target_func_vram, matched_func_index);

                switch (jal_result) {
                    case JalResolutionResult::NoMatch:
                        fmt::print(stderr, "No function found for jal target: 0x{:08X}\n", target_func_vram);
                        return false;
                    case JalResolutionResult::Match:
                        jal_target_name = context.functions[matched_func_index].name;
                        break;
                    case JalResolutionResult::CreateStatic:
                        // Create a static function add it to the static function list for this section.
                        jal_target_name = fmt::format("static_{}_{:08X}", func.section_index, target_func_vram);
                        static_funcs_out[func.section_index].push_back(target_func_vram);
                        break;
                    case JalResolutionResult::Ambiguous:
                        fmt::print(stderr, "[Info] Ambiguous jal target 0x{:08X} in function {}, falling back to function lookup\n", target_func_vram, func.name);
                        // Relocation isn't necessary for jumps inside a relocatable section, as this code path will never run if the target vram
                        // is in the current function's section (see the branch for `in_current_section` above).
                        // If a game ever needs to jump between multiple relocatable sections, relocation will be necessary here.
                        jal_target_name = fmt::format("LOOKUP_FUNC(0x{:08X})", target_func_vram);
            }
        }
    }

    // Additional processing logic goes here...
    return true;
}

std::string_view ctx_gpr_prefix(int reg) {
    if (reg != 0) {
        return "ctx->r";
    }
    return "";
}
