#include <vector>
#include <set>

#include "rabbitizer.hpp"
#include "fmt/format.h"
#include "fmt/ostream.h"

#include "recomp_port.h"

using InstrId = rabbitizer::InstrId::UniqueId;

std::string_view ctx_gpr_prefix(int reg) {
    if (reg != 0) {
        return "ctx->r";
    }
    return "";
}

bool process_instruction(const RecompPort::Context& context, size_t instr_index, const std::vector<rabbitizer::InstructionCpu>& instructions, std::ofstream& output_file, bool indent, bool emit_link_branch, int link_branch_index, bool& needs_link_branch, bool& is_branch_likely) {
    const auto& instr = instructions[instr_index];
    needs_link_branch = false;
    is_branch_likely = false;

    // Output a comment with the original instruction
    if (instr.isBranch() || instr.getUniqueId() == InstrId::cpu_j) {
        fmt::print(output_file, "    // {}\n", instr.disassemble(0, fmt::format("L_{:08X}", (uint32_t)instr.getBranchVramGeneric())));
    } else if (instr.getUniqueId() == InstrId::cpu_jal) {
        fmt::print(output_file, "    // {}\n", instr.disassemble(0, fmt::format("0x{:08X}", (uint32_t)instr.getBranchVramGeneric())));
    } else {
        fmt::print(output_file, "    // {}\n", instr.disassemble(0));
    }

    auto print_indent = [&]() {
        fmt::print(output_file, "    ");
    };

    auto print_line = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts ...args) {
        print_indent();
        fmt::print(output_file, fmt_str, args...);
        fmt::print(output_file, ";\n");
    };

    auto print_branch_condition = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts ...args) {
        fmt::print(output_file, fmt_str, args...);
        fmt::print(output_file, " ");
    };

    auto print_unconditional_branch = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts ...args) {
        if (instr_index < instructions.size() - 1) {
            bool dummy_needs_link_branch;
            bool dummy_is_branch_likely;
            process_instruction(context, instr_index + 1, instructions, output_file, false, false, link_branch_index, dummy_needs_link_branch, dummy_is_branch_likely);
        }
        print_indent();
        fmt::print(output_file, fmt_str, args...);
        if (needs_link_branch) {
            fmt::print(output_file, ";\n    goto after_{};\n", link_branch_index);
        } else {
            fmt::print(output_file, ";\n");
        }
    };

    auto print_branch = [&]<typename... Ts>(fmt::format_string<Ts...> fmt_str, Ts ...args) {
        fmt::print(output_file, "{{\n    ");
        if (instr_index < instructions.size() - 1) {
            bool dummy_needs_link_branch;
            bool dummy_is_branch_likely;
            process_instruction(context, instr_index + 1, instructions, output_file, true, false, link_branch_index, dummy_needs_link_branch, dummy_is_branch_likely);
        }
        fmt::print(output_file, "        ");
        fmt::print(output_file, fmt_str, args...);
        if (needs_link_branch) {
            fmt::print(output_file, ";\n        goto after_{}", link_branch_index);
        }
        fmt::print(output_file, ";\n    }}\n");
    };

    if (indent) {
        print_indent();
    }

    int rd = (int)instr.GetO32_rd();
    int rs = (int)instr.GetO32_rs();
    int base = rs;
    int rt = (int)instr.GetO32_rt();
    int sa = (int)instr.Get_sa();

    int fd = (int)instr.GetO32_fd();
    int fs = (int)instr.GetO32_fs();
    int ft = (int)instr.GetO32_ft();

    uint16_t imm = instr.Get_immediate();

    switch (instr.getUniqueId()) {
    case InstrId::cpu_nop:
        fmt::print(output_file, "\n");
        break;
    // Arithmetic
    case InstrId::cpu_lui:
        print_line("{}{} = {:#X} << 16", ctx_gpr_prefix(rt), rt, imm);
        break;
    case InstrId::cpu_addu:
        print_line("{}{} = ADD32({}{}, {}{})", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_negu: // pseudo instruction for subu x, 0, y
    case InstrId::cpu_subu:
        print_line("{}{} = SUB32({}{}, {}{})", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_addiu:
        print_line("{}{} = ADD32({}{}, {:#X})", ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, (int16_t)imm);
        break;
    case InstrId::cpu_and:
        print_line("{}{} = {}{} & {}{}", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_andi:
        print_line("{}{} = {}{} & {:#X}", ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, imm);
        break;
    case InstrId::cpu_or:
        print_line("{}{} = {}{} | {}{}", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_ori:
        print_line("{}{} = {}{} | {:#X}", ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, imm);
        break;
    case InstrId::cpu_nor:
        print_line("{}{} = ~({}{} | {}{})", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_xor:
        print_line("{}{} = {}{} ^ {}{}", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_xori:
        print_line("{}{} = {}{} ^ {:#X}", ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, imm);
        break;
    case InstrId::cpu_sll:
        print_line("{}{} = S32({}{}) << {}", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rt), rt, sa);
        break;
    case InstrId::cpu_sllv:
        print_line("{}{} = S32({}{}) << ({}{} & 31)", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs);
        break;
    case InstrId::cpu_sra:
        print_line("{}{} = S32(SIGNED({}{}) >> {})", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rt), rt, sa);
        break;
    case InstrId::cpu_srav:
        print_line("{}{} = S32(SIGNED({}{}) >> ({}{} & 31))", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs);
        break;
    case InstrId::cpu_srl:
        print_line("{}{} = S32(U32({}{}) >> {})", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rt), rt, sa);
        break;
    case InstrId::cpu_srlv:
        print_line("{}{} = S32(U32({}{}) >> ({}{} & 31))", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs);
        break;
    case InstrId::cpu_slt:
        print_line("{}{} = SIGNED({}{}) < SIGNED({}{}) ? 1 : 0", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_slti:
        print_line("{}{} = SIGNED({}{}) < {:#X} ? 1 : 0", ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, (int16_t)imm);
        break;
    case InstrId::cpu_sltu:
        print_line("{}{} = {}{} < {}{} ? 1 : 0", ctx_gpr_prefix(rd), rd, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_sltiu:
        print_line("{}{} = {}{} < {:#X} ? 1 : 0", ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, (int16_t)imm);
        break;
    case InstrId::cpu_mult:
        print_line("uint64_t result = S64({}{}) * S64({}{}); lo = S32(result >> 0); hi = S32(result >> 32)", ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_multu:
        print_line("uint64_t result = U64({}{}) * U64({}{}); lo = S32(result >> 0); hi = S32(result >> 32)", ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_div:
        // Cast to 64-bits before division to prevent artihmetic exception for s32(0x80000000) / -1
        print_line("lo = S32(S64(S32({}{})) / S64(S32({}{}))); hi = S32(S64(S32({}{})) % S64(S32({}{})))", ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_divu:
        print_line("lo = S32(U32({}{}) / U32({}{})); hi = S32(U32({}{}) % U32({}{}))", ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt, ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_mflo:
        print_line("{}{} = lo", ctx_gpr_prefix(rd), rd);
        break;
    case InstrId::cpu_mfhi:
        print_line("{}{} = hi", ctx_gpr_prefix(rd), rd);
        break;
    // Loads
    // TODO ld
    case InstrId::cpu_lw:
        print_line("{}{} = MEM_W({:#X}, {}{})", ctx_gpr_prefix(rt), rt, (int16_t)imm, ctx_gpr_prefix(base), base);
        break;
    case InstrId::cpu_lh:
        print_line("{}{} = MEM_H({:#X}, {}{})", ctx_gpr_prefix(rt), rt, (int16_t)imm, ctx_gpr_prefix(base), base);
        break;
    case InstrId::cpu_lb:
        print_line("{}{} = MEM_B({:#X}, {}{})", ctx_gpr_prefix(rt), rt, (int16_t)imm, ctx_gpr_prefix(base), base);
        break;
    case InstrId::cpu_lhu:
        print_line("{}{} = MEM_HU({:#X}, {}{})", ctx_gpr_prefix(rt), rt, (int16_t)imm, ctx_gpr_prefix(base), base);
        break;
    case InstrId::cpu_lbu:
        print_line("{}{} = MEM_BU({:#X}, {}{})", ctx_gpr_prefix(rt), rt, (int16_t)imm, ctx_gpr_prefix(base), base);
        break;
    // Stores
    case InstrId::cpu_sw:
        print_line("MEM_W({:#X}, {}{}) = {}{}", (int16_t)imm, ctx_gpr_prefix(base), base, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_sh:
        print_line("MEM_H({:#X}, {}{}) = {}{}", (int16_t)imm, ctx_gpr_prefix(base), base, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_sb:
        print_line("MEM_B({:#X}, {}{}) = {}{}", (int16_t)imm, ctx_gpr_prefix(base), base, ctx_gpr_prefix(rt), rt);
        break;
    // TODO lwl, lwr
    // examples:
    // reg =        11111111 01234567
    // mem @ x =             89ABCDEF

    // LWL x + 0 -> FFFFFFFF 89ABCDEF
    // LWL x + 1 -> FFFFFFFF ABCDEF67
    // LWL x + 2 -> FFFFFFFF CDEF4567
    // LWL x + 3 -> FFFFFFFF EF234567

    // LWR x + 0 -> 00000000 01234589
    // LWR x + 1 -> 00000000 012389AB
    // LWR x + 2 -> 00000000 0189ABCD
    // LWR x + 3 -> FFFFFFFF 89ABCDEF
    case InstrId::cpu_lwl:
        print_line("{}{} = MEM_WL({:#X}, {}{})", ctx_gpr_prefix(rt), rt, (int16_t)imm, ctx_gpr_prefix(base), base);
        break;
    case InstrId::cpu_lwr:
        print_line("{}{} = MEM_WR({:#X}, {}{})", ctx_gpr_prefix(rt), rt, (int16_t)imm, ctx_gpr_prefix(base), base);
        break;
    case InstrId::cpu_swl:
        print_line("MEM_WL({:#X}, {}{}) = {}{}", (int16_t)imm, ctx_gpr_prefix(base), base, ctx_gpr_prefix(rt), rt);
        break;
    case InstrId::cpu_swr:
        print_line("MEM_WR({:#X}, {}{}) = {}{}", (int16_t)imm, ctx_gpr_prefix(base), base, ctx_gpr_prefix(rt), rt);
        break;
        
    // Branches
    case InstrId::cpu_jal:
        {
            uint32_t target_func_vram = instr.getBranchVramGeneric();
            const auto matching_funcs_find = context.functions_by_vram.find(target_func_vram);
            if (matching_funcs_find == context.functions_by_vram.end()) {
                fmt::print(stderr, "No function found for jal target: 0x{:08X}\n", target_func_vram);
                return false;
            }
            const auto& matching_funcs_vec = matching_funcs_find->second;
            size_t real_func_index;
            bool ambiguous;
            // If there is more than one corresponding function, look for any that have a nonzero size
            if (matching_funcs_vec.size() > 1) {
                size_t nonzero_func_index = (size_t)-1;
                bool found_nonzero_func = false;
                for (size_t cur_func_index : matching_funcs_vec) {
                    const auto& cur_func = context.functions[cur_func_index];
                    if (cur_func.words.size() != 0) {
                        if (found_nonzero_func) {
                            ambiguous = true;
                            break;
                        }
                        found_nonzero_func = true;
                        nonzero_func_index = cur_func_index;
                    }
                }
                real_func_index = nonzero_func_index;
                ambiguous = false;
            } else {
                real_func_index = matching_funcs_vec.front();
                ambiguous = false;
            }
            if (ambiguous) {
                fmt::print(stderr, "Ambiguous jal target: 0x{:08X}\n", target_func_vram);
                for (size_t cur_func_index : matching_funcs_vec) {
                    const auto& cur_func = context.functions[cur_func_index];
                    fmt::print(stderr, "  {}\n", cur_func.name);
                }
                return false;
            }
            needs_link_branch = true;
            print_unconditional_branch("{}(rdram, ctx)", context.functions[real_func_index].name);
            break;
        }
    case InstrId::cpu_jalr:
        // jalr can only be handled with $ra as the return address register
        if (rd != (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra) {
            fmt::print(stderr, "Invalid return address reg for jalr: f{}\n", rd);
            return false;
        }
        needs_link_branch = true;
        print_unconditional_branch("LOOKUP_FUNC({}{})(rdram, ctx)", ctx_gpr_prefix(rs), rs);
        break;
    case InstrId::cpu_j:
    case InstrId::cpu_b:
        print_unconditional_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_jr:
        if (rs == (int)rabbitizer::Registers::Cpu::GprO32::GPR_O32_ra) {
            print_unconditional_branch("return");
        } else {
            // TODO jump table handling
        }
        break;
    case InstrId::cpu_bnel:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_bne:
        print_indent();
        print_branch_condition("if ({}{} != {}{})", ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_beql:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_beq:
        print_indent();
        print_branch_condition("if ({}{} == {}{})", ctx_gpr_prefix(rs), rs, ctx_gpr_prefix(rt), rt);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_bgezl:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_bgez:
        print_indent();
        print_branch_condition("if (SIGNED({}{}) >= 0)", ctx_gpr_prefix(rs), rs);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_bgtzl:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_bgtz:
        print_indent();
        print_branch_condition("if (SIGNED({}{}) > 0)", ctx_gpr_prefix(rs), rs);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_blezl:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_blez:
        print_indent();
        print_branch_condition("if (SIGNED({}{}) <= 0)", ctx_gpr_prefix(rs), rs);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_bltzl:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_bltz:
        print_indent();
        print_branch_condition("if (SIGNED({}{}) < 0)", ctx_gpr_prefix(rs), rs);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_break:
        print_line("do_break();");
        break;

    // Cop1 loads/stores
    case InstrId::cpu_mtc1:
        if ((fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.u32l = {}{}", fs, ctx_gpr_prefix(rt), rt);
        }
        else {
            // odd fpr
            print_line("ctx->f{}.u32h = {}{}", fs - 1, ctx_gpr_prefix(rt), rt);
        }
        break;
    case InstrId::cpu_mfc1:
        if ((fs & 1) == 0) {
            // even fpr
            print_line("{}{} = ctx->f{}.u32l", ctx_gpr_prefix(rt), rt, fs);
        } else {
            // odd fpr
            print_line("{}{} = ctx->f{}.u32h", ctx_gpr_prefix(rt), rt, fs - 1);
        }
        break;
    case InstrId::cpu_lwc1:
        if ((ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.u32l = MEM_W({:#X}, {}{})", ft, (int16_t)imm, ctx_gpr_prefix(base), base);
        } else {
            // odd fpr
            print_line("ctx->f{}.u32h = MEM_W({:#X}, {}{})", ft - 1, (int16_t)imm, ctx_gpr_prefix(base), base);
        }
        break;
    case InstrId::cpu_ldc1:
        if ((ft & 1) == 0) {
            print_line("ctx->f{}.u64 = MEM_D({:#X}, {}{})", ft, (int16_t)imm, ctx_gpr_prefix(base), base);
        } else {
            fmt::print(stderr, "Invalid operand for ldc1: f{}\n", ft);
            return false;
        }
        break;
    case InstrId::cpu_swc1:
        if ((ft & 1) == 0) {
            // even fpr
            print_line("MEM_W({:#X}, {}{}) = ctx->f{}.u32l", (int16_t)imm, ctx_gpr_prefix(base), base, ft);
        } else {
            // odd fpr
            print_line("MEM_W({:#X}, {}{}) = ctx->f{}.u32h", (int16_t)imm, ctx_gpr_prefix(base), base, ft - 1);
        }
        break;
    case InstrId::cpu_sdc1:
        if ((ft & 1) == 0) {
            print_line("MEM_D({:#X}, {}{}) = ctx->f{}.u64", (int16_t)imm, ctx_gpr_prefix(base), base, ft);
        } else {
            fmt::print(stderr, "Invalid operand for sdc1: f{}\n", ft);
            return false;
        }
        break;

    // Cop1 compares
    case InstrId::cpu_c_lt_s:
        if ((fs & 1) == 0 && (ft & 1) == 0) {
            print_line("c1cs = ctx->f{}.fl <= ctx->f{}.fl", fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand for c.lt.s: f{} f{}\n", fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_c_lt_d:
        if ((fs & 1) == 0 && (ft & 1) == 0) {
            print_line("c1cs = ctx->f{}.d <= ctx->f{}.d", fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand for c.lt.d: f{} f{}\n", fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_c_le_s:
        if ((fs & 1) == 0 && (ft & 1) == 0) {
            print_line("c1cs = ctx->f{}.fl <= ctx->f{}.fl", fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand for c.le.s: f{} f{}\n", fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_c_le_d:
        if ((fs & 1) == 0 && (ft & 1) == 0) {
            print_line("c1cs = ctx->f{}.d <= ctx->f{}.d", fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand for c.le.d: f{} f{}\n", fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_c_eq_s:
        if ((fs & 1) == 0 && (ft & 1) == 0) {
            print_line("c1cs = ctx->f{}.fl == ctx->f{}.fl", fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand for c.eq.s: f{} f{}\n", fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_c_eq_d:
        if ((fs & 1) == 0 && (ft & 1) == 0) {
            print_line("c1cs = ctx->f{}.d == ctx->f{}.d", fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand for c.eq.d: f{} f{}\n", fs, ft);
            return false;
        }
        break;
    
    // Cop1 branches
    case InstrId::cpu_bc1tl:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_bc1t:
        print_indent();
        print_branch_condition("if (c1cs)", ctx_gpr_prefix(rs), rs);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;
    case InstrId::cpu_bc1fl:
        is_branch_likely = true;
        [[fallthrough]];
    case InstrId::cpu_bc1f:
        print_indent();
        print_branch_condition("if (!c1cs)", ctx_gpr_prefix(rs), rs);
        print_branch("goto L_{:08X}", (uint32_t)instr.getBranchVramGeneric());
        break;

    // Cop1 arithmetic
    case InstrId::cpu_mov_s:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = ctx->f{}.fl", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for mov.s: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_mov_d:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = ctx->f{}.d", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for mov.d: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_neg_s:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = -ctx->f{}.fl", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for neg.s: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_neg_d:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = -ctx->f{}.d", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for neg.d: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_abs_s:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = fabsf(ctx->f{}.fl)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for abs.s: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_abs_d:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = fabs(ctx->f{}.d)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for abs.d: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_sqrt_s:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = sqrtf(ctx->f{}.fl)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for sqrt.s: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_sqrt_d:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = sqrt(ctx->f{}.d)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for sqrt.d: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_add_s:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = ctx->f{}.fl + ctx->f{}.fl", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for add.s: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_add_d:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = ctx->f{}.d + ctx->f{}.d", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for add.d: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_sub_s:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = ctx->f{}.fl - ctx->f{}.fl", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for sub.s: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_sub_d:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = ctx->f{}.d - ctx->f{}.d", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for sub.d: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_mul_s:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = MUL_S(ctx->f{}.fl, ctx->f{}.fl)", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for mul.s: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_mul_d:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = MUL_D(ctx->f{}.d, ctx->f{}.d)", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for mul.d: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_div_s:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = DIV_S(ctx->f{}.fl, ctx->f{}.fl)", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for div.s: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_div_d:
        if ((fd & 1) == 0 && (fs & 1) == 0 && (ft & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = DIV_D(ctx->f{}.d, ctx->f{}.d)", fd, fs, ft);
        } else {
            fmt::print(stderr, "Invalid operand(s) for div.d: f{} f{} f{}\n", fd, fs, ft);
            return false;
        }
        break;
    case InstrId::cpu_cvt_s_w:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = CVT_S_W(ctx->f{}.u32l)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for cvt.s.w: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_cvt_d_w:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = CVT_D_W(ctx->f{}.u32l)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for cvt.d.w: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_cvt_d_s:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.d = CVT_D_S(ctx->f{}.fl)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for cvt.d.s: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_cvt_s_d:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.fl = CVT_S_D(ctx->f{}.d)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for cvt.s.d: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_trunc_w_s:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.u32l = TRUNC_W_S(ctx->f{}.fl)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for trunc.w.s: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    case InstrId::cpu_trunc_w_d:
        if ((fd & 1) == 0 && (fs & 1) == 0) {
            // even fpr
            print_line("ctx->f{}.u32l = TRUNC_W_D(ctx->f{}.d)", fd, fs);
        } else {
            fmt::print(stderr, "Invalid operand(s) for trunc.w.d: f{} f{}\n", fd, fs);
            return false;
        }
        break;
    default:
        fmt::print(stderr, "Unhandled instruction: {}\n", instr.getOpcodeName());
        return false;
    }

    if (emit_link_branch) {
        fmt::print(output_file, "    after_{}:\n", link_branch_index);
    }

    return true;
}

bool RecompPort::recompile_function(const RecompPort::Context& context, const RecompPort::Function& func, std::string_view output_path) {
    fmt::print("Recompiling {}\n", func.name);
    std::vector<rabbitizer::InstructionCpu> instructions;

    // Open the output file and write the file header
    std::ofstream output_file{ output_path.data() };
    fmt::print(output_file,
        "#include \"recomp.h\"\n"
        "\n"
        "void {}(uint8_t* restrict rdram, recomp_context* restrict ctx) {{\n"
        // these variables shouldn't need to be preserved across function boundaries, so make them local for more efficient output
        "    uint64_t hi = 0, lo = 0;\n"
        "    int c1cs = 0; \n", // cop1 conditional signal
        func.name);

    // Use a set to sort and deduplicate labels
    std::set<uint32_t> branch_labels;
    instructions.reserve(func.words.size());

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

    // Second pass, emit code for each instruction and emit labels
    auto cur_label = branch_labels.cbegin();
    vram = func.vram;
    int num_link_branches = 0;
    int num_likely_branches = 0;
    bool needs_link_branch = false;
    bool in_likely_delay_slot = false;
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
        // Process the current instruction and check for errors
        if (process_instruction(context, instr_index, instructions, output_file, false, needs_link_branch, num_link_branches, needs_link_branch, is_branch_likely) == false) {
            fmt::print(stderr, "Error in recompilation, clearing {}\n", output_path);
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

    // Terminate the function
    fmt::print(output_file, "}}\n");

    return true;
}