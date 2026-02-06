// Copyright 2015, VIXL authors
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name of ARM Limited nor the names of its contributors may be
//     used to endorse or promote products derived from this software without
//     specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "disasm-aarch64.h"

#include <bitset>
#include <cstdlib>
#include <sstream>

namespace vixl {
namespace aarch64 {

std::string Disassembler::GetMnemonicAlias(const Instruction *instr) {
  // Representation of a simple condition for an alias to apply. Mask and
  // post-mask value are combined into a single 64-bit field (similar to
  // unallocated instruction detection elsewhere) such that an alias
  // should be applied if (i & mask_value >> 32) == (mask_value & 0xffffffff).
  using MaskAlias = struct {
    uint64_t mask_value;
    std::string alias;
  };

  // "Simple" alias detection. For each form, one or more masking tests are
  // independently applied to determine if the alias is used.
  using MaskAliasMap = std::unordered_map<uint32_t, std::vector<MaskAlias>>;

  const uint64_t kAllCases = 0x00000000'00000000;
  const uint64_t kRdIsZROrSP = 0x0000001f'0000001f;
  const uint64_t kRnIsZROrSP = 0x000003e0'000003e0;
  const uint64_t kRaIsZROrSP = 0x00007c00'00007c00;
  const uint64_t kAddSubImmZero = 0x003ffc00'00000000;
  const uint64_t kLogImmIsZeroLSL = 0x00c0fc00'00000000;
  const uint64_t kBFMr0s7 = 0x003ffc00'00001c00;
  const uint64_t kBFMr0s15 = 0x003ffc00'00003c00;
  const uint64_t kBFMr0s31 = 0x003ffc00'00007c00;
  const uint64_t kBFMs31 = 0x0000fc00'00007c00;
  const uint64_t kBFMs63 = 0x0000fc00'0000fc00;
  const uint64_t kUMOVIsS = 0x00070000'00040000;
  const uint64_t kNEONQSet = 0x40000000'40000000;
  const uint64_t kSHLLImmh1 = 0x003f0000'00080000;
  const uint64_t kSHLLImmh2 = 0x003f0000'00100000;
  const uint64_t kSHLLImmh4 = 0x003f0000'00200000;

  static const MaskAliasMap maskmap =
      {{"adds_32s_addsub_imm"_h, {{kRdIsZROrSP, "cmn"}}},
       {"adds_64s_addsub_imm"_h, {{kRdIsZROrSP, "cmn"}}},
       {"subs_32s_addsub_imm"_h, {{kRdIsZROrSP, "cmp"}}},
       {"subs_64s_addsub_imm"_h, {{kRdIsZROrSP, "cmp"}}},
       {"add_32_addsub_imm"_h,
        {{kRdIsZROrSP | kAddSubImmZero, "mov"},
         {kRnIsZROrSP | kAddSubImmZero, "mov"}}},
       {"add_64_addsub_imm"_h,
        {{kRdIsZROrSP | kAddSubImmZero, "mov"},
         {kRnIsZROrSP | kAddSubImmZero, "mov"}}},
       {"adds_32_addsub_shift"_h, {{kRdIsZROrSP, "cmn"}}},
       {"adds_64_addsub_shift"_h, {{kRdIsZROrSP, "cmn"}}},
       {"sub_32_addsub_shift"_h, {{kRnIsZROrSP, "neg"}}},
       {"sub_64_addsub_shift"_h, {{kRnIsZROrSP, "neg"}}},
       {"subs_32_addsub_shift"_h,
        {{kRdIsZROrSP, "cmp"}, {kRnIsZROrSP, "negs"}}},
       {"subs_64_addsub_shift"_h,
        {{kRdIsZROrSP, "cmp"}, {kRnIsZROrSP, "negs"}}},
       {"sbc_32_addsub_carry"_h, {{kRnIsZROrSP, "ngc"}}},
       {"sbc_64_addsub_carry"_h, {{kRnIsZROrSP, "ngc"}}},
       {"sbcs_32_addsub_carry"_h, {{kRnIsZROrSP, "ngcs"}}},
       {"sbcs_64_addsub_carry"_h, {{kRnIsZROrSP, "ngcs"}}},
       {"adds_32s_addsub_ext"_h, {{kRdIsZROrSP, "cmn"}}},
       {"adds_64s_addsub_ext"_h, {{kRdIsZROrSP, "cmn"}}},
       {"subs_32s_addsub_ext"_h, {{kRdIsZROrSP, "cmp"}}},
       {"subs_64s_addsub_ext"_h, {{kRdIsZROrSP, "cmp"}}},
       {"ands_32_log_shift"_h, {{kRdIsZROrSP, "tst"}}},
       {"ands_64_log_shift"_h, {{kRdIsZROrSP, "tst"}}},
       {"orr_32_log_shift"_h, {{kRnIsZROrSP | kLogImmIsZeroLSL, "mov"}}},
       {"orr_64_log_shift"_h, {{kRnIsZROrSP | kLogImmIsZeroLSL, "mov"}}},
       {"orn_32_log_shift"_h, {{kRnIsZROrSP, "mvn"}}},
       {"orn_64_log_shift"_h, {{kRnIsZROrSP, "mvn"}}},
       {"ands_32s_log_imm"_h, {{kRdIsZROrSP, "tst"}}},
       {"ands_64s_log_imm"_h, {{kRdIsZROrSP, "tst"}}},
       {"madd_32a_dp_3src"_h, {{kRaIsZROrSP, "mul"}}},
       {"madd_64a_dp_3src"_h, {{kRaIsZROrSP, "mul"}}},
       {"msub_32a_dp_3src"_h, {{kRaIsZROrSP, "mneg"}}},
       {"msub_64a_dp_3src"_h, {{kRaIsZROrSP, "mneg"}}},
       {"smaddl_64wa_dp_3src"_h, {{kRaIsZROrSP, "smull"}}},
       {"smsubl_64wa_dp_3src"_h, {{kRaIsZROrSP, "smnegl"}}},
       {"umaddl_64wa_dp_3src"_h, {{kRaIsZROrSP, "umull"}}},
       {"umsubl_64wa_dp_3src"_h, {{kRaIsZROrSP, "umnegl"}}},
       {"asrv_32_dp_2src"_h, {{kAllCases, "asr"}}},
       {"asrv_64_dp_2src"_h, {{kAllCases, "asr"}}},
       {"lslv_32_dp_2src"_h, {{kAllCases, "lsl"}}},
       {"lslv_64_dp_2src"_h, {{kAllCases, "lsl"}}},
       {"lsrv_32_dp_2src"_h, {{kAllCases, "lsr"}}},
       {"lsrv_64_dp_2src"_h, {{kAllCases, "lsr"}}},
       {"rorv_32_dp_2src"_h, {{kAllCases, "ror"}}},
       {"rorv_64_dp_2src"_h, {{kAllCases, "ror"}}},
       {"b_only_condbranch"_h, {{kAllCases, "b.'CBrn"}}},
       {"bc_only_condbranch"_h, {{kAllCases, "bc.'CBrn"}}},
       {"not_asimdmisc_r"_h, {{kAllCases, "mvn"}}},
       {"dup_z_i"_h, {{kAllCases, "mov"}}},
       {"fdup_z_i"_h, {{kAllCases, "fmov"}}},
       {"dup_z_r"_h, {{kAllCases, "mov"}}},
       {"cpy_z_p_r"_h, {{kAllCases, "mov"}}},
       {"cpy_z_o_i"_h, {{kAllCases, "mov"}}},
       {"cpy_z_p_i"_h, {{kAllCases, "mov"}}},
       {"cpy_z_p_v"_h, {{kAllCases, "mov"}}},
       {"fcpy_z_p_i"_h, {{kAllCases, "fmov"}}},
       {"ins_asimdins_ir_r"_h, {{kAllCases, "mov"}}},
       {"ins_asimdins_iv_v"_h, {{kAllCases, "mov"}}},
       {"umov_asimdins_x_x"_h, {{kAllCases, "mov"}}},
       {"dup_asisdone_only"_h, {{kAllCases, "mov"}}},
       {"umov_asimdins_w_w"_h, {{kUMOVIsS, "mov"}}},
       {"shrn_asimdshf_n"_h, {{kNEONQSet, "shrn2"}}},
       {"rshrn_asimdshf_n"_h, {{kNEONQSet, "rshrn2"}}},
       {"sqshrn_asimdshf_n"_h, {{kNEONQSet, "sqshrn2"}}},
       {"sqrshrn_asimdshf_n"_h, {{kNEONQSet, "sqrshrn2"}}},
       {"sqshrun_asimdshf_n"_h, {{kNEONQSet, "sqshrun2"}}},
       {"sqrshrun_asimdshf_n"_h, {{kNEONQSet, "sqrshrun2"}}},
       {"uqshrn_asimdshf_n"_h, {{kNEONQSet, "uqshrn2"}}},
       {"uqrshrn_asimdshf_n"_h, {{kNEONQSet, "uqrshrn2"}}},
       {"shll_asimdmisc_s"_h, {{kNEONQSet, "shll2"}}},
       {"xtn_asimdmisc_n"_h, {{kNEONQSet, "xtn2"}}},
       {"sqxtn_asimdmisc_n"_h, {{kNEONQSet, "sqxtn2"}}},
       {"uqxtn_asimdmisc_n"_h, {{kNEONQSet, "uqxtn2"}}},
       {"sqxtun_asimdmisc_n"_h, {{kNEONQSet, "sqxtun2"}}},
       {"smlal_asimdelem_l"_h, {{kNEONQSet, "smlal2"}}},
       {"smlsl_asimdelem_l"_h, {{kNEONQSet, "smlsl2"}}},
       {"smull_asimdelem_l"_h, {{kNEONQSet, "smull2"}}},
       {"umlal_asimdelem_l"_h, {{kNEONQSet, "umlal2"}}},
       {"umlsl_asimdelem_l"_h, {{kNEONQSet, "umlsl2"}}},
       {"umull_asimdelem_l"_h, {{kNEONQSet, "umull2"}}},
       {"sqdmull_asimdelem_l"_h, {{kNEONQSet, "sqdmull2"}}},
       {"sqdmlal_asimdelem_l"_h, {{kNEONQSet, "sqdmlal2"}}},
       {"sqdmlsl_asimdelem_l"_h, {{kNEONQSet, "sqdmlsl2"}}},
       {"bfcvtn_asimdmisc_4s"_h, {{kNEONQSet, "bfcvtn2"}}},
       {"fcvtxn_asimdmisc_n"_h, {{kNEONQSet, "fcvtxn2"}}},
       {"sabal_asimddiff_l"_h, {{kNEONQSet, "sabal2"}}},
       {"sabdl_asimddiff_l"_h, {{kNEONQSet, "sabdl2"}}},
       {"saddl_asimddiff_l"_h, {{kNEONQSet, "saddl2"}}},
       {"smlal_asimddiff_l"_h, {{kNEONQSet, "smlal2"}}},
       {"smlsl_asimddiff_l"_h, {{kNEONQSet, "smlsl2"}}},
       {"smull_asimddiff_l"_h, {{kNEONQSet, "smull2"}}},
       {"ssubl_asimddiff_l"_h, {{kNEONQSet, "ssubl2"}}},
       {"uabal_asimddiff_l"_h, {{kNEONQSet, "uabal2"}}},
       {"uabdl_asimddiff_l"_h, {{kNEONQSet, "uabdl2"}}},
       {"uaddl_asimddiff_l"_h, {{kNEONQSet, "uaddl2"}}},
       {"umlal_asimddiff_l"_h, {{kNEONQSet, "umlal2"}}},
       {"umlsl_asimddiff_l"_h, {{kNEONQSet, "umlsl2"}}},
       {"umull_asimddiff_l"_h, {{kNEONQSet, "umull2"}}},
       {"usubl_asimddiff_l"_h, {{kNEONQSet, "usubl2"}}},
       {"saddw_asimddiff_w"_h, {{kNEONQSet, "saddw2"}}},
       {"ssubw_asimddiff_w"_h, {{kNEONQSet, "ssubw2"}}},
       {"uaddw_asimddiff_w"_h, {{kNEONQSet, "uaddw2"}}},
       {"usubw_asimddiff_w"_h, {{kNEONQSet, "usubw2"}}},
       {"addhn_asimddiff_n"_h, {{kNEONQSet, "addhn2"}}},
       {"raddhn_asimddiff_n"_h, {{kNEONQSet, "raddhn2"}}},
       {"rsubhn_asimddiff_n"_h, {{kNEONQSet, "rsubhn2"}}},
       {"subhn_asimddiff_n"_h, {{kNEONQSet, "subhn2"}}},
       {"sqdmlal_asimddiff_l"_h, {{kNEONQSet, "sqdmlal2"}}},
       {"sqdmlsl_asimddiff_l"_h, {{kNEONQSet, "sqdmlsl2"}}},
       {"sqdmull_asimddiff_l"_h, {{kNEONQSet, "sqdmull2"}}},
       {"pmull_asimddiff_l"_h, {{kNEONQSet, "pmull2"}}},
       {"subps_64s_dp_2src"_h, {{kRdIsZROrSP, "cmpp"}}},
       {"sbfm_32m_bitfield"_h,
        {{kBFMr0s7, "sxtb"}, {kBFMr0s15, "sxth"}, {kBFMs31, "asr"}}},
       {"sbfm_64m_bitfield"_h,
        {{kBFMr0s7, "sxtb"},
         {kBFMr0s15, "sxth"},
         {kBFMr0s31, "sxtw"},
         {kBFMs63, "asr"}}},
       {"ubfm_32m_bitfield"_h,
        {{kBFMr0s7, "uxtb"}, {kBFMr0s15, "uxth"}, {kBFMs31, "lsr"}}},
       {"ubfm_64m_bitfield"_h,
        {{kBFMr0s7, "uxtb"}, {kBFMr0s15, "uxth"}, {kBFMs63, "lsr"}}},
       {"sshll_asimdshf_l"_h,
        {{kSHLLImmh1 | kNEONQSet, "sxtl2"},
         {kSHLLImmh2 | kNEONQSet, "sxtl2"},
         {kSHLLImmh4 | kNEONQSet, "sxtl2"},
         {kSHLLImmh1, "sxtl"},
         {kSHLLImmh2, "sxtl"},
         {kSHLLImmh4, "sxtl"},
         {kNEONQSet, "sshll2"},
         {kNEONQSet, "sshll2"},
         {kNEONQSet, "sshll2"}}},
       {"ushll_asimdshf_l"_h,
        {{kSHLLImmh1 | kNEONQSet, "uxtl2"},
         {kSHLLImmh2 | kNEONQSet, "uxtl2"},
         {kSHLLImmh4 | kNEONQSet, "uxtl2"},
         {kSHLLImmh1, "uxtl"},
         {kSHLLImmh2, "uxtl"},
         {kSHLLImmh4, "uxtl"},
         {kNEONQSet, "ushll2"},
         {kNEONQSet, "ushll2"},
         {kNEONQSet, "ushll2"}}},
       {"fcvtl_asimdmisc_l"_h, {{kNEONQSet, "fcvtl2"}}},
       {"fcvtn_asimdmisc_n"_h, {{kNEONQSet, "fcvtn2"}}},
       {"ldaddb_32_memop"_h, {{kRdIsZROrSP, "staddb"}}},
       {"ldaddh_32_memop"_h, {{kRdIsZROrSP, "staddh"}}},
       {"ldaddlb_32_memop"_h, {{kRdIsZROrSP, "staddlb"}}},
       {"ldaddlh_32_memop"_h, {{kRdIsZROrSP, "staddlh"}}},
       {"ldaddl_32_memop"_h, {{kRdIsZROrSP, "staddl"}}},
       {"ldaddl_64_memop"_h, {{kRdIsZROrSP, "staddl"}}},
       {"ldadd_32_memop"_h, {{kRdIsZROrSP, "stadd"}}},
       {"ldadd_64_memop"_h, {{kRdIsZROrSP, "stadd"}}},
       {"ldclrb_32_memop"_h, {{kRdIsZROrSP, "stclrb"}}},
       {"ldclrh_32_memop"_h, {{kRdIsZROrSP, "stclrh"}}},
       {"ldclrlb_32_memop"_h, {{kRdIsZROrSP, "stclrlb"}}},
       {"ldclrlh_32_memop"_h, {{kRdIsZROrSP, "stclrlh"}}},
       {"ldclrl_32_memop"_h, {{kRdIsZROrSP, "stclrl"}}},
       {"ldclrl_64_memop"_h, {{kRdIsZROrSP, "stclrl"}}},
       {"ldclr_32_memop"_h, {{kRdIsZROrSP, "stclr"}}},
       {"ldclr_64_memop"_h, {{kRdIsZROrSP, "stclr"}}},
       {"ldeorb_32_memop"_h, {{kRdIsZROrSP, "steorb"}}},
       {"ldeorh_32_memop"_h, {{kRdIsZROrSP, "steorh"}}},
       {"ldeorlb_32_memop"_h, {{kRdIsZROrSP, "steorlb"}}},
       {"ldeorlh_32_memop"_h, {{kRdIsZROrSP, "steorlh"}}},
       {"ldeorl_32_memop"_h, {{kRdIsZROrSP, "steorl"}}},
       {"ldeorl_64_memop"_h, {{kRdIsZROrSP, "steorl"}}},
       {"ldeor_32_memop"_h, {{kRdIsZROrSP, "steor"}}},
       {"ldeor_64_memop"_h, {{kRdIsZROrSP, "steor"}}},
       {"ldsetb_32_memop"_h, {{kRdIsZROrSP, "stsetb"}}},
       {"ldseth_32_memop"_h, {{kRdIsZROrSP, "stseth"}}},
       {"ldsetlb_32_memop"_h, {{kRdIsZROrSP, "stsetlb"}}},
       {"ldsetlh_32_memop"_h, {{kRdIsZROrSP, "stsetlh"}}},
       {"ldsetl_32_memop"_h, {{kRdIsZROrSP, "stsetl"}}},
       {"ldsetl_64_memop"_h, {{kRdIsZROrSP, "stsetl"}}},
       {"ldset_32_memop"_h, {{kRdIsZROrSP, "stset"}}},
       {"ldset_64_memop"_h, {{kRdIsZROrSP, "stset"}}},
       {"ldsmaxb_32_memop"_h, {{kRdIsZROrSP, "stsmaxb"}}},
       {"ldsmaxh_32_memop"_h, {{kRdIsZROrSP, "stsmaxh"}}},
       {"ldsmaxlb_32_memop"_h, {{kRdIsZROrSP, "stsmaxlb"}}},
       {"ldsmaxlh_32_memop"_h, {{kRdIsZROrSP, "stsmaxlh"}}},
       {"ldsmaxl_32_memop"_h, {{kRdIsZROrSP, "stsmaxl"}}},
       {"ldsmaxl_64_memop"_h, {{kRdIsZROrSP, "stsmaxl"}}},
       {"ldsmax_32_memop"_h, {{kRdIsZROrSP, "stsmax"}}},
       {"ldsmax_64_memop"_h, {{kRdIsZROrSP, "stsmax"}}},
       {"ldsminb_32_memop"_h, {{kRdIsZROrSP, "stsminb"}}},
       {"ldsminh_32_memop"_h, {{kRdIsZROrSP, "stsminh"}}},
       {"ldsminlb_32_memop"_h, {{kRdIsZROrSP, "stsminlb"}}},
       {"ldsminlh_32_memop"_h, {{kRdIsZROrSP, "stsminlh"}}},
       {"ldsminl_32_memop"_h, {{kRdIsZROrSP, "stsminl"}}},
       {"ldsminl_64_memop"_h, {{kRdIsZROrSP, "stsminl"}}},
       {"ldsmin_32_memop"_h, {{kRdIsZROrSP, "stsmin"}}},
       {"ldsmin_64_memop"_h, {{kRdIsZROrSP, "stsmin"}}},
       {"ldumaxb_32_memop"_h, {{kRdIsZROrSP, "stumaxb"}}},
       {"ldumaxh_32_memop"_h, {{kRdIsZROrSP, "stumaxh"}}},
       {"ldumaxlb_32_memop"_h, {{kRdIsZROrSP, "stumaxlb"}}},
       {"ldumaxlh_32_memop"_h, {{kRdIsZROrSP, "stumaxlh"}}},
       {"ldumaxl_32_memop"_h, {{kRdIsZROrSP, "stumaxl"}}},
       {"ldumaxl_64_memop"_h, {{kRdIsZROrSP, "stumaxl"}}},
       {"ldumax_32_memop"_h, {{kRdIsZROrSP, "stumax"}}},
       {"ldumax_64_memop"_h, {{kRdIsZROrSP, "stumax"}}},
       {"lduminb_32_memop"_h, {{kRdIsZROrSP, "stuminb"}}},
       {"lduminh_32_memop"_h, {{kRdIsZROrSP, "stuminh"}}},
       {"lduminlb_32_memop"_h, {{kRdIsZROrSP, "stuminlb"}}},
       {"lduminlh_32_memop"_h, {{kRdIsZROrSP, "stuminlh"}}},
       {"lduminl_32_memop"_h, {{kRdIsZROrSP, "stuminl"}}},
       {"lduminl_64_memop"_h, {{kRdIsZROrSP, "stuminl"}}},
       {"ldumin_32_memop"_h, {{kRdIsZROrSP, "stumin"}}},
       {"ldumin_64_memop"_h, {{kRdIsZROrSP, "stumin"}}}};

  // "Complex" alias detection. For each form, one or more function groups are
  // applied to the encoding. If ALL of the functions in a group return true
  // (ie. intersection) then the alias for that group is used.
  using FuncAlias = struct {
    std::vector<std::function<bool(const Instruction *)>> conditions;
    std::string alias;
  };

  auto RnRmAliased = [](const Instruction *i) {
    return (i->GetRn() == i->GetRm());
  };

  auto RdRmAliased = [](const Instruction *i) {
    return (i->GetRd() == i->GetRm());
  };

  auto PnPmAliased = [](const Instruction *i) {
    return (i->GetPn() == i->GetPm());
  };

  auto PgPmAliased = [](const Instruction *i) {
    return (i->ExtractBits(13, 10) == static_cast<uint32_t>(i->GetPm()));
  };

  auto PdPmAliased = [](const Instruction *i) {
    return (i->GetPd() == i->GetPm());
  };

  auto CondNotAlNv = [](const Instruction *i) {
    return (i->GetCondition() != al) && (i->GetCondition() != nv);
  };

  auto IsNotMovzMovnImmW = [this](const Instruction *i) {
    return !IsMovzMovnImm(kWRegSize, i->GetImmLogical());
  };

  auto IsNotMovzMovnImmX = [this](const Instruction *i) {
    return !IsMovzMovnImm(kXRegSize, i->GetImmLogical());
  };

  auto IsNonOnesMov = [](const Instruction *i) {
    return i->GetImmMoveWide() != 0xffff;
  };

  auto IsNonZeroNoShiftMov = [](const Instruction *i) {
    return i->GetImmMoveWide() || (i->GetShiftMoveWide() == 0);
  };

  auto BitfieldSLessThanR = [](const Instruction *i) {
    return i->GetImmS() < i->GetImmR();
  };
  auto BitfieldRIsSPlus1 = [](const Instruction *i) {
    return i->GetImmR() == (i->GetImmS() + 1);
  };

  auto AllCases = [](const Instruction *i) {
    USE(i);
    return true;
  };

  using FuncAliasMap = std::unordered_map<uint32_t, std::vector<FuncAlias>>;
  static const FuncAliasMap funcmap =
      {{"csinc_32_condsel"_h,
        {{{RnIsZROrSP, RmIsZROrSP, CondNotAlNv}, "cset"},
         {{RnRmAliased, CondNotAlNv}, "cinc"}}},
       {"csinc_64_condsel"_h,
        {{{RnIsZROrSP, RmIsZROrSP, CondNotAlNv}, "cset"},
         {{RnRmAliased, CondNotAlNv}, "cinc"}}},
       {"csinv_32_condsel"_h,
        {{{RnIsZROrSP, RmIsZROrSP, CondNotAlNv}, "csetm"},
         {{RnRmAliased, CondNotAlNv}, "cinv"}}},
       {"csinv_64_condsel"_h,
        {{{RnIsZROrSP, RmIsZROrSP, CondNotAlNv}, "csetm"},
         {{RnRmAliased, CondNotAlNv}, "cinv"}}},
       {"csneg_32_condsel"_h, {{{RnRmAliased, CondNotAlNv}, "cneg"}}},
       {"csneg_64_condsel"_h, {{{RnRmAliased, CondNotAlNv}, "cneg"}}},
       {"extr_32_extract"_h, {{{RnRmAliased}, "ror"}}},
       {"extr_64_extract"_h, {{{RnRmAliased}, "ror"}}},
       {"orr_32_log_imm"_h, {{{RnIsZROrSP, IsNotMovzMovnImmW}, "mov"}}},
       {"orr_64_log_imm"_h, {{{RnIsZROrSP, IsNotMovzMovnImmX}, "mov"}}},
       {"sbfm_32m_bitfield"_h,
        {{{BitfieldSLessThanR}, "sbfiz"}, {{AllCases}, "sbfx"}}},
       {"sbfm_64m_bitfield"_h,
        {{{BitfieldSLessThanR}, "sbfiz"}, {{AllCases}, "sbfx"}}},
       {"ubfm_32m_bitfield"_h,
        {{{BitfieldRIsSPlus1}, "lsl"},
         {{BitfieldSLessThanR}, "ubfiz"},
         {{AllCases}, "ubfx"}}},
       {"ubfm_64m_bitfield"_h,
        {{{BitfieldRIsSPlus1}, "lsl"},
         {{BitfieldSLessThanR}, "ubfiz"},
         {{AllCases}, "ubfx"}}},
       {"bfm_32m_bitfield"_h,
        {{{BitfieldSLessThanR, RnIsZROrSP}, "bfc"},
         {{BitfieldSLessThanR}, "bfi"},
         {{AllCases}, "bfxil"}}},
       {"bfm_64m_bitfield"_h,
        {{{BitfieldSLessThanR, RnIsZROrSP}, "bfc"},
         {{BitfieldSLessThanR}, "bfi"},
         {{AllCases}, "bfxil"}}},
       {"orr_asimdsame_only"_h, {{{RnRmAliased}, "mov"}}},
       {"orr_z_zz"_h, {{{RnRmAliased}, "mov"}}},
       {"sel_z_p_zz"_h, {{{RdRmAliased}, "mov"}}},
       {"ands_p_p_pp_z"_h, {{{PnPmAliased}, "movs"}}},
       {"and_p_p_pp_z"_h, {{{PnPmAliased}, "mov"}}},
       {"eors_p_p_pp_z"_h, {{{PgPmAliased}, "nots"}}},
       {"eor_p_p_pp_z"_h, {{{PgPmAliased}, "not"}}},
       {"orrs_p_p_pp_z"_h, {{{PnPmAliased, PgPmAliased}, "movs"}}},
       {"orr_p_p_pp_z"_h, {{{PnPmAliased, PgPmAliased}, "mov"}}},
       {"sel_p_p_pp"_h, {{{PdPmAliased}, "mov"}}},
       {"movz_32_movewide"_h, {{{IsNonZeroNoShiftMov}, "mov"}}},
       {"movz_64_movewide"_h, {{{IsNonZeroNoShiftMov}, "mov"}}},
       {"movn_32_movewide"_h, {{{IsNonZeroNoShiftMov, IsNonOnesMov}, "mov"}}},
       {"movn_64_movewide"_h, {{{IsNonZeroNoShiftMov}, "mov"}}}};


  // Check simple aliases.
  std::string alias;
  MaskAliasMap::const_iterator ita = maskmap.find(form_hash_);
  if (ita != maskmap.end()) {
    for (auto rule : ita->second) {
      uint64_t mv = rule.mask_value;
      uint32_t mask = mv >> 32;
      uint32_t value = mv & 0xffffffff;
      if ((mask == 0) || (instr->Mask(mask) == value)) {
        alias = rule.alias;
        break;
      }
    }
  }

  // If there was no simple alias, check for a complex one.
  if (alias.length() == 0) {
    FuncAliasMap::const_iterator ita2 = funcmap.find(form_hash_);
    if (ita2 != funcmap.end()) {
      for (auto rule : ita2->second) {
        bool all = true;
        for (auto cond : rule.conditions) {
          all = all && cond(instr);
        }
        if (all == true) {
          alias = rule.alias;
          break;
        }
      }
    }
  }

  return alias;
}

void Disassembler::PopulatePerInstructionUnallocatedMap(FormToUnallocMap *ftm) {
  using UnallocToFormMap =
      std::unordered_map<uint64_t, std::unordered_set<uint32_t>>;

  // Map from mask/value (as uint64) to instruction form. Given an encoding,
  // if, after applying the bitmask (top 32 bits), the resulting encoding equals
  // bottom 32 bits, then the encoding is unallocated for the instructions
  // indexed by the mask/value. On object construction, this is used to build a
  // map from instruction to mask/value, allowing fast lookup during
  // disassembly.
  static const UnallocToFormMap forms =
      {{0x00001c00'00001400,
        {"add_32_addsub_ext"_h,
         "add_64_addsub_ext"_h,
         "subs_32s_addsub_ext"_h,
         "subs_64s_addsub_ext"_h,
         "sub_32_addsub_ext"_h,
         "sub_64_addsub_ext"_h}},
       {0x00001800'00001800,
        {"add_32_addsub_ext"_h,
         "add_64_addsub_ext"_h,
         "subs_32s_addsub_ext"_h,
         "subs_64s_addsub_ext"_h,
         "sub_32_addsub_ext"_h,
         "sub_64_addsub_ext"_h}},
       {0x000207e0'000007c0, {"and_z_zi"_h, "eor_z_zi"_h, "orr_z_zi"_h}},
       {0x000207e0'000007e0, {"and_z_zi"_h, "eor_z_zi"_h, "orr_z_zi"_h}},
       {0x00030000'00000000, {"smov_asimdins_w_w"_h}},
       {0x00070000'00000000, {"smov_asimdins_x_x"_h, "umov_asimdins_w_w"_h}},
       {0x000f0000'00000000,
        {"umov_asimdins_w_w"_h,
         "umov_asimdins_x_x"_h,
         "dup_asimdins_dv_v"_h,
         "dup_asimdins_dr_r"_h,
         "ins_asimdins_iv_v"_h,
         "ins_asimdins_ir_r"_h}},
       {0x001f0000'001f0000,
        {"prfb_i_p_br_s"_h,
         "prfd_i_p_br_s"_h,
         "prfh_i_p_br_s"_h,
         "prfw_i_p_br_s"_h}},
       {0x0040f800'0000f800,
        {"ands_32s_log_imm"_h,
         "ands_64s_log_imm"_h,
         "and_32_log_imm"_h,
         "and_64_log_imm"_h,
         "eor_32_log_imm"_h,
         "eor_64_log_imm"_h,
         "orr_32_log_imm"_h,
         "orr_64_log_imm"_h}},
       {0x0040fc00'00007c00,
        {"ands_32s_log_imm"_h,
         "ands_64s_log_imm"_h,
         "and_32_log_imm"_h,
         "and_64_log_imm"_h,
         "eor_32_log_imm"_h,
         "eor_64_log_imm"_h,
         "orr_32_log_imm"_h,
         "orr_64_log_imm"_h}},
       {0x0040fc00'0000bc00,
        {"ands_32s_log_imm"_h,
         "ands_64s_log_imm"_h,
         "and_32_log_imm"_h,
         "and_64_log_imm"_h,
         "eor_32_log_imm"_h,
         "eor_64_log_imm"_h,
         "orr_32_log_imm"_h,
         "orr_64_log_imm"_h}},
       {0x0040fc00'0000dc00,
        {"ands_32s_log_imm"_h,
         "ands_64s_log_imm"_h,
         "and_32_log_imm"_h,
         "and_64_log_imm"_h,
         "eor_32_log_imm"_h,
         "eor_64_log_imm"_h,
         "orr_32_log_imm"_h,
         "orr_64_log_imm"_h}},
       {0x0040fc00'0000ec00,
        {"ands_32s_log_imm"_h,
         "ands_64s_log_imm"_h,
         "and_32_log_imm"_h,
         "and_64_log_imm"_h,
         "eor_32_log_imm"_h,
         "eor_64_log_imm"_h,
         "orr_32_log_imm"_h,
         "orr_64_log_imm"_h}},
       {0x0040fc00'0000f400,
        {"ands_32s_log_imm"_h,
         "ands_64s_log_imm"_h,
         "and_32_log_imm"_h,
         "and_64_log_imm"_h,
         "eor_32_log_imm"_h,
         "eor_64_log_imm"_h,
         "orr_32_log_imm"_h,
         "orr_64_log_imm"_h}},
       {0x00200000'00200000, {"fcmla_asimdelem_c_s"_h}},
       {0x00400000'00000000,
        {"shl_asisdshf_r"_h,
         "sli_asisdshf_r"_h,
         "sri_asisdshf_r"_h,
         "srshr_asisdshf_r"_h,
         "srsra_asisdshf_r"_h,
         "sshr_asisdshf_r"_h,
         "ssra_asisdshf_r"_h,
         "urshr_asisdshf_r"_h,
         "ursra_asisdshf_r"_h,
         "ushr_asisdshf_r"_h,
         "usra_asisdshf_r"_h,
         "pmullb_z_zz"_h,
         "pmullt_z_zz"_h,
         "fcvtxn_asisdmisc_n"_h,
         "fcvtxn_asimdmisc_n"_h}},
       {0x00400000'00400000, {"urecpe_asimdmisc_r"_h, "ursqrte_asimdmisc_r"_h,
                              "cnt_asimdmisc_r"_h,    "rev16_asimdmisc_r"_h,
                              "shrn_asimdshf_n"_h,    "rshrn_asimdshf_n"_h,
                              "sqshrn_asimdshf_n"_h,  "sqrshrn_asimdshf_n"_h,
                              "sqshrun_asimdshf_n"_h, "sqrshrun_asimdshf_n"_h,
                              "uqshrn_asimdshf_n"_h,  "uqrshrn_asimdshf_n"_h,
                              "sshll_asimdshf_l"_h,   "ushll_asimdshf_l"_h,
                              "sqrshrn_asisdshf_n"_h, "sqrshrun_asisdshf_n"_h,
                              "sqshrn_asisdshf_n"_h,  "sqshrun_asisdshf_n"_h,
                              "uqrshrn_asisdshf_n"_h, "uqshrn_asisdshf_n"_h}},
       {0x00060000'00000000, {"flogb_z_p_z"_h}},
       {0x00580000'00000000,
        {"rshrnb_z_zi"_h,    "rshrnt_z_zi"_h,    "shrnb_z_zi"_h,
         "shrnt_z_zi"_h,     "sqrshrnb_z_zi"_h,  "sqrshrnt_z_zi"_h,
         "sqrshrunb_z_zi"_h, "sqrshrunt_z_zi"_h, "sqshrnb_z_zi"_h,
         "sqshrnt_z_zi"_h,   "sqshrunb_z_zi"_h,  "sqshrunt_z_zi"_h,
         "uqrshrnb_z_zi"_h,  "uqrshrnt_z_zi"_h,  "uqshrnb_z_zi"_h,
         "uqshrnt_z_zi"_h,   "sshllb_z_zi"_h,    "sshllt_z_zi"_h,
         "ushllb_z_zi"_h,    "ushllt_z_zi"_h,    "sqxtnb_z_zz"_h,
         "sqxtnt_z_zz"_h,    "sqxtunb_z_zz"_h,   "sqxtunt_z_zz"_h,
         "uqxtnb_z_zz"_h,    "uqxtnt_z_zz"_h}},
       {0x00580000'00180000,
        {"sqxtnb_z_zz"_h,
         "sqxtnt_z_zz"_h,
         "sqxtunb_z_zz"_h,
         "sqxtunt_z_zz"_h,
         "uqxtnb_z_zz"_h,
         "uqxtnt_z_zz"_h}},
       {0x00580000'00480000,
        {"sqxtnb_z_zz"_h,
         "sqxtnt_z_zz"_h,
         "sqxtunb_z_zz"_h,
         "sqxtunt_z_zz"_h,
         "uqxtnb_z_zz"_h,
         "uqxtnt_z_zz"_h}},
       {0x00580000'00500000,
        {"sqxtnb_z_zz"_h,
         "sqxtnt_z_zz"_h,
         "sqxtunb_z_zz"_h,
         "sqxtunt_z_zz"_h,
         "uqxtnb_z_zz"_h,
         "uqxtnt_z_zz"_h}},
       {0x00580000'00580000,
        {"sqxtnb_z_zz"_h,
         "sqxtnt_z_zz"_h,
         "sqxtunb_z_zz"_h,
         "sqxtunt_z_zz"_h,
         "uqxtnb_z_zz"_h,
         "uqxtnt_z_zz"_h}},
       {0x00600000'00600000,
        {"fmla_asimdelem_r_sd"_h,
         "fmls_asimdelem_r_sd"_h,
         "fmulx_asimdelem_r_sd"_h,
         "fmul_asimdelem_r_sd"_h}},
       {0x00700000'00000000,
        {"fcvtzs_asisdshf_c"_h,
         "fcvtzu_asisdshf_c"_h,
         "scvtf_asisdshf_c"_h,
         "ucvtf_asisdshf_c"_h}},
       {0x00780000'00000000,
        {"sqrshrn_asisdshf_n"_h,
         "sqrshrun_asisdshf_n"_h,
         "sqshrn_asisdshf_n"_h,
         "sqshrun_asisdshf_n"_h,
         "uqrshrn_asisdshf_n"_h,
         "uqshrn_asisdshf_n"_h}},
       {0x00780000'00080000,
        {"scvtf_asimdshf_c"_h,
         "ucvtf_asimdshf_c"_h,
         "fcvtzs_asimdshf_c"_h,
         "fcvtzu_asimdshf_c"_h}},
       {0x00800000'00000000,
        {"compact_z_p_z"_h, "sdot_z_zzz"_h, "udot_z_zzz"_h}},
       {0x00800000'00800000,
        {"cnt_asimdmisc_r"_h, "rev16_asimdmisc_r"_h, "rev32_asimdmisc_r"_h}},
       {0x00c00000'00000000,
        {"smlalb_z_zzz"_h,
         "smlalt_z_zzz"_h,
         "smlslb_z_zzz"_h,
         "smlslt_z_zzz"_h,
         "sqdmlalb_z_zzz"_h,
         "sqdmlalbt_z_zzz"_h,
         "sqdmlalt_z_zzz"_h,
         "sqdmlslb_z_zzz"_h,
         "sqdmlslbt_z_zzz"_h,
         "sqdmlslt_z_zzz"_h,
         "umlalb_z_zzz"_h,
         "umlalt_z_zzz"_h,
         "umlslb_z_zzz"_h,
         "umlslt_z_zzz"_h,
         "faddp_z_p_zz"_h,
         "fmaxnmp_z_p_zz"_h,
         "fmaxp_z_p_zz"_h,
         "fminnmp_z_p_zz"_h,
         "fminp_z_p_zz"_h,
         "urecpe_z_p_z"_h,
         "ursqrte_z_p_z"_h,
         "saddwb_z_zz"_h,
         "saddwt_z_zz"_h,
         "ssubwb_z_zz"_h,
         "ssubwt_z_zz"_h,
         "uaddwb_z_zz"_h,
         "uaddwt_z_zz"_h,
         "usubwb_z_zz"_h,
         "usubwt_z_zz"_h,
         "sadalp_z_p_z"_h,
         "uadalp_z_p_z"_h,
         "sabalb_z_zzz"_h,
         "sabalt_z_zzz"_h,
         "sabdlb_z_zz"_h,
         "sabdlt_z_zz"_h,
         "saddlb_z_zz"_h,
         "saddlbt_z_zz"_h,
         "saddlt_z_zz"_h,
         "smullb_z_zz"_h,
         "smullt_z_zz"_h,
         "sqdmullb_z_zz"_h,
         "sqdmullt_z_zz"_h,
         "ssublb_z_zz"_h,
         "ssublbt_z_zz"_h,
         "ssublt_z_zz"_h,
         "ssubltb_z_zz"_h,
         "uabalb_z_zzz"_h,
         "uabalt_z_zzz"_h,
         "uabdlb_z_zz"_h,
         "uabdlt_z_zz"_h,
         "uaddlb_z_zz"_h,
         "uaddlt_z_zz"_h,
         "umullb_z_zz"_h,
         "umullt_z_zz"_h,
         "usublb_z_zz"_h,
         "usublt_z_zz"_h,
         "addhnb_z_zz"_h,
         "addhnt_z_zz"_h,
         "raddhnb_z_zz"_h,
         "raddhnt_z_zz"_h,
         "rsubhnb_z_zz"_h,
         "rsubhnt_z_zz"_h,
         "subhnb_z_zz"_h,
         "subhnt_z_zz"_h,
         "cmeq_asisdsame_only"_h,
         "cmge_asisdsame_only"_h,
         "cmgt_asisdsame_only"_h,
         "cmhi_asisdsame_only"_h,
         "cmhs_asisdsame_only"_h,
         "cmtst_asisdsame_only"_h,
         "add_asisdsame_only"_h,
         "sub_asisdsame_only"_h,
         "addp_asisdpair_only"_h,
         "frinta_z_p_z"_h,
         "frinti_z_p_z"_h,
         "frintm_z_p_z"_h,
         "frintn_z_p_z"_h,
         "frintp_z_p_z"_h,
         "frintx_z_p_z"_h,
         "frintz_z_p_z"_h,
         "frecpx_z_p_z"_h,
         "fsqrt_z_p_z"_h,
         "frecpe_z_z"_h,
         "frsqrte_z_z"_h,
         "fmad_z_p_zzz"_h,
         "fmla_z_p_zzz"_h,
         "fmls_z_p_zzz"_h,
         "fmsb_z_p_zzz"_h,
         "fnmad_z_p_zzz"_h,
         "fnmla_z_p_zzz"_h,
         "fnmls_z_p_zzz"_h,
         "fnmsb_z_p_zzz"_h,
         "faddv_v_p_z"_h,
         "fmaxnmv_v_p_z"_h,
         "fmaxv_v_p_z"_h,
         "fminnmv_v_p_z"_h,
         "fminv_v_p_z"_h,
         "fcmla_z_p_zzz"_h,
         "fcadd_z_p_zz"_h,
         "fcmeq_p_p_z0"_h,
         "fcmge_p_p_z0"_h,
         "fcmgt_p_p_z0"_h,
         "fcmle_p_p_z0"_h,
         "fcmlt_p_p_z0"_h,
         "fcmne_p_p_z0"_h,
         "facge_p_p_zz"_h,
         "facgt_p_p_zz"_h,
         "fcmeq_p_p_zz"_h,
         "fcmge_p_p_zz"_h,
         "fcmgt_p_p_zz"_h,
         "fcmne_p_p_zz"_h,
         "fcmuo_p_p_zz"_h,
         "fadd_z_zz"_h,
         "fmul_z_zz"_h,
         "frecps_z_zz"_h,
         "frsqrts_z_zz"_h,
         "fsub_z_zz"_h,
         "ftsmul_z_zz"_h,
         "fadda_v_p_z"_h,
         "sxtw_z_p_z"_h,
         "uxtw_z_p_z"_h,
         "sxth_z_p_z"_h,
         "uxth_z_p_z"_h,
         "sxtb_z_p_z"_h,
         "uxtb_z_p_z"_h,
         "fabs_z_p_z"_h,
         "fneg_z_p_z"_h,
         "sunpkhi_z_z"_h,
         "sunpklo_z_z"_h,
         "uunpkhi_z_z"_h,
         "uunpklo_z_z"_h,
         "revb_z_z"_h,
         "revh_z_z"_h,
         "revw_z_z"_h,
         "ftssel_z_zz"_h,
         "ftmad_z_zzi"_h,
         "fexpa_z_z"_h,
         "fabd_z_p_zz"_h,
         "fadd_z_p_zz"_h,
         "fdivr_z_p_zz"_h,
         "fdiv_z_p_zz"_h,
         "fmaxnm_z_p_zz"_h,
         "fmax_z_p_zz"_h,
         "fminnm_z_p_zz"_h,
         "fmin_z_p_zz"_h,
         "fmulx_z_p_zz"_h,
         "fmul_z_p_zz"_h,
         "fscale_z_p_zz"_h,
         "fsubr_z_p_zz"_h,
         "fsub_z_p_zz"_h,
         "fadd_z_p_zs"_h,
         "fmaxnm_z_p_zs"_h,
         "fmax_z_p_zs"_h,
         "fminnm_z_p_zs"_h,
         "fmin_z_p_zs"_h,
         "fmul_z_p_zs"_h,
         "fsubr_z_p_zs"_h,
         "fsub_z_p_zs"_h,
         "abs_asisdmisc_r"_h,
         "neg_asisdmisc_r"_h,
         "cmeq_asisdmisc_z"_h,
         "cmge_asisdmisc_z"_h,
         "cmgt_asisdmisc_z"_h,
         "cmle_asisdmisc_z"_h,
         "cmlt_asisdmisc_z"_h,
         "cdot_z_zzz"_h,
         "histcnt_z_p_zz"_h,
         "sdiv_z_p_zz"_h,
         "sdivr_z_p_zz"_h,
         "udiv_z_p_zz"_h,
         "udivr_z_p_zz"_h,
         "fdup_z_i"_h,
         "fcpy_z_p_i"_h,
         "sqdmulh_asimdsame_only"_h,
         "sqrdmulh_asimdsame_only"_h,
         "fcmla_asimdsame2_c"_h,
         "fcadd_asimdsame2_c"_h,
         "sqrdmlah_asimdsame2_only"_h,
         "sqrdmlsh_asimdsame2_only"_h,
         "sdot_asimdsame2_d"_h,
         "udot_asimdsame2_d"_h,
         "mla_asimdelem_r"_h,
         "mls_asimdelem_r"_h,
         "mul_asimdelem_r"_h,
         "sqdmulh_asimdelem_r"_h,
         "sqrdmlah_asimdelem_r"_h,
         "sqrdmlsh_asimdelem_r"_h,
         "sqrdmulh_asimdelem_r"_h,
         "sqdmlal_asisddiff_only"_h,
         "sqdmlsl_asisddiff_only"_h,
         "sqdmull_asisddiff_only"_h,
         "sqdmulh_asisdsame_only"_h,
         "sqrdmulh_asisdsame_only"_h,
         "sqrdmlah_asisdsame2_only"_h,
         "sqrdmlsh_asisdsame2_only"_h,
         "srshl_asisdsame_only"_h,
         "urshl_asisdsame_only"_h,
         "sshl_asisdsame_only"_h,
         "ushl_asisdsame_only"_h,
         "sqdmulh_asisdelem_r"_h,
         "sqrdmlah_asisdelem_r"_h,
         "sqrdmlsh_asisdelem_r"_h,
         "sqrdmulh_asisdelem_r"_h,
         "sqdmlal_asisdelem_l"_h,
         "sqdmlsl_asisdelem_l"_h,
         "sqdmull_asisdelem_l"_h,
         "smlal_asimdelem_l"_h,
         "smlsl_asimdelem_l"_h,
         "smull_asimdelem_l"_h,
         "umlal_asimdelem_l"_h,
         "umlsl_asimdelem_l"_h,
         "umull_asimdelem_l"_h,
         "sqdmull_asimdelem_l"_h,
         "sqdmlal_asimdelem_l"_h,
         "sqdmlsl_asimdelem_l"_h,
         "sqdmlal_asimddiff_l"_h,
         "sqdmlsl_asimddiff_l"_h,
         "sqdmull_asimddiff_l"_h}},
       {0x00c00300'00000000,
        {"asr_z_p_zi"_h,
         "asrd_z_p_zi"_h,
         "lsl_z_p_zi"_h,
         "lsr_z_p_zi"_h,
         "sqshl_z_p_zi"_h,
         "sqshlu_z_p_zi"_h,
         "srshr_z_p_zi"_h,
         "uqshl_z_p_zi"_h,
         "urshr_z_p_zi"_h}},
       {0x00c00000'00400000,
        {"urecpe_z_p_z"_h,
         "ursqrte_z_p_z"_h,
         "histseg_z_zz"_h,
         "pmul_z_zz"_h,
         "cmeq_asisdsame_only"_h,
         "cmge_asisdsame_only"_h,
         "cmgt_asisdsame_only"_h,
         "cmhi_asisdsame_only"_h,
         "cmhs_asisdsame_only"_h,
         "cmtst_asisdsame_only"_h,
         "add_asisdsame_only"_h,
         "sub_asisdsame_only"_h,
         "addp_asisdpair_only"_h,
         "sxtw_z_p_z"_h,
         "uxtw_z_p_z"_h,
         "sxth_z_p_z"_h,
         "uxth_z_p_z"_h,
         "revh_z_z"_h,
         "revw_z_z"_h,
         "pmul_asimdsame_only"_h,
         "abs_asisdmisc_r"_h,
         "neg_asisdmisc_r"_h,
         "cmeq_asisdmisc_z"_h,
         "cmge_asisdmisc_z"_h,
         "cmgt_asisdmisc_z"_h,
         "cmle_asisdmisc_z"_h,
         "cmlt_asisdmisc_z"_h,
         "cdot_z_zzz"_h,
         "histcnt_z_p_zz"_h,
         "pmull_asimddiff_l"_h,
         "sdot_asimdsame2_d"_h,
         "udot_asimdsame2_d"_h,
         "srshl_asisdsame_only"_h,
         "urshl_asisdsame_only"_h,
         "sshl_asisdsame_only"_h,
         "ushl_asisdsame_only"_h}},
       {0x00c00000'00800000,
        {"histseg_z_zz"_h,         "pmul_z_zz"_h,
         "cmeq_asisdsame_only"_h,  "cmge_asisdsame_only"_h,
         "cmgt_asisdsame_only"_h,  "cmhi_asisdsame_only"_h,
         "cmhs_asisdsame_only"_h,  "cmtst_asisdsame_only"_h,
         "add_asisdsame_only"_h,   "sub_asisdsame_only"_h,
         "addp_asisdpair_only"_h,  "sxtw_z_p_z"_h,
         "uxtw_z_p_z"_h,           "revw_z_z"_h,
         "pmul_asimdsame_only"_h,  "abs_asisdmisc_r"_h,
         "neg_asisdmisc_r"_h,      "cmeq_asisdmisc_z"_h,
         "cmge_asisdmisc_z"_h,     "cmgt_asisdmisc_z"_h,
         "cmle_asisdmisc_z"_h,     "cmlt_asisdmisc_z"_h,
         "match_p_p_zz"_h,         "nmatch_p_p_zz"_h,
         "pmull_asimddiff_l"_h,    "srshl_asisdsame_only"_h,
         "urshl_asisdsame_only"_h, "sshl_asisdsame_only"_h,
         "ushl_asisdsame_only"_h}},
       {0x00c00000'00c00000,
        {"asr_z_p_zw"_h,
         "lsl_z_p_zw"_h,
         "lsr_z_p_zw"_h,
         "urecpe_z_p_z"_h,
         "ursqrte_z_p_z"_h,
         "histseg_z_zz"_h,
         "pmul_z_zz"_h,
         "asr_z_zw"_h,
         "lsl_z_zw"_h,
         "lsr_z_zw"_h,
         "pmul_asimdsame_only"_h,
         "match_p_p_zz"_h,
         "nmatch_p_p_zz"_h,
         "adds_32_addsub_shift"_h,
         "adds_64_addsub_shift"_h,
         "add_32_addsub_shift"_h,
         "add_64_addsub_shift"_h,
         "subs_32_addsub_shift"_h,
         "subs_64_addsub_shift"_h,
         "sub_32_addsub_shift"_h,
         "sub_64_addsub_shift"_h,
         "mla_asimdsame_only"_h,
         "mls_asimdsame_only"_h,
         "mul_asimdsame_only"_h,
         "saba_asimdsame_only"_h,
         "sabd_asimdsame_only"_h,
         "shadd_asimdsame_only"_h,
         "shsub_asimdsame_only"_h,
         "smaxp_asimdsame_only"_h,
         "smax_asimdsame_only"_h,
         "sminp_asimdsame_only"_h,
         "smin_asimdsame_only"_h,
         "srhadd_asimdsame_only"_h,
         "uaba_asimdsame_only"_h,
         "uabd_asimdsame_only"_h,
         "uhadd_asimdsame_only"_h,
         "uhsub_asimdsame_only"_h,
         "umaxp_asimdsame_only"_h,
         "umax_asimdsame_only"_h,
         "uminp_asimdsame_only"_h,
         "umin_asimdsame_only"_h,
         "urhadd_asimdsame_only"_h,
         "sqdmulh_asimdsame_only"_h,
         "sqrdmulh_asimdsame_only"_h,
         "sqrdmlah_asimdsame2_only"_h,
         "sqrdmlsh_asimdsame2_only"_h,
         "sdot_asimdsame2_d"_h,
         "udot_asimdsame2_d"_h,
         "clz_asimdmisc_r"_h,
         "cls_asimdmisc_r"_h,
         "rev64_asimdmisc_r"_h,
         "mla_asimdelem_r"_h,
         "mls_asimdelem_r"_h,
         "mul_asimdelem_r"_h,
         "sqdmulh_asimdelem_r"_h,
         "sqrdmlah_asimdelem_r"_h,
         "sqrdmlsh_asimdelem_r"_h,
         "sqrdmulh_asimdelem_r"_h,
         "sqxtn_asisdmisc_n"_h,
         "sqxtun_asisdmisc_n"_h,
         "uqxtn_asisdmisc_n"_h,
         "sqdmlal_asisddiff_only"_h,
         "sqdmlsl_asisddiff_only"_h,
         "sqdmull_asisddiff_only"_h,
         "sqdmulh_asisdsame_only"_h,
         "sqrdmulh_asisdsame_only"_h,
         "sqrdmlah_asisdsame2_only"_h,
         "sqrdmlsh_asisdsame2_only"_h,
         "sqdmulh_asisdelem_r"_h,
         "sqrdmlah_asisdelem_r"_h,
         "sqrdmlsh_asisdelem_r"_h,
         "sqrdmulh_asisdelem_r"_h,
         "sqdmlal_asisdelem_l"_h,
         "sqdmlsl_asisdelem_l"_h,
         "sqdmull_asisdelem_l"_h,
         "shll_asimdmisc_s"_h,
         "xtn_asimdmisc_n"_h,
         "sqxtn_asimdmisc_n"_h,
         "uqxtn_asimdmisc_n"_h,
         "sqxtun_asimdmisc_n"_h,
         "smlal_asimdelem_l"_h,
         "smlsl_asimdelem_l"_h,
         "smull_asimdelem_l"_h,
         "umlal_asimdelem_l"_h,
         "umlsl_asimdelem_l"_h,
         "umull_asimdelem_l"_h,
         "sqdmull_asimdelem_l"_h,
         "sqdmlal_asimdelem_l"_h,
         "sqdmlsl_asimdelem_l"_h,
         "saddlv_asimdall_only"_h,
         "uaddlv_asimdall_only"_h,
         "addv_asimdall_only"_h,
         "smaxv_asimdall_only"_h,
         "sminv_asimdall_only"_h,
         "umaxv_asimdall_only"_h,
         "uminv_asimdall_only"_h,
         "sabal_asimddiff_l"_h,
         "sabdl_asimddiff_l"_h,
         "saddl_asimddiff_l"_h,
         "smlal_asimddiff_l"_h,
         "smlsl_asimddiff_l"_h,
         "smull_asimddiff_l"_h,
         "ssubl_asimddiff_l"_h,
         "uabal_asimddiff_l"_h,
         "uabdl_asimddiff_l"_h,
         "uaddl_asimddiff_l"_h,
         "umlal_asimddiff_l"_h,
         "umlsl_asimddiff_l"_h,
         "umull_asimddiff_l"_h,
         "usubl_asimddiff_l"_h,
         "saddw_asimddiff_w"_h,
         "ssubw_asimddiff_w"_h,
         "uaddw_asimddiff_w"_h,
         "usubw_asimddiff_w"_h
         "addhn_asimddiff_n"_h,
         "raddhn_asimddiff_n"_h,
         "rsubhn_asimddiff_n"_h,
         "subhn_asimddiff_n"_h,
         "sqdmlal_asimddiff_l"_h,
         "sqdmlsl_asimddiff_l"_h,
         "sqdmull_asimddiff_l"_h}},
       {0x00c02000'00002000, {"dup_z_i"_h}},
       {0x00d80000'00000000,
        {"xar_z_zzi"_h,
         "asr_z_zi"_h,
         "lsr_z_zi"_h,
         "sri_z_zzi"_h,
         "srsra_z_zi"_h,
         "ssra_z_zi"_h,
         "ursra_z_zi"_h,
         "usra_z_zi"_h,
         "lsl_z_zi"_h,
         "sli_z_zzi"_h}},
       {0x40000000'00000000, {"fcmla_asimdelem_c_s"_h}},
       {0x40000800'00000800, {"fcmla_asimdelem_c_h"_h}},
       {0x40000c00'00000c00,
        {"ld2_asisdlse_r2"_h,
         "ld2_asisdlsep_i2_i"_h,
         "ld2_asisdlsep_r2_r"_h,
         "st2_asisdlse_r2"_h,
         "st2_asisdlsep_i2_i"_h,
         "st2_asisdlsep_r2_r"_h,
         "ld3_asisdlse_r3"_h,
         "ld3_asisdlsep_i3_i"_h,
         "ld3_asisdlsep_r3_r"_h,
         "st3_asisdlse_r3"_h,
         "st3_asisdlsep_i3_i"_h,
         "st3_asisdlsep_r3_r"_h,
         "ld4_asisdlse_r4"_h,
         "ld4_asisdlsep_i4_i"_h,
         "ld4_asisdlsep_r4_r"_h,
         "st4_asisdlse_r4"_h,
         "st4_asisdlsep_i4_i"_h,
         "st4_asisdlsep_r4_r"_h}},
       {0x40004000'00004000, {"ext_asimdext_only"_h}},
       {0x400f0000'00080000, {"dup_asimdins_dv_v"_h, "dup_asimdins_dr_d"_h}},
       {0x40400000'00000000,
        {"fmaxnmv_asimdall_only_sd"_h,
         "fminnmv_asimdall_only_sd"_h,
         "fmaxv_asimdall_only_sd"_h,
         "fminv_asimdall_only_sd"_h}},
       {0x40400000'00400000,
        {"fabs_asimdmisc_r"_h,         "fcvtas_asimdmisc_r"_h,
         "fcvtau_asimdmisc_r"_h,       "fcvtms_asimdmisc_r"_h,
         "fcvtmu_asimdmisc_r"_h,       "fcvtns_asimdmisc_r"_h,
         "fcvtnu_asimdmisc_r"_h,       "fcvtps_asimdmisc_r"_h,
         "fcvtpu_asimdmisc_r"_h,       "fcvtzs_asimdmisc_r"_h,
         "fcvtzu_asimdmisc_r"_h,       "fneg_asimdmisc_r"_h,
         "frecpe_asimdmisc_r"_h,       "frint32x_asimdmisc_r"_h,
         "frint32z_asimdmisc_r"_h,     "frint64x_asimdmisc_r"_h,
         "frint64z_asimdmisc_r"_h,     "frinta_asimdmisc_r"_h,
         "frinti_asimdmisc_r"_h,       "frintm_asimdmisc_r"_h,
         "frintn_asimdmisc_r"_h,       "frintp_asimdmisc_r"_h,
         "frintx_asimdmisc_r"_h,       "frintz_asimdmisc_r"_h,
         "frsqrte_asimdmisc_r"_h,      "fsqrt_asimdmisc_r"_h,
         "scvtf_asimdmisc_r"_h,        "ucvtf_asimdmisc_r"_h,
         "fmaxnmv_asimdall_only_sd"_h, "fminnmv_asimdall_only_sd"_h,
         "fmaxv_asimdall_only_sd"_h,   "fminv_asimdall_only_sd"_h,
         "fcmeq_asimdmisc_fz"_h,       "fcmge_asimdmisc_fz"_h,
         "fcmgt_asimdmisc_fz"_h,       "fcmle_asimdmisc_fz"_h,
         "fcmlt_asimdmisc_fz"_h,       "fabd_asimdsame_only"_h,
         "facge_asimdsame_only"_h,     "facgt_asimdsame_only"_h,
         "faddp_asimdsame_only"_h,     "fadd_asimdsame_only"_h,
         "fcmeq_asimdsame_only"_h,     "fcmge_asimdsame_only"_h,
         "fcmgt_asimdsame_only"_h,     "fdiv_asimdsame_only"_h,
         "fmaxnmp_asimdsame_only"_h,   "fmaxnm_asimdsame_only"_h,
         "fmaxp_asimdsame_only"_h,     "fmax_asimdsame_only"_h,
         "fminnmp_asimdsame_only"_h,   "fminnm_asimdsame_only"_h,
         "fminp_asimdsame_only"_h,     "fmin_asimdsame_only"_h,
         "fmla_asimdsame_only"_h,      "fmls_asimdsame_only"_h,
         "fmulx_asimdsame_only"_h,     "fmul_asimdsame_only"_h,
         "frecps_asimdsame_only"_h,    "frsqrts_asimdsame_only"_h,
         "fsub_asimdsame_only"_h,      "fmla_asimdelem_r_sd"_h,
         "fmls_asimdelem_r_sd"_h,      "fmulx_asimdelem_r_sd"_h,
         "fmul_asimdelem_r_sd"_h,      "sri_asimdshf_r"_h,
         "srshr_asimdshf_r"_h,         "srsra_asimdshf_r"_h,
         "sshr_asimdshf_r"_h,          "ssra_asimdshf_r"_h,
         "urshr_asimdshf_r"_h,         "ursra_asimdshf_r"_h,
         "ushr_asimdshf_r"_h,          "usra_asimdshf_r"_h,
         "scvtf_asimdshf_c"_h,         "ucvtf_asimdshf_c"_h,
         "fcvtzs_asimdshf_c"_h,        "fcvtzu_asimdshf_c"_h}},
       {0x40400000'40400000,
        {"fmaxnmv_asimdall_only_sd"_h,
         "fminnmv_asimdall_only_sd"_h,
         "fmaxv_asimdall_only_sd"_h,
         "fminv_asimdall_only_sd"_h}},
       {0x40c00000'00800000,
        {"saddlv_asimdall_only"_h,
         "uaddlv_asimdall_only"_h,
         "addv_asimdall_only"_h,
         "smaxv_asimdall_only"_h,
         "sminv_asimdall_only"_h,
         "umaxv_asimdall_only"_h,
         "uminv_asimdall_only"_h}},
       {0x40c00000'00c00000,
        {"cmeq_asimdmisc_z"_h,       "cmge_asimdmisc_z"_h,
         "cmgt_asimdmisc_z"_h,       "cmle_asimdmisc_z"_h,
         "cmlt_asimdmisc_z"_h,       "addp_asimdsame_only"_h,
         "add_asimdsame_only"_h,     "cmeq_asimdsame_only"_h,
         "cmge_asimdsame_only"_h,    "cmgt_asimdsame_only"_h,
         "cmhi_asimdsame_only"_h,    "cmhs_asimdsame_only"_h,
         "cmtst_asimdsame_only"_h,   "sqadd_asimdsame_only"_h,
         "sqdmulh_asimdsame_only"_h, "sqrdmulh_asimdsame_only"_h,
         "sqrshl_asimdsame_only"_h,  "sqshl_asimdsame_only"_h,
         "sqsub_asimdsame_only"_h,   "srshl_asimdsame_only"_h,
         "sshl_asimdsame_only"_h,    "sub_asimdsame_only"_h,
         "uqadd_asimdsame_only"_h,   "uqrshl_asimdsame_only"_h,
         "uqshl_asimdsame_only"_h,   "uqsub_asimdsame_only"_h,
         "urshl_asimdsame_only"_h,   "ushl_asimdsame_only"_h,
         "trn1_asimdperm_only"_h,    "trn2_asimdperm_only"_h,
         "uzp1_asimdperm_only"_h,    "uzp2_asimdperm_only"_h,
         "zip1_asimdperm_only"_h,    "zip2_asimdperm_only"_h,
         "fcmla_asimdsame2_c"_h,     "fcadd_asimdsame2_c"_h}},
       {0x80400000'00400000,
        {"sbfm_64m_bitfield"_h,
         "sbfm_32m_bitfield"_h,
         "ubfm_32m_bitfield"_h,
         "ubfm_64m_bitfield"_h,
         "bfm_32m_bitfield"_h,
         "bfm_64m_bitfield"_h}},
       {0x80200000'00200000,
        {"sbfm_64m_bitfield"_h,
         "sbfm_32m_bitfield"_h,
         "ubfm_32m_bitfield"_h,
         "ubfm_64m_bitfield"_h,
         "bfm_32m_bitfield"_h,
         "bfm_64m_bitfield"_h}},
       {0x80008000'00008000,
        {"sbfm_64m_bitfield"_h,
         "sbfm_32m_bitfield"_h,
         "ubfm_32m_bitfield"_h,
         "ubfm_64m_bitfield"_h,
         "bfm_32m_bitfield"_h,
         "bfm_64m_bitfield"_h}}};

  for (auto &itm : forms) {
    const std::unordered_set<uint32_t> &s = forms.at(itm.first);
    for (const uint32_t &its : s) {
      ftm->insert(std::make_pair(its, itm.first));
    }
  }
}

void Disassembler::PopulateFormToStringMap(FormToStringMap *fts) {
  using StringToFormMap =
      std::unordered_map<std::string, std::unordered_set<uint32_t>>;

  // Map from disassembler format string to instruction form that uses it. On
  // object construction, this is used to build a map from instruction to
  // disassembler string, allowing fast lookup during disassembly.
  static const StringToFormMap forms = {
      {"", {"autia1716_hi_hints"_h,
            "autiasp_hi_hints"_h,
            "autiaz_hi_hints"_h,
            "autib1716_hi_hints"_h,
            "autibsp_hi_hints"_h,
            "autibz_hi_hints"_h,
            "axflag_m_pstate"_h,
            "cfinv_m_pstate"_h,
            "csdb_hi_hints"_h,
            "dgh_hi_hints"_h,
            "ssbb_only_barriers"_h,
            "esb_hi_hints"_h,
            "isb_bi_barriers"_h,
            "nop_hi_hints"_h,
            "pacia1716_hi_hints"_h,
            "paciasp_hi_hints"_h,
            "paciaz_hi_hints"_h,
            "pacib1716_hi_hints"_h,
            "pacibsp_hi_hints"_h,
            "pacibz_hi_hints"_h,
            "setffr_f"_h,
            "sev_hi_hints"_h,
            "sevl_hi_hints"_h,
            "wfe_hi_hints"_h,
            "wfi_hi_hints"_h,
            "xaflag_m_pstate"_h,
            "xpaclri_hi_hints"_h,
            "yield_hi_hints"_h,
            "retaa_64e_branch_reg"_h,
            "retab_64e_branch_reg"_h}},
      {"#'u1105", {"hint_hm_hints"_h}},
      {"#0x'x2005",
       {"brk_ex_exception"_h,
        "hlt_ex_exception"_h,
        "hvc_ex_exception"_h,
        "smc_ex_exception"_h,
        "svc_ex_exception"_h}},
      {"'{nscal}'u0400, '{nscal}'u0905",
       {"sqabs_asisdmisc_r"_h,
        "sqneg_asisdmisc_r"_h,
        "suqadd_asisdmisc_r"_h,
        "usqadd_asisdmisc_r"_h}},
      {"'{nscal}'u0400, '{nscall}'u0905",
       {"sqxtn_asisdmisc_n"_h, "sqxtun_asisdmisc_n"_h, "uqxtn_asisdmisc_n"_h}},
      {"'{nscal}'u0400, '{nscal}'u0905, '{nscal}'u2016",
       {"sqadd_asisdsame_only"_h,
        "sqdmulh_asisdsame_only"_h,
        "sqrdmulh_asisdsame_only"_h,
        "sqrshl_asisdsame_only"_h,
        "sqshl_asisdsame_only"_h,
        "sqsub_asisdsame_only"_h,
        "srshl_asisdsame_only"_h,
        "sshl_asisdsame_only"_h,
        "uqadd_asisdsame_only"_h,
        "uqrshl_asisdsame_only"_h,
        "uqshl_asisdsame_only"_h,
        "uqsub_asisdsame_only"_h,
        "urshl_asisdsame_only"_h,
        "ushl_asisdsame_only"_h,
        "sqrdmlah_asisdsame2_only"_h,
        "sqrdmlsh_asisdsame2_only"_h}},
      {"'{nscal}'u0400, '{nscal}'u0905, 'Vf.'{nscal}['IVByElemIndex]",
       {"sqdmulh_asisdelem_r"_h,
        "sqrdmlah_asisdelem_r"_h,
        "sqrdmlsh_asisdelem_r"_h,
        "sqrdmulh_asisdelem_r"_h}},
      {"'{nscal}'u0400, 'Vn.'{n}",
       {"addv_asimdall_only"_h,
        "smaxv_asimdall_only"_h,
        "sminv_asimdall_only"_h,
        "umaxv_asimdall_only"_h,
        "uminv_asimdall_only"_h}},
      {"'{nscall}'u0400, 'Vn.'{n}",
       {"saddlv_asimdall_only"_h, "uaddlv_asimdall_only"_h}},
      {"'{nscall}'u0400, '{nscal}'u0905, '{nscal}'u2016",
       {"sqdmlal_asisddiff_only"_h,
        "sqdmlsl_asisddiff_only"_h,
        "sqdmull_asisddiff_only"_h}},
      {"'{nscall}'u0400, '{nscal}'u0905, 'Vf.'{nscal}['IVByElemIndex]",
       {"sqdmlal_asisdelem_l"_h,
        "sqdmlsl_asisdelem_l"_h,
        "sqdmull_asisdelem_l"_h}},
      {"'{nshiftscal}'u0400, '{nshiftscal}'u0905, 'IsL",
       {"sqshlu_asisdshf_r"_h, "sqshl_asisdshf_r"_h, "uqshl_asisdshf_r"_h}},
      {"'{nshiftscal}'u0400, '{nshiftscal}'u0905, 'IsR",
       {"fcvtzs_asisdshf_c"_h,
        "fcvtzu_asisdshf_c"_h,
        "scvtf_asisdshf_c"_h,
        "ucvtf_asisdshf_c"_h}},
      {"'{ntriscal}'u0400, 'Vn.'{ntriscal}['IVInsIndex1]",
       {"mov_dup_asisdone_only"_h}},
      {"'(07?j)'(06?c)", {"bti_hb_hints"_h}},
      {"'(0905=30?:'Xn)", {"ret_64r_branch_reg"_h}},
      {"'(1108=15?:#0x'x1108)", {"clrex_bn_barriers"_h}},
      {"'(21?s:'?20:hb)'u0400, '(21?d:'?20:sh)'u0905, 'IsR",
       {"sqrshrn_asisdshf_n"_h,
        "sqrshrun_asisdshf_n"_h,
        "sqshrn_asisdshf_n"_h,
        "sqshrun_asisdshf_n"_h,
        "uqrshrn_asisdshf_n"_h,
        "uqshrn_asisdshf_n"_h}},
      {"'(2322=3?'Xd:'Wd), 'Pgl, '(2322=3?'Xd:'Wd), 'Zn.'t",
       {"clasta_r_p_z"_h, "clastb_r_p_z"_h}},
      {"'(2322=3?'Xd:'Wd), 'Pgl, 'Zn.'t", {"lasta_r_p_z"_h, "lastb_r_p_z"_h}},
      {"'Wt, ['Xns]",
       {"ldaprb_32l_memop"_h, "ldaprh_32l_memop"_h, "ldapr_32l_memop"_h}},
      {"'Xt, ['Xns]", {"ldapr_64l_memop"_h}},
      {"'Ws, ['Xns]",
       {"staddb_ldaddb_32_memop"_h,     "staddh_ldaddh_32_memop"_h,
        "staddlb_ldaddlb_32_memop"_h,   "staddlh_ldaddlh_32_memop"_h,
        "staddl_ldaddl_32_memop"_h,     "stadd_ldadd_32_memop"_h,
        "stclrb_ldclrb_32_memop"_h,     "stclrh_ldclrh_32_memop"_h,
        "stclrlb_ldclrlb_32_memop"_h,   "stclrlh_ldclrlh_32_memop"_h,
        "stclrl_ldclrl_32_memop"_h,     "stclr_ldclr_32_memop"_h,
        "steorb_ldeorb_32_memop"_h,     "steorh_ldeorh_32_memop"_h,
        "steorlb_ldeorlb_32_memop"_h,   "steorlh_ldeorlh_32_memop"_h,
        "steorl_ldeorl_32_memop"_h,     "steor_ldeor_32_memop"_h,
        "stsetb_ldsetb_32_memop"_h,     "stseth_ldseth_32_memop"_h,
        "stsetlb_ldsetlb_32_memop"_h,   "stsetlh_ldsetlh_32_memop"_h,
        "stsetl_ldsetl_32_memop"_h,     "stset_ldset_32_memop"_h,
        "stsmaxb_ldsmaxb_32_memop"_h,   "stsmaxh_ldsmaxh_32_memop"_h,
        "stsmaxlb_ldsmaxlb_32_memop"_h, "stsmaxlh_ldsmaxlh_32_memop"_h,
        "stsmaxl_ldsmaxl_32_memop"_h,   "stsmax_ldsmax_32_memop"_h,
        "stsminb_ldsminb_32_memop"_h,   "stsminh_ldsminh_32_memop"_h,
        "stsminlb_ldsminlb_32_memop"_h, "stsminlh_ldsminlh_32_memop"_h,
        "stsminl_ldsminl_32_memop"_h,   "stsmin_ldsmin_32_memop"_h,
        "stumaxb_ldumaxb_32_memop"_h,   "stumaxh_ldumaxh_32_memop"_h,
        "stumaxlb_ldumaxlb_32_memop"_h, "stumaxlh_ldumaxlh_32_memop"_h,
        "stumaxl_ldumaxl_32_memop"_h,   "stumax_ldumax_32_memop"_h,
        "stuminb_lduminb_32_memop"_h,   "stuminh_lduminh_32_memop"_h,
        "stuminlb_lduminlb_32_memop"_h, "stuminlh_lduminlh_32_memop"_h,
        "stuminl_lduminl_32_memop"_h,   "stumin_ldumin_32_memop"_h}},
      {"'Xs, ['Xns]",
       {"staddl_ldaddl_64_memop"_h,
        "stadd_ldadd_64_memop"_h,
        "stclrl_ldclrl_64_memop"_h,
        "stclr_ldclr_64_memop"_h,
        "steorl_ldeorl_64_memop"_h,
        "steor_ldeor_64_memop"_h,
        "stsetl_ldsetl_64_memop"_h,
        "stset_ldset_64_memop"_h,
        "stsmaxl_ldsmaxl_64_memop"_h,
        "stsmax_ldsmax_64_memop"_h,
        "stsminl_ldsminl_64_memop"_h,
        "stsmin_ldsmin_64_memop"_h,
        "stumaxl_ldumaxl_64_memop"_h,
        "stumax_ldumax_64_memop"_h,
        "stuminl_lduminl_64_memop"_h,
        "stumin_ldumin_64_memop"_h}},
      {"'Ws, 'Wt, ['Xns]",
       {"ldaddab_32_memop"_h,   "ldaddah_32_memop"_h,  "ldaddalb_32_memop"_h,
        "ldaddalh_32_memop"_h,  "ldaddal_32_memop"_h,  "ldadda_32_memop"_h,
        "ldaddb_32_memop"_h,    "ldaddh_32_memop"_h,   "ldaddlb_32_memop"_h,
        "ldaddlh_32_memop"_h,   "ldaddl_32_memop"_h,   "ldadd_32_memop"_h,
        "ldclrab_32_memop"_h,   "ldclrah_32_memop"_h,  "ldclralb_32_memop"_h,
        "ldclralh_32_memop"_h,  "ldclral_32_memop"_h,  "ldclra_32_memop"_h,
        "ldclrb_32_memop"_h,    "ldclrh_32_memop"_h,   "ldclrlb_32_memop"_h,
        "ldclrlh_32_memop"_h,   "ldclrl_32_memop"_h,   "ldclr_32_memop"_h,
        "ldeorab_32_memop"_h,   "ldeorah_32_memop"_h,  "ldeoralb_32_memop"_h,
        "ldeoralh_32_memop"_h,  "ldeoral_32_memop"_h,  "ldeora_32_memop"_h,
        "ldeorb_32_memop"_h,    "ldeorh_32_memop"_h,   "ldeorlb_32_memop"_h,
        "ldeorlh_32_memop"_h,   "ldeorl_32_memop"_h,   "ldeor_32_memop"_h,
        "ldsetab_32_memop"_h,   "ldsetah_32_memop"_h,  "ldsetalb_32_memop"_h,
        "ldsetalh_32_memop"_h,  "ldsetal_32_memop"_h,  "ldseta_32_memop"_h,
        "ldsetb_32_memop"_h,    "ldseth_32_memop"_h,   "ldsetlb_32_memop"_h,
        "ldsetlh_32_memop"_h,   "ldsetl_32_memop"_h,   "ldset_32_memop"_h,
        "ldsmaxab_32_memop"_h,  "ldsmaxah_32_memop"_h, "ldsmaxalb_32_memop"_h,
        "ldsmaxalh_32_memop"_h, "ldsmaxal_32_memop"_h, "ldsmaxa_32_memop"_h,
        "ldsmaxb_32_memop"_h,   "ldsmaxh_32_memop"_h,  "ldsmaxlb_32_memop"_h,
        "ldsmaxlh_32_memop"_h,  "ldsmaxl_32_memop"_h,  "ldsmax_32_memop"_h,
        "ldsminab_32_memop"_h,  "ldsminah_32_memop"_h, "ldsminalb_32_memop"_h,
        "ldsminalh_32_memop"_h, "ldsminal_32_memop"_h, "ldsmina_32_memop"_h,
        "ldsminb_32_memop"_h,   "ldsminh_32_memop"_h,  "ldsminlb_32_memop"_h,
        "ldsminlh_32_memop"_h,  "ldsminl_32_memop"_h,  "ldsmin_32_memop"_h,
        "ldumaxab_32_memop"_h,  "ldumaxah_32_memop"_h, "ldumaxalb_32_memop"_h,
        "ldumaxalh_32_memop"_h, "ldumaxal_32_memop"_h, "ldumaxa_32_memop"_h,
        "ldumaxb_32_memop"_h,   "ldumaxh_32_memop"_h,  "ldumaxlb_32_memop"_h,
        "ldumaxlh_32_memop"_h,  "ldumaxl_32_memop"_h,  "ldumax_32_memop"_h,
        "lduminab_32_memop"_h,  "lduminah_32_memop"_h, "lduminalb_32_memop"_h,
        "lduminalh_32_memop"_h, "lduminal_32_memop"_h, "ldumina_32_memop"_h,
        "lduminb_32_memop"_h,   "lduminh_32_memop"_h,  "lduminlb_32_memop"_h,
        "lduminlh_32_memop"_h,  "lduminl_32_memop"_h,  "ldumin_32_memop"_h,
        "swpab_32_memop"_h,     "swpah_32_memop"_h,    "swpalb_32_memop"_h,
        "swpalh_32_memop"_h,    "swpal_32_memop"_h,    "swpa_32_memop"_h,
        "swpb_32_memop"_h,      "swph_32_memop"_h,     "swplb_32_memop"_h,
        "swplh_32_memop"_h,     "swpl_32_memop"_h,     "swp_32_memop"_h}},
      {"'Xs, 'Xt, ['Xns]",
       {"ldaddal_64_memop"_h,  "ldadda_64_memop"_h,   "ldaddl_64_memop"_h,
        "ldadd_64_memop"_h,    "ldclral_64_memop"_h,  "ldclra_64_memop"_h,
        "ldclrl_64_memop"_h,   "ldclr_64_memop"_h,    "ldeoral_64_memop"_h,
        "ldeora_64_memop"_h,   "ldeorl_64_memop"_h,   "ldeor_64_memop"_h,
        "ldsetal_64_memop"_h,  "ldseta_64_memop"_h,   "ldsetl_64_memop"_h,
        "ldset_64_memop"_h,    "ldsmaxal_64_memop"_h, "ldsmaxa_64_memop"_h,
        "ldsmaxl_64_memop"_h,  "ldsmax_64_memop"_h,   "ldsminal_64_memop"_h,
        "ldsmina_64_memop"_h,  "ldsminl_64_memop"_h,  "ldsmin_64_memop"_h,
        "ldumaxal_64_memop"_h, "ldumaxa_64_memop"_h,  "ldumaxl_64_memop"_h,
        "ldumax_64_memop"_h,   "lduminal_64_memop"_h, "ldumina_64_memop"_h,
        "lduminl_64_memop"_h,  "ldumin_64_memop"_h,   "swpal_64_memop"_h,
        "swpa_64_memop"_h,     "swpl_64_memop"_h,     "swp_64_memop"_h}},
      {"'?22:ds'u0400, '?22:ds'u0905",
       {"fcvtas_asisdmisc_r"_h,
        "fcvtau_asisdmisc_r"_h,
        "fcvtms_asisdmisc_r"_h,
        "fcvtmu_asisdmisc_r"_h,
        "fcvtns_asisdmisc_r"_h,
        "fcvtnu_asisdmisc_r"_h,
        "fcvtps_asisdmisc_r"_h,
        "fcvtpu_asisdmisc_r"_h,
        "fcvtzs_asisdmisc_r"_h,
        "fcvtzu_asisdmisc_r"_h,
        "frecpe_asisdmisc_r"_h,
        "frecpx_asisdmisc_r"_h,
        "frsqrte_asisdmisc_r"_h,
        "scvtf_asisdmisc_r"_h,
        "ucvtf_asisdmisc_r"_h}},
      {"'?22:ds'u0400, '?22:ds'u0905, #0.0",
       {"fcmeq_asisdmisc_fz"_h,
        "fcmge_asisdmisc_fz"_h,
        "fcmgt_asisdmisc_fz"_h,
        "fcmle_asisdmisc_fz"_h,
        "fcmlt_asisdmisc_fz"_h}},
      {"'?22:ds'u0400, '?22:ds'u0905, '?22:ds'u2016",
       {"fabd_asisdsame_only"_h,
        "facge_asisdsame_only"_h,
        "facgt_asisdsame_only"_h,
        "fcmeq_asisdsame_only"_h,
        "fcmge_asisdsame_only"_h,
        "fcmgt_asisdsame_only"_h,
        "fmulx_asisdsame_only"_h,
        "frecps_asisdsame_only"_h,
        "frsqrts_asisdsame_only"_h}},
      {"'?22:ds'u0400, '?22:ds'u0905, 'Vf.'?22:ds['IVByElemIndex]",
       {"fmla_asisdelem_r_sd"_h,
        "fmls_asisdelem_r_sd"_h,
        "fmul_asisdelem_r_sd"_h,
        "fmulx_asisdelem_r_sd"_h}},
      {"'?22:ds'u0400, 'Vn.2'?22:ds",
       {"faddp_asisdpair_only_sd"_h,
        "fmaxnmp_asisdpair_only_sd"_h,
        "fmaxp_asisdpair_only_sd"_h,
        "fminnmp_asisdpair_only_sd"_h,
        "fminp_asisdpair_only_sd"_h}},
      {"'Bt, ['Xns'(2012?, #'s2012)]",
       {"ldur_b_ldst_unscaled"_h, "stur_b_ldst_unscaled"_h}},
      {"'Bt, ['Xns'ILU]", {"ldr_b_ldst_pos"_h, "str_b_ldst_pos"_h}},
      {"'Bt, ['Xns, #'s2012]!", {"ldr_b_ldst_immpre"_h, "str_b_ldst_immpre"_h}},
      {"'Bt, ['Xns, 'Offsetreg]",
       {"ldr_b_ldst_regoff"_h,
        "ldr_bl_ldst_regoff"_h,
        "str_b_ldst_regoff"_h,
        "str_bl_ldst_regoff"_h}},
      {"'Bt, ['Xns], #'s2012",
       {"ldr_b_ldst_immpost"_h, "str_b_ldst_immpost"_h}},
      {"'Dd, 'Dn", {"abs_asisdmisc_r"_h, "neg_asisdmisc_r"_h}},
      {"'Dd, 'Dn, #0",
       {"cmeq_asisdmisc_z"_h,
        "cmge_asisdmisc_z"_h,
        "cmgt_asisdmisc_z"_h,
        "cmle_asisdmisc_z"_h,
        "cmlt_asisdmisc_z"_h}},
      {"'Dd, 'Dn, 'Dm",
       {"cmeq_asisdsame_only"_h,
        "cmge_asisdsame_only"_h,
        "cmgt_asisdsame_only"_h,
        "cmhi_asisdsame_only"_h,
        "cmhs_asisdsame_only"_h,
        "cmtst_asisdsame_only"_h,
        "add_asisdsame_only"_h,
        "sub_asisdsame_only"_h}},
      {"'Dd, 'Dn, 'IsR",
       {"sri_asisdshf_r"_h,
        "srshr_asisdshf_r"_h,
        "srsra_asisdshf_r"_h,
        "sshr_asisdshf_r"_h,
        "ssra_asisdshf_r"_h,
        "urshr_asisdshf_r"_h,
        "ursra_asisdshf_r"_h,
        "ushr_asisdshf_r"_h,
        "usra_asisdshf_r"_h}},
      {"'Dd, 'Dn, 'IsL", {"shl_asisdshf_r"_h, "sli_asisdshf_r"_h}},
      {"'Dd, 'Hn", {"fcvt_dh_floatdp1"_h}},
      {"'Dd, 'IFP", {"fmov_d_floatimm"_h}},
      {"'Dd, 'IVMIImm", {"movi_asimdimm_d_ds"_h}},
      {"'Dd, 'Pgl, 'Zn.'t", {"saddv_r_p_z"_h, "uaddv_r_p_z"_h}},
      {"'Dd, 'Sn", {"fcvt_ds_floatdp1"_h}},
      {"'Dd, 'Vn.2d", {"addp_asisdpair_only"_h}},
      {"'Dt, 'Dt2, ['Xns'(2115?, #'s2115*8)]",
       {"ldnp_d_ldstnapair_offs"_h,
        "ldp_d_ldstpair_off"_h,
        "stnp_d_ldstnapair_offs"_h,
        "stp_d_ldstpair_off"_h}},
      {"'Dt, 'Dt2, ['Xns, #'s2115*8]!",
       {"ldp_d_ldstpair_pre"_h, "stp_d_ldstpair_pre"_h}},
      {"'Dt, 'Dt2, ['Xns], #'s2115*8",
       {"ldp_d_ldstpair_post"_h, "stp_d_ldstpair_post"_h}},
      {"'Dt, 'ILLiteral 'LValue", {"ldr_d_loadlit"_h}},
      {"'Dt, ['Xns'(2012?, #'s2012)]",
       {"ldur_d_ldst_unscaled"_h, "stur_d_ldst_unscaled"_h}},
      {"'Dt, ['Xns'ILU]", {"ldr_d_ldst_pos"_h, "str_d_ldst_pos"_h}},
      {"'Dt, ['Xns, #'s2012]!", {"ldr_d_ldst_immpre"_h, "str_d_ldst_immpre"_h}},
      {"'Dt, ['Xns, 'Offsetreg]",
       {"ldr_d_ldst_regoff"_h, "str_d_ldst_regoff"_h}},
      {"'Dt, ['Xns], #'s2012",
       {"ldr_d_ldst_immpost"_h, "str_d_ldst_immpost"_h}},
      {"'Fd, 'Fn", {"fabs_d_floatdp1"_h,     "fabs_h_floatdp1"_h,
                    "fabs_s_floatdp1"_h,     "fmov_d_floatdp1"_h,
                    "fmov_h_floatdp1"_h,     "fmov_s_floatdp1"_h,
                    "fneg_d_floatdp1"_h,     "fneg_h_floatdp1"_h,
                    "fneg_s_floatdp1"_h,     "frint32x_d_floatdp1"_h,
                    "frint32x_s_floatdp1"_h, "frint32z_d_floatdp1"_h,
                    "frint32z_s_floatdp1"_h, "frint64x_d_floatdp1"_h,
                    "frint64x_s_floatdp1"_h, "frint64z_d_floatdp1"_h,
                    "frint64z_s_floatdp1"_h, "frinta_d_floatdp1"_h,
                    "frinta_h_floatdp1"_h,   "frinta_s_floatdp1"_h,
                    "frinti_d_floatdp1"_h,   "frinti_h_floatdp1"_h,
                    "frinti_s_floatdp1"_h,   "frintm_d_floatdp1"_h,
                    "frintm_h_floatdp1"_h,   "frintm_s_floatdp1"_h,
                    "frintn_d_floatdp1"_h,   "frintn_h_floatdp1"_h,
                    "frintn_s_floatdp1"_h,   "frintp_d_floatdp1"_h,
                    "frintp_h_floatdp1"_h,   "frintp_s_floatdp1"_h,
                    "frintx_d_floatdp1"_h,   "frintx_h_floatdp1"_h,
                    "frintx_s_floatdp1"_h,   "frintz_d_floatdp1"_h,
                    "frintz_h_floatdp1"_h,   "frintz_s_floatdp1"_h,
                    "fsqrt_d_floatdp1"_h,    "fsqrt_h_floatdp1"_h,
                    "fsqrt_s_floatdp1"_h}},
      {"'Fd, 'Fn, 'Fm",
       {"fadd_d_floatdp2"_h,   "fadd_h_floatdp2"_h,   "fadd_s_floatdp2"_h,
        "fdiv_d_floatdp2"_h,   "fdiv_h_floatdp2"_h,   "fdiv_s_floatdp2"_h,
        "fmax_d_floatdp2"_h,   "fmax_h_floatdp2"_h,   "fmax_s_floatdp2"_h,
        "fmaxnm_d_floatdp2"_h, "fmaxnm_h_floatdp2"_h, "fmaxnm_s_floatdp2"_h,
        "fmin_d_floatdp2"_h,   "fmin_h_floatdp2"_h,   "fmin_s_floatdp2"_h,
        "fminnm_d_floatdp2"_h, "fminnm_h_floatdp2"_h, "fminnm_s_floatdp2"_h,
        "fmul_d_floatdp2"_h,   "fmul_h_floatdp2"_h,   "fmul_s_floatdp2"_h,
        "fnmul_d_floatdp2"_h,  "fnmul_h_floatdp2"_h,  "fnmul_s_floatdp2"_h,
        "fsub_d_floatdp2"_h,   "fsub_h_floatdp2"_h,   "fsub_s_floatdp2"_h}},
      {"'Fd, 'Fn, 'Fm, 'Cond",
       {"fcsel_d_floatsel"_h, "fcsel_h_floatsel"_h, "fcsel_s_floatsel"_h}},
      {"'Fd, 'Fn, 'Fm, 'Fa",
       {"fmadd_d_floatdp3"_h,
        "fmadd_h_floatdp3"_h,
        "fmadd_s_floatdp3"_h,
        "fmsub_d_floatdp3"_h,
        "fmsub_h_floatdp3"_h,
        "fmsub_s_floatdp3"_h,
        "fnmadd_d_floatdp3"_h,
        "fnmadd_h_floatdp3"_h,
        "fnmadd_s_floatdp3"_h,
        "fnmsub_d_floatdp3"_h,
        "fnmsub_h_floatdp3"_h,
        "fnmsub_s_floatdp3"_h}},
      {"'Fd, 'Rn",
       {"fmov_d64_float2int"_h,
        "fmov_h32_float2int"_h,
        "fmov_h64_float2int"_h,
        "fmov_s32_float2int"_h,
        "scvtf_d32_float2int"_h,
        "scvtf_d64_float2int"_h,
        "scvtf_h32_float2int"_h,
        "scvtf_h64_float2int"_h,
        "scvtf_s32_float2int"_h,
        "scvtf_s64_float2int"_h,
        "ucvtf_d32_float2int"_h,
        "ucvtf_d64_float2int"_h,
        "ucvtf_h32_float2int"_h,
        "ucvtf_h64_float2int"_h,
        "ucvtf_s32_float2int"_h,
        "ucvtf_s64_float2int"_h}},
      {"'Fd, 'Rn, 'IFPFBits",
       {"scvtf_d32_float2fix"_h,
        "scvtf_d64_float2fix"_h,
        "scvtf_h32_float2fix"_h,
        "scvtf_h64_float2fix"_h,
        "scvtf_s32_float2fix"_h,
        "scvtf_s64_float2fix"_h,
        "ucvtf_d32_float2fix"_h,
        "ucvtf_d64_float2fix"_h,
        "ucvtf_h32_float2fix"_h,
        "ucvtf_h64_float2fix"_h,
        "ucvtf_s32_float2fix"_h,
        "ucvtf_s64_float2fix"_h}},
      {"'Fn, #0.0",
       {"fcmp_dz_floatcmp"_h,
        "fcmp_hz_floatcmp"_h,
        "fcmp_sz_floatcmp"_h,
        "fcmpe_dz_floatcmp"_h,
        "fcmpe_hz_floatcmp"_h,
        "fcmpe_sz_floatcmp"_h}},
      {"'Fn, 'Fm",
       {"fcmp_d_floatcmp"_h,
        "fcmp_h_floatcmp"_h,
        "fcmp_s_floatcmp"_h,
        "fcmpe_d_floatcmp"_h,
        "fcmpe_h_floatcmp"_h,
        "fcmpe_s_floatcmp"_h}},
      {"'Fn, 'Fm, 'INzcv, 'Cond",
       {"fccmp_d_floatccmp"_h,
        "fccmp_h_floatccmp"_h,
        "fccmp_s_floatccmp"_h,
        "fccmpe_d_floatccmp"_h,
        "fccmpe_h_floatccmp"_h,
        "fccmpe_s_floatccmp"_h}},
      {"'Hd, 'Dn", {"fcvt_hd_floatdp1"_h}},
      {"'Hd, 'Hn",
       {"fcvtas_asisdmiscfp16_r"_h,
        "fcvtau_asisdmiscfp16_r"_h,
        "fcvtms_asisdmiscfp16_r"_h,
        "fcvtmu_asisdmiscfp16_r"_h,
        "fcvtns_asisdmiscfp16_r"_h,
        "fcvtnu_asisdmiscfp16_r"_h,
        "fcvtps_asisdmiscfp16_r"_h,
        "fcvtpu_asisdmiscfp16_r"_h,
        "fcvtzs_asisdmiscfp16_r"_h,
        "fcvtzu_asisdmiscfp16_r"_h,
        "frecpe_asisdmiscfp16_r"_h,
        "frecpx_asisdmiscfp16_r"_h,
        "frsqrte_asisdmiscfp16_r"_h,
        "scvtf_asisdmiscfp16_r"_h,
        "ucvtf_asisdmiscfp16_r"_h}},
      {"'Hd, 'Hn, #0.0",
       {"fcmeq_asisdmiscfp16_fz"_h,
        "fcmge_asisdmiscfp16_fz"_h,
        "fcmgt_asisdmiscfp16_fz"_h,
        "fcmle_asisdmiscfp16_fz"_h,
        "fcmlt_asisdmiscfp16_fz"_h}},
      {"'Hd, 'Hn, 'Hm",
       {"fabd_asisdsamefp16_only"_h,
        "facge_asisdsamefp16_only"_h,
        "facgt_asisdsamefp16_only"_h,
        "fcmeq_asisdsamefp16_only"_h,
        "fcmge_asisdsamefp16_only"_h,
        "fcmgt_asisdsamefp16_only"_h,
        "fmulx_asisdsamefp16_only"_h,
        "frecps_asisdsamefp16_only"_h,
        "frsqrts_asisdsamefp16_only"_h}},
      {"'Hd, 'Hn, 'Vf.h['IVByElemIndex]",
       {"fmla_asisdelem_rh_h"_h,
        "fmls_asisdelem_rh_h"_h,
        "fmul_asisdelem_rh_h"_h,
        "fmulx_asisdelem_rh_h"_h}},
      {"'Hd, 'IFP", {"fmov_h_floatimm"_h}},
      {"'Hd, 'Sn", {"bfcvt_bs_floatdp1"_h, "fcvt_hs_floatdp1"_h}},
      {"'Hd, 'Vn.'?30:84h",
       {"fmaxnmv_asimdall_only_h"_h,
        "fmaxv_asimdall_only_h"_h,
        "fminnmv_asimdall_only_h"_h,
        "fminv_asimdall_only_h"_h}},
      {"'Hd, 'Vn.2h",
       {"faddp_asisdpair_only_h"_h,
        "fmaxnmp_asisdpair_only_h"_h,
        "fmaxp_asisdpair_only_h"_h,
        "fminnmp_asisdpair_only_h"_h,
        "fminp_asisdpair_only_h"_h}},
      {"'Ht, ['Xns'(2012?, #'s2012)]",
       {"ldur_h_ldst_unscaled"_h, "stur_h_ldst_unscaled"_h}},
      {"'Ht, ['Xns'ILU]", {"ldr_h_ldst_pos"_h, "str_h_ldst_pos"_h}},
      {"'Ht, ['Xns, #'s2012]!", {"ldr_h_ldst_immpre"_h, "str_h_ldst_immpre"_h}},
      {"'Ht, ['Xns, 'Offsetreg]",
       {"ldr_h_ldst_regoff"_h, "str_h_ldst_regoff"_h}},
      {"'Ht, ['Xns], #'s2012",
       {"ldr_h_ldst_immpost"_h, "str_h_ldst_immpost"_h}},
      {"'IY, 'Xt", {"msr_sr_systemmove"_h}},
      {"'M", {"dmb_bo_barriers"_h}},
      {"'Pd, ['Xns'(2110?, #'s2116_1210, mul vl)]",
       {"ldr_p_bi"_h, "str_p_bi"_h}},
      {"'Pd.'t'(0905=31?:, 'Ipc)", {"ptrue_p_s"_h, "ptrues_p_s"_h}},
      {"'Pd.'t, 'Pgl/z, 'Zn.'t, #'s2016",
       {"cmpeq_p_p_zi"_h,
        "cmpge_p_p_zi"_h,
        "cmpgt_p_p_zi"_h,
        "cmple_p_p_zi"_h,
        "cmplt_p_p_zi"_h,
        "cmpne_p_p_zi"_h}},
      {"'Pd.'t, 'Pgl/z, 'Zn.'t, #'u2014",
       {"cmphi_p_p_zi"_h,
        "cmphs_p_p_zi"_h,
        "cmplo_p_p_zi"_h,
        "cmpls_p_p_zi"_h}},
      {"'Pd.'t, 'Pgl/z, 'Zn.'t, #0.0",
       {
           "fcmeq_p_p_z0"_h,
           "fcmge_p_p_z0"_h,
           "fcmgt_p_p_z0"_h,
           "fcmle_p_p_z0"_h,
           "fcmlt_p_p_z0"_h,
           "fcmne_p_p_z0"_h,
       }},
      {"'Pd.'t, 'Pgl/z, 'Zn.'t, 'Zm.'t",
       {"cmpeq_p_p_zz"_h,
        "cmpge_p_p_zz"_h,
        "cmpgt_p_p_zz"_h,
        "cmphi_p_p_zz"_h,
        "cmphs_p_p_zz"_h,
        "cmpne_p_p_zz"_h,
        "facge_p_p_zz"_h,
        "facgt_p_p_zz"_h,
        "fcmeq_p_p_zz"_h,
        "fcmge_p_p_zz"_h,
        "fcmgt_p_p_zz"_h,
        "fcmne_p_p_zz"_h,
        "fcmuo_p_p_zz"_h,
        "match_p_p_zz"_h,
        "nmatch_p_p_zz"_h}},
      {"'Pd.'t, 'Pgl/z, 'Zn.'t, 'Zm.d",
       {"cmpeq_p_p_zw"_h,
        "cmpge_p_p_zw"_h,
        "cmpgt_p_p_zw"_h,
        "cmphi_p_p_zw"_h,
        "cmphs_p_p_zw"_h,
        "cmple_p_p_zw"_h,
        "cmplo_p_p_zw"_h,
        "cmpls_p_p_zw"_h,
        "cmplt_p_p_zw"_h,
        "cmpne_p_p_zw"_h}},
      {"'Pd.'t, 'Pn, 'Pd.'t", {"pnext_p_p_p"_h}},
      {"'Pd.'t, 'Pn.'t", {"rev_p_p"_h}},
      {"'Pd.'t, 'Pn.'t, 'Pm.'t",
       {"trn1_p_pp"_h,
        "trn2_p_pp"_h,
        "uzp1_p_pp"_h,
        "uzp2_p_pp"_h,
        "zip1_p_pp"_h,
        "zip2_p_pp"_h}},
      {"'Pd.'t, 'R12n, 'R12m",
       {"whilege_p_p_rr"_h,
        "whilegt_p_p_rr"_h,
        "whilehi_p_p_rr"_h,
        "whilehs_p_p_rr"_h,
        "whilele_p_p_rr"_h,
        "whilelo_p_p_rr"_h,
        "whilels_p_p_rr"_h,
        "whilelt_p_p_rr"_h,
        "whilerw_p_rr"_h,
        "whilewr_p_rr"_h}},
      {"'Pd.b", {"pfalse_p"_h, "rdffr_p_f"_h}},
      {"'Pd.b, 'Pn.b", {"movs_orrs_p_p_pp_z"_h, "mov_orr_p_p_pp_z"_h}},
      {"'Pd.b, 'Pn, 'Pd.b", {"pfirst_p_p_p"_h}},
      {"'Pd.b, 'Pn/z", {"rdffrs_p_p_f"_h, "rdffr_p_p_f"_h}},
      {"'Pd.b, 'Pm/z, 'Pn.b", {"nots_eors_p_p_pp_z"_h, "not_eor_p_p_pp_z"_h}},
      {"'Pd.b, p'u1310, 'Pn.b, 'Pm.b", {"sel_p_p_pp"_h}},
      {"'Pd.b, p'u1310/'?04:mz, 'Pn.b",
       {"brka_p_p_p"_h,
        "brkas_p_p_p_z"_h,
        "brkb_p_p_p"_h,
        "brkbs_p_p_p_z"_h,
        "movs_ands_p_p_pp_z"_h,
        "mov_and_p_p_pp_z"_h,
        "mov_sel_p_p_pp"_h}},
      {"'Pd.b, p'u1310/z, 'Pn.b, 'Pd.b", {"brkn_p_p_pp"_h, "brkns_p_p_pp"_h}},
      {"'Pd.b, p'u1310/z, 'Pn.b, 'Pm.b",
       {"brkpas_p_p_pp"_h,
        "brkpa_p_p_pp"_h,
        "brkpbs_p_p_pp"_h,
        "brkpb_p_p_pp"_h,
        "ands_p_p_pp_z"_h,
        "and_p_p_pp_z"_h,
        "bics_p_p_pp_z"_h,
        "bic_p_p_pp_z"_h,
        "eors_p_p_pp_z"_h,
        "eor_p_p_pp_z"_h,
        "nands_p_p_pp_z"_h,
        "nand_p_p_pp_z"_h,
        "nors_p_p_pp_z"_h,
        "nor_p_p_pp_z"_h,
        "orns_p_p_pp_z"_h,
        "orn_p_p_pp_z"_h,
        "orrs_p_p_pp_z"_h,
        "orr_p_p_pp_z"_h}},
      {"'Pd.h, 'Pn.b", {"punpkhi_p_p"_h, "punpklo_p_p"_h}},
      {"'Pn.b", {"wrffr_f_p"_h}},
      {"'Qd, 'Qn, 'Vm.2d",
       {"sha512h2_qqv_cryptosha512_3"_h, "sha512h_qqv_cryptosha512_3"_h}},
      {"'Qd, 'Qn, 'Vm.4s",
       {"sha256h2_qqv_cryptosha3"_h, "sha256h_qqv_cryptosha3"_h}},
      {"'Qd, 'Sn, 'Vm.4s",
       {"sha1c_qsv_cryptosha3"_h,
        "sha1m_qsv_cryptosha3"_h,
        "sha1p_qsv_cryptosha3"_h}},
      {"'Qt, 'ILLiteral 'LValue", {"ldr_q_loadlit"_h}},
      {"'Qt, 'Qt2, ['Xns'(2115?, #'s2115*16)]",
       {"ldnp_q_ldstnapair_offs"_h,
        "ldp_q_ldstpair_off"_h,
        "stnp_q_ldstnapair_offs"_h,
        "stp_q_ldstpair_off"_h}},
      {"'Qt, 'Qt2, ['Xns, #'s2115*16]!",
       {"ldp_q_ldstpair_pre"_h, "stp_q_ldstpair_pre"_h}},
      {"'Qt, 'Qt2, ['Xns], #'s2115*16",
       {"ldp_q_ldstpair_post"_h, "stp_q_ldstpair_post"_h}},
      {"'Qt, ['Xns'(2012?, #'s2012)]",
       {"ldur_q_ldst_unscaled"_h, "stur_q_ldst_unscaled"_h}},
      {"'Qt, ['Xns'ILU]", {"ldr_q_ldst_pos"_h, "str_q_ldst_pos"_h}},
      {"'Qt, ['Xns, #'s2012]!", {"ldr_q_ldst_immpre"_h, "str_q_ldst_immpre"_h}},
      {"'Qt, ['Xns, 'Offsetreg]",
       {"ldr_q_ldst_regoff"_h, "str_q_ldst_regoff"_h}},
      {"'Qt, ['Xns], #'s2012",
       {"ldr_q_ldst_immpost"_h, "str_q_ldst_immpost"_h}},
      {"'R20d'(1916?, 'Ipc, mul #'u1916+1'$)'(0905=31?:, 'Ipc)",
       {"sqdecb_r_rs_x"_h,  "sqdecd_r_rs_x"_h,  "sqdech_r_rs_x"_h,
        "sqdecw_r_rs_x"_h,  "sqincb_r_rs_x"_h,  "sqincd_r_rs_x"_h,
        "sqinch_r_rs_x"_h,  "sqincw_r_rs_x"_h,  "uqdecb_r_rs_uw"_h,
        "uqdecb_r_rs_x"_h,  "uqdecd_r_rs_uw"_h, "uqdecd_r_rs_x"_h,
        "uqdech_r_rs_uw"_h, "uqdech_r_rs_x"_h,  "uqdecw_r_rs_uw"_h,
        "uqdecw_r_rs_x"_h,  "uqincb_r_rs_uw"_h, "uqincb_r_rs_x"_h,
        "uqincd_r_rs_uw"_h, "uqincd_r_rs_x"_h,  "uqinch_r_rs_uw"_h,
        "uqinch_r_rs_x"_h,  "uqincw_r_rs_uw"_h, "uqincw_r_rs_x"_h}},
      {"'R22n, 'R22m", {"ctermeq_rr"_h, "ctermne_rr"_h}},
      {"'Rd, #0x'x2005'(2221?, lsl #'u2221*16)",
       {"movk_32_movewide"_h, "movk_64_movewide"_h}},
      {"'Rd, 'CInv",
       {"cset_csinc_32_condsel"_h,
        "cset_csinc_64_condsel"_h,
        "csetm_csinv_32_condsel"_h,
        "csetm_csinv_64_condsel"_h}},
      {"'Rd, 'Fn", {"fcvtas_32d_float2int"_h,  "fcvtas_32h_float2int"_h,
                    "fcvtas_32s_float2int"_h,  "fcvtas_64d_float2int"_h,
                    "fcvtas_64h_float2int"_h,  "fcvtas_64s_float2int"_h,
                    "fcvtau_32d_float2int"_h,  "fcvtau_32h_float2int"_h,
                    "fcvtau_32s_float2int"_h,  "fcvtau_64d_float2int"_h,
                    "fcvtau_64h_float2int"_h,  "fcvtau_64s_float2int"_h,
                    "fcvtms_32d_float2int"_h,  "fcvtms_32h_float2int"_h,
                    "fcvtms_32s_float2int"_h,  "fcvtms_64d_float2int"_h,
                    "fcvtms_64h_float2int"_h,  "fcvtms_64s_float2int"_h,
                    "fcvtmu_32d_float2int"_h,  "fcvtmu_32h_float2int"_h,
                    "fcvtmu_32s_float2int"_h,  "fcvtmu_64d_float2int"_h,
                    "fcvtmu_64h_float2int"_h,  "fcvtmu_64s_float2int"_h,
                    "fcvtns_32d_float2int"_h,  "fcvtns_32h_float2int"_h,
                    "fcvtns_32s_float2int"_h,  "fcvtns_64d_float2int"_h,
                    "fcvtns_64h_float2int"_h,  "fcvtns_64s_float2int"_h,
                    "fcvtnu_32d_float2int"_h,  "fcvtnu_32h_float2int"_h,
                    "fcvtnu_32s_float2int"_h,  "fcvtnu_64d_float2int"_h,
                    "fcvtnu_64h_float2int"_h,  "fcvtnu_64s_float2int"_h,
                    "fcvtps_32d_float2int"_h,  "fcvtps_32h_float2int"_h,
                    "fcvtps_32s_float2int"_h,  "fcvtps_64d_float2int"_h,
                    "fcvtps_64h_float2int"_h,  "fcvtps_64s_float2int"_h,
                    "fcvtpu_32d_float2int"_h,  "fcvtpu_32h_float2int"_h,
                    "fcvtpu_32s_float2int"_h,  "fcvtpu_64d_float2int"_h,
                    "fcvtpu_64h_float2int"_h,  "fcvtpu_64s_float2int"_h,
                    "fcvtzs_32d_float2int"_h,  "fcvtzs_32h_float2int"_h,
                    "fcvtzs_32s_float2int"_h,  "fcvtzs_64d_float2int"_h,
                    "fcvtzs_64h_float2int"_h,  "fcvtzs_64s_float2int"_h,
                    "fcvtzu_32d_float2int"_h,  "fcvtzu_32h_float2int"_h,
                    "fcvtzu_32s_float2int"_h,  "fcvtzu_64d_float2int"_h,
                    "fcvtzu_64h_float2int"_h,  "fcvtzu_64s_float2int"_h,
                    "fjcvtzs_32d_float2int"_h, "fmov_32h_float2int"_h,
                    "fmov_32s_float2int"_h,    "fmov_64d_float2int"_h,
                    "fmov_64h_float2int"_h}},
      {"'Rd, 'Fn, 'IFPFBits",
       {"fcvtzs_32d_float2fix"_h,
        "fcvtzs_32h_float2fix"_h,
        "fcvtzs_32s_float2fix"_h,
        "fcvtzs_64d_float2fix"_h,
        "fcvtzs_64h_float2fix"_h,
        "fcvtzs_64s_float2fix"_h,
        "fcvtzu_32d_float2fix"_h,
        "fcvtzu_32h_float2fix"_h,
        "fcvtzu_32s_float2fix"_h,
        "fcvtzu_64d_float2fix"_h,
        "fcvtzu_64h_float2fix"_h,
        "fcvtzu_64s_float2fix"_h}},
      {"'Rd, 'IBZ-r, #'s1510+1",
       {"bfc_bfm_32m_bitfield"_h, "bfc_bfm_64m_bitfield"_h}},
      {"'Rd, 'IMoveImm",
       {"movz_32_movewide"_h,
        "movz_64_movewide"_h,
        "movn_32_movewide"_h,
        "movn_64_movewide"_h,
        "mov_movz_32_movewide"_h,
        "mov_movz_64_movewide"_h}},
      {"'Rd, 'IMoveNeg", {"mov_movn_32_movewide"_h, "mov_movn_64_movewide"_h}},
      {"'Rd, 'Rm",
       {"ngc_sbc_32_addsub_carry"_h,
        "ngc_sbc_64_addsub_carry"_h,
        "ngcs_sbcs_32_addsub_carry"_h,
        "ngcs_sbcs_64_addsub_carry"_h,
        "mov_orr_32_log_shift"_h,
        "mov_orr_64_log_shift"_h}},
      {"'Rd, 'Rm'NDP",
       {"neg_sub_32_addsub_shift"_h,
        "neg_sub_64_addsub_shift"_h,
        "negs_subs_32_addsub_shift"_h,
        "negs_subs_64_addsub_shift"_h}},
      {"'Rd, 'Rm'NLo", {"mvn_orn_32_log_shift"_h, "mvn_orn_64_log_shift"_h}},
      {"'Rd, 'Rn",
       {"abs_32_dp_1src"_h,
        "abs_64_dp_1src"_h,
        "cls_32_dp_1src"_h,
        "cls_64_dp_1src"_h,
        "clz_32_dp_1src"_h,
        "clz_64_dp_1src"_h,
        "cnt_32_dp_1src"_h,
        "cnt_64_dp_1src"_h,
        "ctz_32_dp_1src"_h,
        "ctz_64_dp_1src"_h,
        "rbit_32_dp_1src"_h,
        "rbit_64_dp_1src"_h,
        "rev16_32_dp_1src"_h,
        "rev16_64_dp_1src"_h,
        "rev32_64_dp_1src"_h,
        "rev_32_dp_1src"_h,
        "rev_64_dp_1src"_h}},
      {"'Rd, 'Rn, #'s1710",
       {"smax_32_minmax_imm"_h,
        "smax_64_minmax_imm"_h,
        "smin_32_minmax_imm"_h,
        "smin_64_minmax_imm"_h}},
      {"'Rd, 'Rn, #'u1510", {"ror_extr_32_extract"_h, "ror_extr_64_extract"_h}},
      {"'Rd, 'Rn, #'u1710",
       {"umax_32u_minmax_imm"_h,
        "umax_64u_minmax_imm"_h,
        "umin_32u_minmax_imm"_h,
        "umin_64u_minmax_imm"_h}},
      {"'Rd, 'Rn, 'CInv",
       {"cinc_csinc_32_condsel"_h,
        "cinc_csinc_64_condsel"_h,
        "cinv_csinv_32_condsel"_h,
        "cinv_csinv_64_condsel"_h,
        "cneg_csneg_32_condsel"_h,
        "cneg_csneg_64_condsel"_h}},
      {"'Rd, 'Rn, #'u2116",
       {"asr_sbfm_32m_bitfield"_h,
        "asr_sbfm_64m_bitfield"_h,
        "lsr_ubfm_32m_bitfield"_h,
        "lsr_ubfm_64m_bitfield"_h}},
      {"'Rd, 'Rn, #'u2116, 'IBs-r+1",
       {"sbfx_sbfm_32m_bitfield"_h,
        "sbfx_sbfm_64m_bitfield"_h,
        "ubfx_ubfm_32m_bitfield"_h,
        "ubfx_ubfm_64m_bitfield"_h,
        "bfxil_bfm_32m_bitfield"_h,
        "bfxil_bfm_64m_bitfield"_h}},
      {"'Rd, 'Rn, 'IBZ-r",
       {"lsl_ubfm_32m_bitfield"_h, "lsl_ubfm_64m_bitfield"_h}},
      {"'Rd, 'Rn, 'IBZ-r, #'s1510+1",
       {"sbfiz_sbfm_32m_bitfield"_h,
        "sbfiz_sbfm_64m_bitfield"_h,
        "ubfiz_ubfm_32m_bitfield"_h,
        "ubfiz_ubfm_64m_bitfield"_h,
        "bfi_bfm_32m_bitfield"_h,
        "bfi_bfm_64m_bitfield"_h}},
      {"'Rd, 'Rn, 'Rm", {"crc32b_32c_dp_2src"_h,    "crc32cb_32c_dp_2src"_h,
                         "crc32ch_32c_dp_2src"_h,   "crc32cw_32c_dp_2src"_h,
                         "crc32h_32c_dp_2src"_h,    "crc32w_32c_dp_2src"_h,
                         "sdiv_32_dp_2src"_h,       "sdiv_64_dp_2src"_h,
                         "smax_32_dp_2src"_h,       "smax_64_dp_2src"_h,
                         "smin_32_dp_2src"_h,       "smin_64_dp_2src"_h,
                         "udiv_32_dp_2src"_h,       "udiv_64_dp_2src"_h,
                         "umax_32_dp_2src"_h,       "umax_64_dp_2src"_h,
                         "umin_32_dp_2src"_h,       "umin_64_dp_2src"_h,
                         "adcs_32_addsub_carry"_h,  "adcs_64_addsub_carry"_h,
                         "adc_32_addsub_carry"_h,   "adc_64_addsub_carry"_h,
                         "sbcs_32_addsub_carry"_h,  "sbcs_64_addsub_carry"_h,
                         "sbc_32_addsub_carry"_h,   "sbc_64_addsub_carry"_h,
                         "mul_madd_32a_dp_3src"_h,  "mul_madd_64a_dp_3src"_h,
                         "mneg_msub_32a_dp_3src"_h, "mneg_msub_64a_dp_3src"_h,
                         "asr_asrv_32_dp_2src"_h,   "asr_asrv_64_dp_2src"_h,
                         "lsl_lslv_32_dp_2src"_h,   "lsl_lslv_64_dp_2src"_h,
                         "lsr_lsrv_32_dp_2src"_h,   "lsr_lsrv_64_dp_2src"_h,
                         "ror_rorv_32_dp_2src"_h,   "ror_rorv_64_dp_2src"_h}},
      {"'Rd, 'Rn, 'Rm, #'u1510", {"extr_32_extract"_h, "extr_64_extract"_h}},
      {"'Rd, 'Rn, 'Rm, 'Cond",
       {"csel_32_condsel"_h,
        "csel_64_condsel"_h,
        "csinc_32_condsel"_h,
        "csinc_64_condsel"_h,
        "csinv_32_condsel"_h,
        "csinv_64_condsel"_h,
        "csneg_32_condsel"_h,
        "csneg_64_condsel"_h}},
      {"'Rd, 'Rn, 'Rm, 'Ra",
       {"madd_32a_dp_3src"_h,
        "madd_64a_dp_3src"_h,
        "msub_32a_dp_3src"_h,
        "msub_64a_dp_3src"_h}},
      {"'Rd, 'Rn, 'Rm'NDP",
       {"adds_32_addsub_shift"_h,
        "adds_64_addsub_shift"_h,
        "add_32_addsub_shift"_h,
        "add_64_addsub_shift"_h,
        "subs_32_addsub_shift"_h,
        "subs_64_addsub_shift"_h,
        "sub_32_addsub_shift"_h,
        "sub_64_addsub_shift"_h}},
      {"'Rd, 'Rn, 'Rm'NLo",
       {"ands_32_log_shift"_h,
        "ands_64_log_shift"_h,
        "and_32_log_shift"_h,
        "and_64_log_shift"_h,
        "bics_32_log_shift"_h,
        "bics_64_log_shift"_h,
        "bic_32_log_shift"_h,
        "bic_64_log_shift"_h,
        "eon_32_log_shift"_h,
        "eon_64_log_shift"_h,
        "eor_32_log_shift"_h,
        "eor_64_log_shift"_h,
        "orn_32_log_shift"_h,
        "orn_64_log_shift"_h,
        "orr_32_log_shift"_h,
        "orr_64_log_shift"_h}},
      {"'Rd, 'Vn.D[1]", {"fmov_64vx_float2int"_h}},
      {"'Rd, 'Wn",
       {"sxtb_sbfm_32m_bitfield"_h,
        "sxtb_sbfm_64m_bitfield"_h,
        "sxth_sbfm_32m_bitfield"_h,
        "sxth_sbfm_64m_bitfield"_h,
        "sxtw_sbfm_64m_bitfield"_h,
        "uxtb_ubfm_32m_bitfield"_h,
        "uxtb_ubfm_64m_bitfield"_h,
        "uxth_ubfm_32m_bitfield"_h,
        "uxth_ubfm_64m_bitfield"_h}},
      {"'Rd, 'Xns, 'Rm", {"gmi_64g_dp_2src"_h}},
      {"'Rds, 'ITri", {"mov_orr_32_log_imm"_h, "mov_orr_64_log_imm"_h}},
      {"'Rds, 'Rn, 'ITri",
       {"ands_32s_log_imm"_h,
        "ands_64s_log_imm"_h,
        "and_32_log_imm"_h,
        "and_64_log_imm"_h,
        "eor_32_log_imm"_h,
        "eor_64_log_imm"_h,
        "orr_32_log_imm"_h,
        "orr_64_log_imm"_h}},
      {"'Rds, 'Rns", {"mov_add_32_addsub_imm"_h, "mov_add_64_addsub_imm"_h}},
      {"'Rds, 'Rns, '(1413=3?x:w)'(2016=31?zr:'u2016)'Ext",
       {"adds_32s_addsub_ext"_h,
        "adds_64s_addsub_ext"_h,
        "add_32_addsub_ext"_h,
        "add_64_addsub_ext"_h,
        "subs_32s_addsub_ext"_h,
        "subs_64s_addsub_ext"_h,
        "sub_32_addsub_ext"_h,
        "sub_64_addsub_ext"_h}},
      {"'Rds, 'Rns, 'IAddSub",
       {"adds_32s_addsub_imm"_h,
        "adds_64s_addsub_imm"_h,
        "add_32_addsub_imm"_h,
        "add_64_addsub_imm"_h,
        "subs_32s_addsub_imm"_h,
        "subs_64s_addsub_imm"_h,
        "sub_32_addsub_imm"_h,
        "sub_64_addsub_imm"_h}},
      {"'Rn, #'u2016, 'INzcv, 'Cond",
       {"ccmn_32_condcmp_imm"_h,
        "ccmn_64_condcmp_imm"_h,
        "ccmp_32_condcmp_imm"_h,
        "ccmp_64_condcmp_imm"_h}},
      {"'Rn, 'ITri", {"tst_ands_32s_log_imm"_h, "tst_ands_64s_log_imm"_h}},
      {"'Rn, 'Rm, 'INzcv, 'Cond",
       {"ccmn_32_condcmp_reg"_h,
        "ccmn_64_condcmp_reg"_h,
        "ccmp_32_condcmp_reg"_h,
        "ccmp_64_condcmp_reg"_h}},
      {"'Rn, 'Rm'NDP",
       {"cmn_adds_32_addsub_shift"_h,
        "cmn_adds_64_addsub_shift"_h,
        "cmp_subs_32_addsub_shift"_h,
        "cmp_subs_64_addsub_shift"_h}},
      {"'Rn, 'Rm'NLo", {"tst_ands_32_log_shift"_h, "tst_ands_64_log_shift"_h}},
      {"'Rns, '(1413=3?x:w)'(2016=31?zr:'u2016)'Ext",
       {"cmn_adds_32s_addsub_ext"_h,
        "cmn_adds_64s_addsub_ext"_h,
        "cmp_subs_32s_addsub_ext"_h,
        "cmp_subs_64s_addsub_ext"_h}},
      {"'Rns, 'IAddSub",
       {"cmn_adds_32s_addsub_imm"_h,
        "cmn_adds_64s_addsub_imm"_h,
        "cmp_subs_32s_addsub_imm"_h,
        "cmp_subs_64s_addsub_imm"_h}},
      {"'Rt, #'u3131_2319, 'TImmTest",
       {"tbnz_only_testbranch"_h, "tbz_only_testbranch"_h}},
      {"'Rt, 'TImmCmpa",
       {"cbnz_32_compbranch"_h,
        "cbnz_64_compbranch"_h,
        "cbz_32_compbranch"_h,
        "cbz_64_compbranch"_h}},
      {"'Sd, 'Dn", {"fcvt_sd_floatdp1"_h, "fcvtxn_asisdmisc_n"_h}},
      {"'Sd, 'Hn", {"fcvt_sh_floatdp1"_h}},
      {"'Sd, 'IFP", {"fmov_s_floatimm"_h}},
      {"'Sd, 'Sn", {"sha1h_ss_cryptosha2"_h}},
      {"'Sd, 'Vn.4s",
       {"fmaxnmv_asimdall_only_sd"_h,
        "fminnmv_asimdall_only_sd"_h,
        "fmaxv_asimdall_only_sd"_h,
        "fminv_asimdall_only_sd"_h}},
      {"'St, 'ILLiteral 'LValue", {"ldr_s_loadlit"_h}},
      {"'St, 'St2, ['Xns'(2115?, #'s2115*4)]",
       {"ldnp_s_ldstnapair_offs"_h,
        "ldp_s_ldstpair_off"_h,
        "stnp_s_ldstnapair_offs"_h,
        "stp_s_ldstpair_off"_h}},
      {"'St, 'St2, ['Xns, #'s2115*4]!",
       {"ldp_s_ldstpair_pre"_h, "stp_s_ldstpair_pre"_h}},
      {"'St, 'St2, ['Xns], #'s2115*4",
       {"ldp_s_ldstpair_post"_h, "stp_s_ldstpair_post"_h}},
      {"'St, ['Xns'(2012?, #'s2012)]",
       {"ldur_s_ldst_unscaled"_h, "stur_s_ldst_unscaled"_h}},
      {"'St, ['Xns'ILU]", {"ldr_s_ldst_pos"_h, "str_s_ldst_pos"_h}},
      {"'St, ['Xns, #'s2012]!", {"ldr_s_ldst_immpre"_h, "str_s_ldst_immpre"_h}},
      {"'St, ['Xns, 'Offsetreg]",
       {"ldr_s_ldst_regoff"_h, "str_s_ldst_regoff"_h}},
      {"'St, ['Xns], #'s2012",
       {"ldr_s_ldst_immpost"_h, "str_s_ldst_immpost"_h}},
      {"'TImmCond",
       {"b.'CBrn_b_only_condbranch"_h, "bc.'CBrn_bc_only_condbranch"_h}},
      {"'TImmUncn", {"b_only_branch_imm"_h, "bl_only_branch_imm"_h}},
      {"'Vd.'{nf}, 'Vn.'{nf}, 'Vm.'{nf}",
       {"fabd_asimdsame_only"_h,    "facge_asimdsame_only"_h,
        "facgt_asimdsame_only"_h,   "faddp_asimdsame_only"_h,
        "fadd_asimdsame_only"_h,    "fcmeq_asimdsame_only"_h,
        "fcmge_asimdsame_only"_h,   "fcmgt_asimdsame_only"_h,
        "fdiv_asimdsame_only"_h,    "fmaxnmp_asimdsame_only"_h,
        "fmaxnm_asimdsame_only"_h,  "fmaxp_asimdsame_only"_h,
        "fmax_asimdsame_only"_h,    "fminnmp_asimdsame_only"_h,
        "fminnm_asimdsame_only"_h,  "fminp_asimdsame_only"_h,
        "fmin_asimdsame_only"_h,    "fmla_asimdsame_only"_h,
        "fmls_asimdsame_only"_h,    "fmulx_asimdsame_only"_h,
        "fmul_asimdsame_only"_h,    "frecps_asimdsame_only"_h,
        "frsqrts_asimdsame_only"_h, "fsub_asimdsame_only"_h}},
      {"'Vd.'{nf}, 'Vn.'{nf}, 'Vf.'{nscal}['IVByElemIndex]",
       {"fmla_asimdelem_r_sd"_h,
        "fmls_asimdelem_r_sd"_h,
        "fmulx_asimdelem_r_sd"_h,
        "fmul_asimdelem_r_sd"_h}},
      {"'Vd.'{npair}, 'Vn.'{n}",
       {"sadalp_asimdmisc_p"_h,
        "saddlp_asimdmisc_p"_h,
        "uadalp_asimdmisc_p"_h,
        "uaddlp_asimdmisc_p"_h}},
      {"'Vd.'{nshift}, 'Vn.'{nshift}, 'IsL",
       {"sqshlu_asimdshf_r"_h,
        "sqshl_asimdshf_r"_h,
        "uqshl_asimdshf_r"_h,
        "shl_asimdshf_r"_h,
        "sli_asimdshf_r"_h}},
      {"'Vd.'{nshift}, 'Vn.'{nshift}, 'IsR",
       {"sri_asimdshf_r"_h,
        "srshr_asimdshf_r"_h,
        "srsra_asimdshf_r"_h,
        "sshr_asimdshf_r"_h,
        "ssra_asimdshf_r"_h,
        "urshr_asimdshf_r"_h,
        "ursra_asimdshf_r"_h,
        "ushr_asimdshf_r"_h,
        "usra_asimdshf_r"_h,
        "scvtf_asimdshf_c"_h,
        "ucvtf_asimdshf_c"_h,
        "fcvtzs_asimdshf_c"_h,
        "fcvtzu_asimdshf_c"_h}},
      {"'Vd.'{nshift}, 'Vn.'{nshiftln}, 'IsR",
       {"shrn_asimdshf_n"_h,
        "rshrn_asimdshf_n"_h,
        "sqshrn_asimdshf_n"_h,
        "sqrshrn_asimdshf_n"_h,
        "sqshrun_asimdshf_n"_h,
        "sqrshrun_asimdshf_n"_h,
        "uqshrn_asimdshf_n"_h,
        "uqrshrn_asimdshf_n"_h,
        "shrn2_shrn_asimdshf_n"_h,
        "rshrn2_rshrn_asimdshf_n"_h,
        "sqshrn2_sqshrn_asimdshf_n"_h,
        "sqrshrn2_sqrshrn_asimdshf_n"_h,
        "sqshrun2_sqshrun_asimdshf_n"_h,
        "sqrshrun2_sqrshrun_asimdshf_n"_h,
        "uqshrn2_uqshrn_asimdshf_n"_h,
        "uqrshrn2_uqrshrn_asimdshf_n"_h}},
      {"'Vd.'{nshiftln}, 'Vn.'{nshift}",
       {"sxtl_sshll_asimdshf_l"_h,
        "uxtl_ushll_asimdshf_l"_h,
        "sxtl2_sshll_asimdshf_l"_h,
        "uxtl2_ushll_asimdshf_l"_h}},
      {"'Vd.'{nshiftln}, 'Vn.'{nshift}, 'IsL",
       {"sshll_asimdshf_l"_h,
        "ushll_asimdshf_l"_h,
        "sshll2_sshll_asimdshf_l"_h,
        "ushll2_ushll_asimdshf_l"_h}},
      {"'Vd.'{ntri}, '(1916=8?'Xn:'Wn)", {"dup_asimdins_dr_r"_h}},
      {"'Vd.'{ntri}, 'Vn.'{ntriscal}['IVInsIndex1]", {"dup_asimdins_dv_v"_h}},
      {"'Vd.'{ntriscal}['IVInsIndex1], '(1916=8?'Xn:'Wn)",
       {"mov_ins_asimdins_ir_r"_h}},
      {"'Vd.'{ntriscal}['IVInsIndex1], 'Vn.'{ntriscal}['IVInsIndex2]",
       {"mov_ins_asimdins_iv_v"_h}},
      {"'Vd.'(22?1q:8h), 'Vn.'(22?'u3030+1d:'u3027+7b), "
       "'Vm.'(22?'u3030+1d:'u3027+7b)",
       {"pmull_asimddiff_l"_h, "pmull2_pmull_asimddiff_l"_h}},
      {"'Vd.'(22?2d:4s), 'Vn.'(22?2s:4h)", {"fcvtl_asimdmisc_l"_h}},
      {"'Vd.'(22?2d:4s), 'Vn.'(22?4s:8h)", {"fcvtl2_fcvtl_asimdmisc_l"_h}},
      {"'Vd.'(22?2s:4h), 'Vn.'(22?2d:4s)", {"fcvtn_asimdmisc_n"_h}},
      {"'Vd.'(22?4s:8h), 'Vn.'(22?2d:4s)", {"fcvtn2_fcvtn_asimdmisc_n"_h}},
      {"'Vd.'(22?4s:2d), 'Vn.'{n}, 'Vf.'{nscal}['IVByElemIndex]",
       {"smlal_asimdelem_l"_h,
        "smlsl_asimdelem_l"_h,
        "smull_asimdelem_l"_h,
        "umlal_asimdelem_l"_h,
        "umlsl_asimdelem_l"_h,
        "umull_asimdelem_l"_h,
        "sqdmull_asimdelem_l"_h,
        "sqdmlal_asimdelem_l"_h,
        "sqdmlsl_asimdelem_l"_h,
        "smlal2_smlal_asimdelem_l"_h,
        "smlsl2_smlsl_asimdelem_l"_h,
        "smull2_smull_asimdelem_l"_h,
        "umlal2_umlal_asimdelem_l"_h,
        "umlsl2_umlsl_asimdelem_l"_h,
        "umull2_umull_asimdelem_l"_h,
        "sqdmull2_sqdmull_asimdelem_l"_h,
        "sqdmlal2_sqdmlal_asimdelem_l"_h,
        "sqdmlsl2_sqdmlsl_asimdelem_l"_h}},
      {"'Vd.'(2222=1?2d:'?30:42s), 'Vn.'(2222=1?2d:'?30:42s)",
       {"fabs_asimdmisc_r"_h,     "fcvtas_asimdmisc_r"_h,
        "fcvtau_asimdmisc_r"_h,   "fcvtms_asimdmisc_r"_h,
        "fcvtmu_asimdmisc_r"_h,   "fcvtns_asimdmisc_r"_h,
        "fcvtnu_asimdmisc_r"_h,   "fcvtps_asimdmisc_r"_h,
        "fcvtpu_asimdmisc_r"_h,   "fcvtzs_asimdmisc_r"_h,
        "fcvtzu_asimdmisc_r"_h,   "fneg_asimdmisc_r"_h,
        "frecpe_asimdmisc_r"_h,   "frint32x_asimdmisc_r"_h,
        "frint32z_asimdmisc_r"_h, "frint64x_asimdmisc_r"_h,
        "frint64z_asimdmisc_r"_h, "frinta_asimdmisc_r"_h,
        "frinti_asimdmisc_r"_h,   "frintm_asimdmisc_r"_h,
        "frintn_asimdmisc_r"_h,   "frintp_asimdmisc_r"_h,
        "frintx_asimdmisc_r"_h,   "frintz_asimdmisc_r"_h,
        "frsqrte_asimdmisc_r"_h,  "fsqrt_asimdmisc_r"_h,
        "scvtf_asimdmisc_r"_h,    "ucvtf_asimdmisc_r"_h}},
      {"'Vd.'(2222=1?2d:'?30:42s), 'Vn.'(2222=1?2d:'?30:42s), #0.0",
       {"fcmeq_asimdmisc_fz"_h,
        "fcmge_asimdmisc_fz"_h,
        "fcmgt_asimdmisc_fz"_h,
        "fcmle_asimdmisc_fz"_h,
        "fcmlt_asimdmisc_fz"_h}},
      {"'Vd.'(30?16:8)b, 'Vn.'(30?16:8)b",
       {"rbit_asimdmisc_r"_h,
        "cnt_asimdmisc_r"_h,
        "rev16_asimdmisc_r"_h,
        "mov_orr_asimdsame_only"_h,
        "mvn_not_asimdmisc_r"_h}},
      {"'Vd.'(30?16:8)b, 'Vn.'(30?16:8)b, 'Vm.'(30?16:8)b",
       {"and_asimdsame_only"_h,
        "bic_asimdsame_only"_h,
        "bif_asimdsame_only"_h,
        "bit_asimdsame_only"_h,
        "bsl_asimdsame_only"_h,
        "eor_asimdsame_only"_h,
        "orn_asimdsame_only"_h,
        "orr_asimdsame_only"_h,
        "pmul_asimdsame_only"_h}},
      {"'Vd.'(30?16:8)b, 'Vn.'(30?16:8)b, 'Vm.'(30?16:8)b, #'u1411",
       {"ext_asimdext_only"_h}},
      {"'Vd.'(30?16:8)b, {'Vn.16b, 'Vn2.16b, 'Vn3.16b, 'Vn4.16b}, "
       "'Vm.'(30?16:8)b",
       {"tbl_asimdtbl_l4_4"_h, "tbx_asimdtbl_l4_4"_h}},
      {"'Vd.'(30?16:8)b, {'Vn.16b, 'Vn2.16b, 'Vn3.16b}, 'Vm.'(30?16:8)b",
       {"tbl_asimdtbl_l3_3"_h, "tbx_asimdtbl_l3_3"_h}},
      {"'Vd.'(30?16:8)b, {'Vn.16b, 'Vn2.16b}, 'Vm.'(30?16:8)b",
       {"tbl_asimdtbl_l2_2"_h, "tbx_asimdtbl_l2_2"_h}},
      {"'Vd.'(30?16:8)b, {'Vn.16b}, 'Vm.'(30?16:8)b",
       {"tbl_asimdtbl_l1_1"_h, "tbx_asimdtbl_l1_1"_h}},
      {"'Vd.'?30:42s, 'Vn.'(30?16:8)b, 'Vm.4b['u1111_2121]",
       {"sdot_asimdelem_d"_h,
        "sudot_asimdelem_d"_h,
        "udot_asimdelem_d"_h,
        "usdot_asimdelem_d"_h}},
      {"'Vd.'?30:42s, 'Vn.'?30:42h, 'Ve.h['IVByElemIndexFHM]",
       {"fmlal2_asimdelem_lh"_h,
        "fmlal_asimdelem_lh"_h,
        "fmlsl2_asimdelem_lh"_h,
        "fmlsl_asimdelem_lh"_h}},
      {"'Vd.'?30:42s, 'Vn.'?30:42h, 'Vm.'?30:42h",
       {"fmlal2_asimdsame_f"_h,
        "fmlal_asimdsame_f"_h,
        "fmlsl2_asimdsame_f"_h,
        "fmlsl_asimdsame_f"_h}},
      {"'Vd.'?30:42s, 'Vn.'?30:84h, 'Vm.'?30:84h",
       {"bfdot_asimdsame2_d"_h, "bfmmla_asimdsame2_e"_h}},
      {"'Vd.'?30:42s, 'Vn.'?30:84h, 'Vm.2h['u1111_2121]",
       {"bfdot_asimdelem_e"_h}},
      {"'Vd.'?30:42s, 'Vn.'?30:42s",
       {"urecpe_asimdmisc_r"_h, "ursqrte_asimdmisc_r"_h}},
      {"'Vd.'?30:42s, 'Vn.'(30?16:8)b, 'Vm.'(30?16:8)b",
       {"sdot_asimdsame2_d"_h, "udot_asimdsame2_d"_h, "usdot_asimdsame2_d"_h}},
      {"'Vd.'?30:42s, 'Vn.2d",
       {"fcvtxn_asimdmisc_n"_h, "fcvtxn2_fcvtxn_asimdmisc_n"_h}},
      {"'Vd.'?30:84h, 'Vn.4s",
       {"bfcvtn_asimdmisc_4s"_h, "bfcvtn2_bfcvtn_asimdmisc_4s"_h}},
      {"'Vd.'?30:84h, 'Vn.'?30:84h",
       {"fabs_asimdmiscfp16_r"_h,    "fcvtas_asimdmiscfp16_r"_h,
        "fcvtau_asimdmiscfp16_r"_h,  "fcvtms_asimdmiscfp16_r"_h,
        "fcvtmu_asimdmiscfp16_r"_h,  "fcvtns_asimdmiscfp16_r"_h,
        "fcvtnu_asimdmiscfp16_r"_h,  "fcvtps_asimdmiscfp16_r"_h,
        "fcvtpu_asimdmiscfp16_r"_h,  "fcvtzs_asimdmiscfp16_r"_h,
        "fcvtzu_asimdmiscfp16_r"_h,  "fneg_asimdmiscfp16_r"_h,
        "frecpe_asimdmiscfp16_r"_h,  "frinta_asimdmiscfp16_r"_h,
        "frinti_asimdmiscfp16_r"_h,  "frintm_asimdmiscfp16_r"_h,
        "frintn_asimdmiscfp16_r"_h,  "frintp_asimdmiscfp16_r"_h,
        "frintx_asimdmiscfp16_r"_h,  "frintz_asimdmiscfp16_r"_h,
        "frsqrte_asimdmiscfp16_r"_h, "fsqrt_asimdmiscfp16_r"_h,
        "scvtf_asimdmiscfp16_r"_h,   "ucvtf_asimdmiscfp16_r"_h}},
      {"'Vd.'?30:84h, 'Vn.'?30:84h, #0.0",
       {"fcmeq_asimdmiscfp16_fz"_h,
        "fcmge_asimdmiscfp16_fz"_h,
        "fcmgt_asimdmiscfp16_fz"_h,
        "fcmle_asimdmiscfp16_fz"_h,
        "fcmlt_asimdmiscfp16_fz"_h}},
      {"'Vd.'?30:84h, 'Vn.'?30:84h, 'Ve.h['IVByElemIndex]",
       {"fmla_asimdelem_rh_h"_h,
        "fmls_asimdelem_rh_h"_h,
        "fmulx_asimdelem_rh_h"_h,
        "fmul_asimdelem_rh_h"_h}},
      {"'Vd.'?30:84h, 'Vn.'?30:84h, 'Vm.'?30:84h",
       {"fabd_asimdsamefp16_only"_h,    "facge_asimdsamefp16_only"_h,
        "facgt_asimdsamefp16_only"_h,   "faddp_asimdsamefp16_only"_h,
        "fadd_asimdsamefp16_only"_h,    "fcmeq_asimdsamefp16_only"_h,
        "fcmge_asimdsamefp16_only"_h,   "fcmgt_asimdsamefp16_only"_h,
        "fdiv_asimdsamefp16_only"_h,    "fmaxnmp_asimdsamefp16_only"_h,
        "fmaxnm_asimdsamefp16_only"_h,  "fmaxp_asimdsamefp16_only"_h,
        "fmax_asimdsamefp16_only"_h,    "fminnmp_asimdsamefp16_only"_h,
        "fminnm_asimdsamefp16_only"_h,  "fminp_asimdsamefp16_only"_h,
        "fmin_asimdsamefp16_only"_h,    "fmla_asimdsamefp16_only"_h,
        "fmls_asimdsamefp16_only"_h,    "fmulx_asimdsamefp16_only"_h,
        "fmul_asimdsamefp16_only"_h,    "frecps_asimdsamefp16_only"_h,
        "frsqrts_asimdsamefp16_only"_h, "fsub_asimdsamefp16_only"_h}},
      {"'Vd.'?30:84h, 'Vn.'?30:84h, 'Vm.h['IVByElemIndexRot], #'u1413*90",
       {"fcmla_asimdelem_c_h"_h}},
      {"'Vd.'{n}, 'Vn.'{n}",
       {"abs_asimdmisc_r"_h,    "cls_asimdmisc_r"_h,    "clz_asimdmisc_r"_h,
        "neg_asimdmisc_r"_h,    "not_asimdmisc_r"_h,    "rev32_asimdmisc_r"_h,
        "rev64_asimdmisc_r"_h,  "sqabs_asimdmisc_r"_h,  "sqneg_asimdmisc_r"_h,
        "suqadd_asimdmisc_r"_h, "usqadd_asimdmisc_r"_h, "abs_asimdmisc_r"_h,
        "cls_asimdmisc_r"_h,    "clz_asimdmisc_r"_h,    "cnt_asimdmisc_r"_h,
        "neg_asimdmisc_r"_h,    "rev16_asimdmisc_r"_h,  "rev32_asimdmisc_r"_h,
        "rev64_asimdmisc_r"_h,  "sqabs_asimdmisc_r"_h,  "sqneg_asimdmisc_r"_h,
        "suqadd_asimdmisc_r"_h, "urecpe_asimdmisc_r"_h, "ursqrte_asimdmisc_r"_h,
        "usqadd_asimdmisc_r"_h}},
      {"'Vd.'{n}, 'Vn.'{n}, #0",
       {"cmeq_asimdmisc_z"_h,
        "cmge_asimdmisc_z"_h,
        "cmgt_asimdmisc_z"_h,
        "cmle_asimdmisc_z"_h,
        "cmlt_asimdmisc_z"_h}},
      {"'Vd.'{n}, 'Vn.'{n}, 'Vf.'{nscal}['IVByElemIndex]",
       {"mla_asimdelem_r"_h,
        "mls_asimdelem_r"_h,
        "mul_asimdelem_r"_h,
        "sqdmulh_asimdelem_r"_h,
        "sqrdmlah_asimdelem_r"_h,
        "sqrdmlsh_asimdelem_r"_h,
        "sqrdmulh_asimdelem_r"_h}},
      {"'Vd.'{n}, 'Vn.'{n}, 'Vm.'{n}",
       {"mla_asimdsame_only"_h,       "mls_asimdsame_only"_h,
        "mul_asimdsame_only"_h,       "saba_asimdsame_only"_h,
        "sabd_asimdsame_only"_h,      "shadd_asimdsame_only"_h,
        "shsub_asimdsame_only"_h,     "smaxp_asimdsame_only"_h,
        "smax_asimdsame_only"_h,      "sminp_asimdsame_only"_h,
        "smin_asimdsame_only"_h,      "srhadd_asimdsame_only"_h,
        "uaba_asimdsame_only"_h,      "uabd_asimdsame_only"_h,
        "uhadd_asimdsame_only"_h,     "uhsub_asimdsame_only"_h,
        "umaxp_asimdsame_only"_h,     "umax_asimdsame_only"_h,
        "uminp_asimdsame_only"_h,     "umin_asimdsame_only"_h,
        "urhadd_asimdsame_only"_h,    "addp_asimdsame_only"_h,
        "add_asimdsame_only"_h,       "cmeq_asimdsame_only"_h,
        "cmge_asimdsame_only"_h,      "cmgt_asimdsame_only"_h,
        "cmhi_asimdsame_only"_h,      "cmhs_asimdsame_only"_h,
        "cmtst_asimdsame_only"_h,     "sqadd_asimdsame_only"_h,
        "sqdmulh_asimdsame_only"_h,   "sqrdmulh_asimdsame_only"_h,
        "sqrshl_asimdsame_only"_h,    "sqshl_asimdsame_only"_h,
        "sqsub_asimdsame_only"_h,     "srshl_asimdsame_only"_h,
        "sshl_asimdsame_only"_h,      "sub_asimdsame_only"_h,
        "uqadd_asimdsame_only"_h,     "uqrshl_asimdsame_only"_h,
        "uqshl_asimdsame_only"_h,     "uqsub_asimdsame_only"_h,
        "urshl_asimdsame_only"_h,     "ushl_asimdsame_only"_h,
        "trn1_asimdperm_only"_h,      "trn2_asimdperm_only"_h,
        "uzp1_asimdperm_only"_h,      "uzp2_asimdperm_only"_h,
        "zip1_asimdperm_only"_h,      "zip2_asimdperm_only"_h,
        "sqrdmlah_asimdsame2_only"_h, "sqrdmlsh_asimdsame2_only"_h}},
      {"'Vd.'{n}, 'Vn.'{n}, 'Vm.'{n}, #'u1211*90", {"fcmla_asimdsame2_c"_h}},
      {"'Vd.'{n}, 'Vn.'{n}, 'Vm.'{n}, #'(12?270:90)", {"fcadd_asimdsame2_c"_h}},
      {"'Vd.'{n}, 'Vn.'{nl}",
       {"xtn_asimdmisc_n"_h,
        "sqxtn_asimdmisc_n"_h,
        "uqxtn_asimdmisc_n"_h,
        "sqxtun_asimdmisc_n"_h,
        "xtn2_xtn_asimdmisc_n"_h,
        "sqxtn2_sqxtn_asimdmisc_n"_h,
        "uqxtn2_uqxtn_asimdmisc_n"_h,
        "sqxtun2_sqxtun_asimdmisc_n"_h}},
      {"'Vd.'{n}, 'Vn.'{nl}, 'Vm.'{nl}",
       {"addhn_asimddiff_n"_h,
        "raddhn_asimddiff_n"_h,
        "rsubhn_asimddiff_n"_h,
        "subhn_asimddiff_n"_h,
        "addhn2_addhn_asimddiff_n"_h,
        "raddhn2_raddhn_asimddiff_n"_h,
        "rsubhn2_rsubhn_asimddiff_n"_h,
        "subhn2_subhn_asimddiff_n"_h}},
      {"'Vd.'{nl}, 'Vn.'{n}, #'(2322?'u2322*16:8)",
       {"shll_asimdmisc_s"_h, "shll2_shll_asimdmisc_s"_h}},
      {"'Vd.'{nl}, 'Vn.'{n}, 'Vm.'{n}",
       {"sabal_asimddiff_l"_h,
        "sabdl_asimddiff_l"_h,
        "saddl_asimddiff_l"_h,
        "smlal_asimddiff_l"_h,
        "smlsl_asimddiff_l"_h,
        "smull_asimddiff_l"_h,
        "ssubl_asimddiff_l"_h,
        "uabal_asimddiff_l"_h,
        "uabdl_asimddiff_l"_h,
        "uaddl_asimddiff_l"_h,
        "umlal_asimddiff_l"_h,
        "umlsl_asimddiff_l"_h,
        "umull_asimddiff_l"_h,
        "usubl_asimddiff_l"_h,
        "sabal2_sabal_asimddiff_l"_h,
        "sabdl2_sabdl_asimddiff_l"_h,
        "saddl2_saddl_asimddiff_l"_h,
        "smlal2_smlal_asimddiff_l"_h,
        "smlsl2_smlsl_asimddiff_l"_h,
        "smull2_smull_asimddiff_l"_h,
        "ssubl2_ssubl_asimddiff_l"_h,
        "uabal2_uabal_asimddiff_l"_h,
        "uabdl2_uabdl_asimddiff_l"_h,
        "uaddl2_uaddl_asimddiff_l"_h,
        "umlal2_umlal_asimddiff_l"_h,
        "umlsl2_umlsl_asimddiff_l"_h,
        "umull2_umull_asimddiff_l"_h,
        "usubl2_usubl_asimddiff_l"_h,
        "sqdmlal_asimddiff_l"_h,
        "sqdmlsl_asimddiff_l"_h,
        "sqdmull_asimddiff_l"_h,
        "sqdmlal2_sqdmlal_asimddiff_l"_h,
        "sqdmlsl2_sqdmlsl_asimddiff_l"_h,
        "sqdmull2_sqdmull_asimddiff_l"_h}},
      {"'Vd.'{nl}, 'Vn.'{nl}, 'Vm.'{n}",
       {"saddw_asimddiff_w"_h,
        "ssubw_asimddiff_w"_h,
        "uaddw_asimddiff_w"_h,
        "usubw_asimddiff_w"_h,
        "saddw2_saddw_asimddiff_w"_h,
        "ssubw2_ssubw_asimddiff_w"_h,
        "uaddw2_uaddw_asimddiff_w"_h,
        "usubw2_usubw_asimddiff_w"_h}},
      {"'Vd.16b, 'Vn.16b",
       {"aesd_b_cryptoaes"_h,
        "aese_b_cryptoaes"_h,
        "aesimc_b_cryptoaes"_h,
        "aesmc_b_cryptoaes"_h}},
      {"'Vd.16b, 'Vn.16b, 'Vm.16b, 'Va.16b",
       {"bcax_vvv16_crypto4"_h, "eor3_vvv16_crypto4"_h}},
      {"'Vd.2d, 'Vn.2d", {"sha512su0_vv2_cryptosha512_2"_h}},
      {"'Vd.2d, 'Vn.2d, 'Vm.2d",
       {"rax1_vvv2_cryptosha512_3"_h, "sha512su1_vvv2_cryptosha512_3"_h}},
      {"'Vd.2d, 'Vn.2d, 'Vm.2d, #'u1510", {"xar_vvv2_crypto3_imm6"_h}},
      {"'Vd.4s, 'Vn.16b, 'Vm.16b",
       {"smmla_asimdsame2_g"_h,
        "ummla_asimdsame2_g"_h,
        "usmmla_asimdsame2_g"_h}},
      {"'Vd.4s, 'Vn.4s",
       {"sha1su1_vv_cryptosha2"_h,
        "sha256su0_vv_cryptosha2"_h,
        "sm4e_vv4_cryptosha512_2"_h}},
      {"'Vd.4s, 'Vn.4s, 'Vm.4s",
       {"sha1su0_vvv_cryptosha3"_h,
        "sha256su1_vvv_cryptosha3"_h,
        "sm3partw1_vvv4_cryptosha512_3"_h,
        "sm3partw2_vvv4_cryptosha512_3"_h,
        "sm4ekey_vvv4_cryptosha512_3"_h}},
      {"'Vd.4s, 'Vn.4s, 'Vm.4s, 'Va.4s", {"sm3ss1_vvv4_crypto4"_h}},
      {"'Vd.4s, 'Vn.4s, 'Vm.s['u1312]",
       {"sm3tt1a_vvv4_crypto3_imm2"_h,
        "sm3tt1b_vvv4_crypto3_imm2"_h,
        "sm3tt2a_vvv4_crypto3_imm2"_h,
        "sm3tt2b_vvv_crypto3_imm2"_h}},
      {"'Vd.4s, 'Vn.4s, 'Vm.s['IVByElemIndexRot], #'u1413*90",
       {"fcmla_asimdelem_c_s"_h}},
      {"'Vd.D[1], 'Rn", {"fmov_v64i_float2int"_h}},
      {"'Vdv, 'Pgl, 'Zn.'t",
       {"andv_r_p_z"_h,
        "eorv_r_p_z"_h,
        "orv_r_p_z"_h,
        "smaxv_r_p_z"_h,
        "sminv_r_p_z"_h,
        "umaxv_r_p_z"_h,
        "uminv_r_p_z"_h}},
      {"'Vt.'(30?16:8)b, #0x'x1816_0905", {"movi_asimdimm_n_b"_h}},
      {"'Vt.'?30:42s, #0x'x1816_0905'(1413?, lsl #'u1413*8)",
       {"bic_asimdimm_l_sl"_h,
        "movi_asimdimm_l_sl"_h,
        "mvni_asimdimm_l_sl"_h,
        "orr_asimdimm_l_sl"_h}},
      {"'Vt.'?30:42s, #0x'x1816_0905, msl #'(12?16:8)",
       {"movi_asimdimm_m_sm"_h, "mvni_asimdimm_m_sm"_h}},
      {"'Vt.'?30:42s, 'IFPNeon", {"fmov_asimdimm_s_s"_h}},
      {"'Vt.'?30:84h, #0x'x1816_0905'(1413?, lsl #'u1413*8)",
       {"bic_asimdimm_l_hl"_h,
        "movi_asimdimm_l_hl"_h,
        "mvni_asimdimm_l_hl"_h,
        "orr_asimdimm_l_hl"_h}},
      {"'Vt.'?30:84h, 'IFPNeon", {"fmov_asimdimm_h_h"_h}},
      {"'Vt.2d, 'IFPNeon", {"fmov_asimdimm_d2_d"_h}},
      {"'Vt.2d, 'IVMIImm", {"movi_asimdimm_d2_d"_h}},
      {"'Wd, 'Pn.'t", {"uqdecp_r_p_r_uw"_h, "uqincp_r_p_r_uw"_h}},
      {"'Wd, 'Wn, 'Xm", {"crc32cx_64c_dp_2src"_h, "crc32x_64c_dp_2src"_h}},
      {"'Wn", {"setf16_only_setf"_h, "setf8_only_setf"_h}},
      {"'Wt, 'ILLiteral 'LValue", {"ldr_32_loadlit"_h}},
      {"'Wt, 'Wt2, ['Xns'(2115?, #'s2115*4)]",
       {"ldnp_32_ldstnapair_offs"_h,
        "ldp_32_ldstpair_off"_h,
        "stnp_32_ldstnapair_offs"_h,
        "stp_32_ldstpair_off"_h}},
      {"'Wt, 'Wt2, ['Xns, #'s2115*4]!",
       {"ldp_32_ldstpair_pre"_h, "stp_32_ldstpair_pre"_h}},
      {"'Wt, 'Wt2, ['Xns], #'s2115*4",
       {"ldp_32_ldstpair_post"_h, "stp_32_ldstpair_post"_h}},
      {"'Wt, ['Xns'(2012?, #'s2012)]",
       {"ldapur_32_ldapstl_unscaled"_h,
        "ldapurb_32_ldapstl_unscaled"_h,
        "ldapurh_32_ldapstl_unscaled"_h,
        "ldapursb_32_ldapstl_unscaled"_h,
        "ldapursh_32_ldapstl_unscaled"_h,
        "ldur_32_ldst_unscaled"_h,
        "ldurb_32_ldst_unscaled"_h,
        "ldurh_32_ldst_unscaled"_h,
        "ldursb_32_ldst_unscaled"_h,
        "ldursh_32_ldst_unscaled"_h,
        "stlur_32_ldapstl_unscaled"_h,
        "stlurb_32_ldapstl_unscaled"_h,
        "stlurh_32_ldapstl_unscaled"_h,
        "stur_32_ldst_unscaled"_h,
        "sturb_32_ldst_unscaled"_h,
        "sturh_32_ldst_unscaled"_h}},
      {"'Wt, ['Xns'ILU]",
       {"ldr_32_ldst_pos"_h,
        "ldrb_32_ldst_pos"_h,
        "ldrh_32_ldst_pos"_h,
        "ldrsb_32_ldst_pos"_h,
        "ldrsh_32_ldst_pos"_h,
        "str_32_ldst_pos"_h,
        "strb_32_ldst_pos"_h,
        "strh_32_ldst_pos"_h}},
      {"'Wt, ['Xns, #'s2012]!",
       {"ldr_32_ldst_immpre"_h,
        "ldrb_32_ldst_immpre"_h,
        "ldrh_32_ldst_immpre"_h,
        "ldrsb_32_ldst_immpre"_h,
        "ldrsh_32_ldst_immpre"_h,
        "str_32_ldst_immpre"_h,
        "strb_32_ldst_immpre"_h,
        "strh_32_ldst_immpre"_h}},
      {"'Wt, ['Xns, 'Offsetreg]",
       {"ldr_32_ldst_regoff"_h,
        "ldrb_32b_ldst_regoff"_h,
        "ldrb_32bl_ldst_regoff"_h,
        "ldrh_32_ldst_regoff"_h,
        "ldrsb_32b_ldst_regoff"_h,
        "ldrsb_32bl_ldst_regoff"_h,
        "ldrsh_32_ldst_regoff"_h,
        "str_32_ldst_regoff"_h,
        "strb_32b_ldst_regoff"_h,
        "strb_32bl_ldst_regoff"_h,
        "strh_32_ldst_regoff"_h}},
      {"'Wt, ['Xns], #'s2012",
       {"ldr_32_ldst_immpost"_h,
        "ldrb_32_ldst_immpost"_h,
        "ldrh_32_ldst_immpost"_h,
        "ldrsb_32_ldst_immpost"_h,
        "ldrsh_32_ldst_immpost"_h,
        "str_32_ldst_immpost"_h,
        "strb_32_ldst_immpost"_h,
        "strh_32_ldst_immpost"_h}},
      {"'Xd",
       {"autdza_64z_dp_1src"_h,
        "autdzb_64z_dp_1src"_h,
        "autiza_64z_dp_1src"_h,
        "autizb_64z_dp_1src"_h,
        "pacdza_64z_dp_1src"_h,
        "pacdzb_64z_dp_1src"_h,
        "paciza_64z_dp_1src"_h,
        "pacizb_64z_dp_1src"_h,
        "xpacd_64z_dp_1src"_h,
        "xpaci_64z_dp_1src"_h}},
      {"'Xd'(1916?, 'Ipc, mul #'u1916+1'$)'(0905=31?:, 'Ipc)",
       {"decb_r_rs"_h,
        "decd_r_rs"_h,
        "dech_r_rs"_h,
        "decw_r_rs"_h,
        "incb_r_rs"_h,
        "incd_r_rs"_h,
        "inch_r_rs"_h,
        "incw_r_rs"_h,
        "cntb_r_s"_h,
        "cntd_r_s"_h,
        "cnth_r_s"_h,
        "cntw_r_s"_h}},
      {"'Xd, #'s1005", {"rdvl_r_i"_h}},
      {"'Xd, 'AddrPCRelByte", {"adr_only_pcreladdr"_h}},
      {"'Xd, 'AddrPCRelPage", {"adrp_only_pcreladdr"_h}},
      {"'Xd, 'Pn.'t",
       {"decp_r_p_r"_h,
        "incp_r_p_r"_h,
        "sqdecp_r_p_r_x"_h,
        "sqincp_r_p_r_x"_h,
        "uqdecp_r_p_r_x"_h,
        "uqincp_r_p_r_x"_h}},
      {"'Xd, 'Pn.'t, 'Wd", {"sqdecp_r_p_r_sx"_h, "sqincp_r_p_r_sx"_h}},
      {"'Xd, 'Vn.'{ntriscal}['IVInsIndex1]",
       {"mov_umov_asimdins_x_x"_h, "smov_asimdins_x_x"_h}},
      {"'Wd, 'Vn.'{ntriscal}['IVInsIndex1]",
       {"mov_umov_asimdins_w_w"_h,
        "umov_asimdins_w_w"_h,
        "smov_asimdins_w_w"_h}},
      {"'Xd, 'Wd'(1916?, 'Ipc, mul #'u1916+1'$)'(0905=31?:, 'Ipc)",
       {"sqdecb_r_rs_sx"_h,
        "sqdecd_r_rs_sx"_h,
        "sqdech_r_rs_sx"_h,
        "sqdecw_r_rs_sx"_h,
        "sqincb_r_rs_sx"_h,
        "sqincd_r_rs_sx"_h,
        "sqinch_r_rs_sx"_h,
        "sqincw_r_rs_sx"_h}},
      {"'Xd, 'Wn, 'Wm",
       {"smull_smaddl_64wa_dp_3src"_h,
        "smnegl_smsubl_64wa_dp_3src"_h,
        "umull_umaddl_64wa_dp_3src"_h,
        "umnegl_umsubl_64wa_dp_3src"_h}},
      {"'Xd, 'Wn, 'Wm, 'Xa",
       {"smaddl_64wa_dp_3src"_h,
        "smsubl_64wa_dp_3src"_h,
        "umaddl_64wa_dp_3src"_h,
        "umsubl_64wa_dp_3src"_h}},
      {"'Xd, 'Xn, 'Xm", {"smulh_64_dp_3src"_h, "umulh_64_dp_3src"_h}},
      {"'Xd, 'Xn, 'Xms", {"pacga_64p_dp_2src"_h}},
      {"'Xd, 'Xns",
       {"autda_64p_dp_1src"_h,
        "autdb_64p_dp_1src"_h,
        "autia_64p_dp_1src"_h,
        "autib_64p_dp_1src"_h,
        "pacda_64p_dp_1src"_h,
        "pacdb_64p_dp_1src"_h,
        "pacia_64p_dp_1src"_h,
        "pacib_64p_dp_1src"_h}},
      {"'Xd, 'Xns, 'Xms", {"subp_64s_dp_2src"_h, "subps_64s_dp_2src"_h}},
      {"'Xd, p'u1310, 'Pn.'t", {"cntp_r_p_p"_h}},
      {"'Xds, 'Xms, #'s1005", {"addpl_r_ri"_h, "addvl_r_ri"_h}},
      {"'Xds, 'Xns'(2016=31?:, 'Xm)", {"irg_64i_dp_2src"_h}},
      {"'Xds, 'Xns, #'u2116*16, #'u1310",
       {"addg_64_addsub_immtags"_h, "subg_64_addsub_immtags"_h}},
      {"'Xds, ['Xns'(2012?, #'s2012*16)]",
       {"st2g_64soffset_ldsttags"_h,
        "stg_64soffset_ldsttags"_h,
        "stz2g_64soffset_ldsttags"_h,
        "stzg_64soffset_ldsttags"_h}},
      {"'Xds, ['Xns, #'s2012*16]!",
       {"st2g_64spre_ldsttags"_h,
        "stg_64spre_ldsttags"_h,
        "stz2g_64spre_ldsttags"_h,
        "stzg_64spre_ldsttags"_h}},
      {"'Xds, ['Xns], #'s2012*16",
       {"st2g_64spost_ldsttags"_h,
        "stg_64spost_ldsttags"_h,
        "stz2g_64spost_ldsttags"_h,
        "stzg_64spost_ldsttags"_h}},
      {"'Xn",
       {"blr_64_branch_reg"_h,
        "blraaz_64_branch_reg"_h,
        "blrabz_64_branch_reg"_h,
        "br_64_branch_reg"_h,
        "braaz_64_branch_reg"_h,
        "brabz_64_branch_reg"_h,
        "drps_64e_branch_reg"_h,
        "eret_64e_branch_reg"_h,
        "eretaa_64e_branch_reg"_h,
        "eretab_64e_branch_reg"_h}},
      {"'Xn, #'u2015, 'INzcv", {"rmif_only_rmif"_h}},
      {"'Xn, 'Xds",
       {"blraa_64p_branch_reg"_h,
        "blrab_64p_branch_reg"_h,
        "braa_64p_branch_reg"_h,
        "brab_64p_branch_reg"_h}},
      {"'Xns, 'Xms", {"cmpp_subps_64s_dp_2src"_h}},
      {"'Xt, 'ILLiteral 'LValue", {"ldr_64_loadlit"_h, "ldrsw_64_loadlit"_h}},
      {"'Xt, 'IY", {"mrs_rs_systemmove"_h}},
      {"'Xt, 'Xt2, ['Xns'(2115?, #'s2115*16)]", {"stgp_64_ldstpair_off"_h}},
      {"'Xt, 'Xt2, ['Xns'(2115?, #'s2115*4)]", {"ldpsw_64_ldstpair_off"_h}},
      {"'Xt, 'Xt2, ['Xns'(2115?, #'s2115*8)]",
       {"ldnp_64_ldstnapair_offs"_h,
        "ldp_64_ldstpair_off"_h,
        "stnp_64_ldstnapair_offs"_h,
        "stp_64_ldstpair_off"_h}},
      {"'Xt, 'Xt2, ['Xns, #'s2115*16]!", {"stgp_64_ldstpair_pre"_h}},
      {"'Xt, 'Xt2, ['Xns, #'s2115*4]!", {"ldpsw_64_ldstpair_pre"_h}},
      {"'Xt, 'Xt2, ['Xns, #'s2115*8]!",
       {"ldp_64_ldstpair_pre"_h, "stp_64_ldstpair_pre"_h}},
      {"'Xt, 'Xt2, ['Xns], #'s2115*16", {"stgp_64_ldstpair_post"_h}},
      {"'Xt, 'Xt2, ['Xns], #'s2115*4", {"ldpsw_64_ldstpair_post"_h}},
      {"'Xt, 'Xt2, ['Xns], #'s2115*8",
       {"ldp_64_ldstpair_post"_h, "stp_64_ldstpair_post"_h}},
      {"'Xt, ['Xns'(2012?, #'s2012)]",
       {"ldapur_64_ldapstl_unscaled"_h,
        "ldapursb_64_ldapstl_unscaled"_h,
        "ldapursh_64_ldapstl_unscaled"_h,
        "ldapursw_64_ldapstl_unscaled"_h,
        "ldur_64_ldst_unscaled"_h,
        "ldursb_64_ldst_unscaled"_h,
        "ldursh_64_ldst_unscaled"_h,
        "ldursw_64_ldst_unscaled"_h,
        "stlur_64_ldapstl_unscaled"_h,
        "stur_64_ldst_unscaled"_h}},
      {"'Xt, ['Xns'(2012?, #'s2012*16)]", {"ldg_64loffset_ldsttags"_h}},
      {"'Xt, ['Xns'ILA]!", {"ldraa_64w_ldst_pac"_h, "ldrab_64w_ldst_pac"_h}},
      {"'Xt, ['Xns'ILA]", {"ldraa_64_ldst_pac"_h, "ldrab_64_ldst_pac"_h}},
      {"'Xt, ['Xns'ILU]",
       {"ldr_64_ldst_pos"_h,
        "ldrsb_64_ldst_pos"_h,
        "ldrsh_64_ldst_pos"_h,
        "ldrsw_64_ldst_pos"_h,
        "str_64_ldst_pos"_h}},
      {"'Xt, ['Xns, #'s2012]!",
       {"ldr_64_ldst_immpre"_h,
        "ldrsb_64_ldst_immpre"_h,
        "ldrsh_64_ldst_immpre"_h,
        "ldrsw_64_ldst_immpre"_h,
        "str_64_ldst_immpre"_h}},
      {"'Xt, ['Xns, 'Offsetreg]",
       {"ldr_64_ldst_regoff"_h,
        "ldrsb_64b_ldst_regoff"_h,
        "ldrsb_64bl_ldst_regoff"_h,
        "ldrsh_64_ldst_regoff"_h,
        "ldrsw_64_ldst_regoff"_h,
        "str_64_ldst_regoff"_h}},
      {"'Xt, ['Xns], #'s2012",
       {"ldr_64_ldst_immpost"_h,
        "ldrsb_64_ldst_immpost"_h,
        "ldrsh_64_ldst_immpost"_h,
        "ldrsw_64_ldst_immpost"_h,
        "str_64_ldst_immpost"_h}},
      {"'Zd, 'Zn", {"movprfx_z_z"_h}},
      {"'Zd.'?22:ds, 'Zn.'?22:ds, 'Zm.'?22:ds",
       {"adclb_z_zzz"_h, "adclt_z_zzz"_h, "sbclb_z_zzz"_h, "sbclt_z_zzz"_h}},
      {"'Zd.'t'(1916?, 'Ipc, mul #'u1916+1'$)'(0905=31?:, 'Ipc)",
       {"decd_z_zs"_h,
        "dech_z_zs"_h,
        "decw_z_zs"_h,
        "incd_z_zs"_h,
        "inch_z_zs"_h,
        "incw_z_zs"_h,
        "sqdecd_z_zs"_h,
        "sqdech_z_zs"_h,
        "sqdecw_z_zs"_h,
        "sqincd_z_zs"_h,
        "sqinch_z_zs"_h,
        "sqincw_z_zs"_h,
        "uqdecd_z_zs"_h,
        "uqdech_z_zs"_h,
        "uqdecw_z_zs"_h,
        "uqincd_z_zs"_h,
        "uqinch_z_zs"_h,
        "uqincw_z_zs"_h}},
      {"'Zd.'t, #'s0905, #'s2016", {"index_z_ii"_h}},
      {"'Zd.'t, #'s0905, '(2322=3?'Xm:'Wm)", {"index_z_ir"_h}},
      {"'Zd.'t, #'s1205'(13?, lsl #8)", {"mov_dup_z_i"_h}},
      {"'Zd.'t, '(2322=3?'Xn:'Wn)", {"insr_z_r"_h}},
      {"'Zd.'t, '(2322=3?'Xn:'Wn), #'s2016", {"index_z_ri"_h}},
      {"'Zd.'t, '(2322=3?'Xn:'Wn), '(2322=3?'Xm:'Wm)", {"index_z_rr"_h}},
      {"'Zd.'t, '(2322=3?'Xns:'Wns)", {"mov_dup_z_r"_h}},
      {"'Zd.'t, 'IFPSve", {"fmov_fdup_z_i"_h}},
      {"'Zd.'t, 'Pgl, 'Zd.'t, 'Zn.'t",
       {"clasta_z_p_zz"_h, "clastb_z_p_zz"_h, "splice_z_p_zz_des"_h}},
      {"'Zd.'t, 'Pgl, 'Zn.'t", {"compact_z_p_z"_h}},
      {"'Zd.'t, 'Pgl, {'Zn.'t, 'Zn2.'t}", {"splice_z_p_zz_con"_h}},
      {"'Zd.'t, 'Pgl/'?16:mz, 'Zn.'t", {"movprfx_z_p_z"_h}},
      {"'Zd.'t, 'Pgl/m, '(2322=3?'Xns:'Wns)", {"mov_cpy_z_p_r"_h}},
      {"'Zd.'t, 'Pgl/m, 'Vnv", {"mov_cpy_z_p_v"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zd.'t, #'(05?1:0).0",
       {"fmaxnm_z_p_zs"_h,
        "fmax_z_p_zs"_h,
        "fminnm_z_p_zs"_h,
        "fmin_z_p_zs"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zd.'t, #'(05?1.0:0.5)",
       {"fadd_z_p_zs"_h, "fsubr_z_p_zs"_h, "fsub_z_p_zs"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zd.'t, #'(05?2.0:0.5)", {"fmul_z_p_zs"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zd.'t, 'Zn.'t",
       {"addp_z_p_zz"_h,    "shadd_z_p_zz"_h,   "shsub_z_p_zz"_h,
        "shsubr_z_p_zz"_h,  "smaxp_z_p_zz"_h,   "sminp_z_p_zz"_h,
        "sqadd_z_p_zz"_h,   "sqrshl_z_p_zz"_h,  "sqrshlr_z_p_zz"_h,
        "sqshl_z_p_zz"_h,   "sqshlr_z_p_zz"_h,  "sqsub_z_p_zz"_h,
        "sqsubr_z_p_zz"_h,  "srhadd_z_p_zz"_h,  "srshl_z_p_zz"_h,
        "srshlr_z_p_zz"_h,  "suqadd_z_p_zz"_h,  "uhadd_z_p_zz"_h,
        "uhsub_z_p_zz"_h,   "uhsubr_z_p_zz"_h,  "umaxp_z_p_zz"_h,
        "uminp_z_p_zz"_h,   "uqadd_z_p_zz"_h,   "uqrshl_z_p_zz"_h,
        "uqrshlr_z_p_zz"_h, "uqshl_z_p_zz"_h,   "uqshlr_z_p_zz"_h,
        "uqsub_z_p_zz"_h,   "uqsubr_z_p_zz"_h,  "urhadd_z_p_zz"_h,
        "urshl_z_p_zz"_h,   "urshlr_z_p_zz"_h,  "usqadd_z_p_zz"_h,
        "mul_z_p_zz"_h,     "smulh_z_p_zz"_h,   "umulh_z_p_zz"_h,
        "sabd_z_p_zz"_h,    "smax_z_p_zz"_h,    "smin_z_p_zz"_h,
        "uabd_z_p_zz"_h,    "umax_z_p_zz"_h,    "umin_z_p_zz"_h,
        "add_z_p_zz"_h,     "subr_z_p_zz"_h,    "sub_z_p_zz"_h,
        "and_z_p_zz"_h,     "bic_z_p_zz"_h,     "eor_z_p_zz"_h,
        "orr_z_p_zz"_h,     "asrr_z_p_zz"_h,    "asr_z_p_zz"_h,
        "lslr_z_p_zz"_h,    "lsl_z_p_zz"_h,     "lsrr_z_p_zz"_h,
        "lsr_z_p_zz"_h,     "faddp_z_p_zz"_h,   "fmaxnmp_z_p_zz"_h,
        "fmaxp_z_p_zz"_h,   "fminnmp_z_p_zz"_h, "fminp_z_p_zz"_h,
        "fabd_z_p_zz"_h,    "fadd_z_p_zz"_h,    "fdivr_z_p_zz"_h,
        "fdiv_z_p_zz"_h,    "fmaxnm_z_p_zz"_h,  "fmax_z_p_zz"_h,
        "fminnm_z_p_zz"_h,  "fmin_z_p_zz"_h,    "fmulx_z_p_zz"_h,
        "fmul_z_p_zz"_h,    "fscale_z_p_zz"_h,  "fsubr_z_p_zz"_h,
        "fsub_z_p_zz"_h,    "sdiv_z_p_zz"_h,    "sdivr_z_p_zz"_h,
        "udiv_z_p_zz"_h,    "udivr_z_p_zz"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zd.'t, 'Zn.'t, #'u1615*90", {"fcadd_z_p_zz"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zm.'t, 'Zn.'t", {"mad_z_p_zzz"_h, "msb_z_p_zzz"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zn.'t",
       {"sqabs_z_p_z"_h,  "sqneg_z_p_z"_h,  "frinta_z_p_z"_h, "frinti_z_p_z"_h,
        "frintm_z_p_z"_h, "frintn_z_p_z"_h, "frintp_z_p_z"_h, "frintx_z_p_z"_h,
        "frintz_z_p_z"_h, "frecpx_z_p_z"_h, "fsqrt_z_p_z"_h,  "abs_z_p_z"_h,
        "cls_z_p_z"_h,    "clz_z_p_z"_h,    "cnot_z_p_z"_h,   "cnt_z_p_z"_h,
        "fabs_z_p_z"_h,   "fneg_z_p_z"_h,   "neg_z_p_z"_h,    "not_z_p_z"_h,
        "sxtb_z_p_z"_h,   "sxth_z_p_z"_h,   "sxtw_z_p_z"_h,   "uxtb_z_p_z"_h,
        "uxth_z_p_z"_h,   "uxtw_z_p_z"_h,   "rbit_z_p_z"_h,   "revb_z_z"_h,
        "revh_z_z"_h,     "revw_z_z"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zn.'t, 'Zm.'t",
       {"mla_z_p_zzz"_h,
        "mls_z_p_zzz"_h,
        "fmad_z_p_zzz"_h,
        "fmla_z_p_zzz"_h,
        "fmls_z_p_zzz"_h,
        "fmsb_z_p_zzz"_h,
        "fnmad_z_p_zzz"_h,
        "fnmla_z_p_zzz"_h,
        "fnmls_z_p_zzz"_h,
        "fnmsb_z_p_zzz"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zn.'t, 'Zm.'t, #'u1413*90", {"fcmla_z_p_zzz"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zn.'th", {"sadalp_z_p_z"_h, "uadalp_z_p_z"_h}},
      {"'Zd.'t, 'Pgl/z, 'Zn.'t, 'Zm.'t", {"histcnt_z_p_zz"_h}},
      {"'Zd.'t, 'Pm/'?14:mz, #'s1205'(13?, lsl #8)",
       {"mov_cpy_z_o_i"_h, "mov_cpy_z_p_i"_h}},
      {"'Zd.'t, 'Pm/m, 'IFPSve", {"fmov_fcpy_z_p_i"_h}},
      {"'Zd.'t, 'Pn",
       {"decp_z_p_z"_h,
        "incp_z_p_z"_h,
        "sqdecp_z_p_z"_h,
        "sqincp_z_p_z"_h,
        "uqdecp_z_p_z"_h,
        "uqincp_z_p_z"_h}},
      {"'Zd.'t, 'Vnv", {"insr_z_v"_h}},
      {"'Zd.'t, 'Zd.'t, #'s1205", {"mul_z_zi"_h, "smax_z_zi"_h, "smin_z_zi"_h}},
      {"'Zd.'t, 'Zd.'t, #'u1205", {"umax_z_zi"_h, "umin_z_zi"_h}},
      {"'Zd.'t, 'Zd.'t, #'u1205'(13?, lsl #8)",
       {"add_z_zi"_h,
        "sqadd_z_zi"_h,
        "sqsub_z_zi"_h,
        "sub_z_zi"_h,
        "subr_z_zi"_h,
        "uqadd_z_zi"_h,
        "uqsub_z_zi"_h}},
      {"'Zd.'t, 'Zd.'t, 'Zn.'t, #'(10?27:9)0",
       {"cadd_z_zz"_h, "sqcadd_z_zz"_h}},
      {"'Zd.'t, 'Zd.'t, 'Zn.'t, #'u1816", {"ftmad_z_zzi"_h}},
      {"'Zd.'t, 'Zn.'t",
       {"frecpe_z_z"_h, "frsqrte_z_z"_h, "rev_z_z"_h, "fexpa_z_z"_h}},
      {"'Zd.'t, 'Zn.'t, 'Zm.'t",
       {"bdep_z_zz"_h,      "bext_z_zz"_h,      "bgrp_z_zz"_h,
        "eorbt_z_zz"_h,     "eortb_z_zz"_h,     "mul_z_zz"_h,
        "smulh_z_zz"_h,     "sqdmulh_z_zz"_h,   "sqrdmulh_z_zz"_h,
        "tbx_z_zz"_h,       "umulh_z_zz"_h,     "saba_z_zzz"_h,
        "sqrdmlah_z_zzz"_h, "sqrdmlsh_z_zzz"_h, "uaba_z_zzz"_h,
        "fmmla_z_zzz_s"_h,  "fmmla_z_zzz_d"_h,  "trn1_z_zz"_h,
        "trn2_z_zz"_h,      "uzp1_z_zz"_h,      "uzp2_z_zz"_h,
        "zip1_z_zz"_h,      "zip2_z_zz"_h,      "add_z_zz"_h,
        "sqadd_z_zz"_h,     "sqsub_z_zz"_h,     "sub_z_zz"_h,
        "uqadd_z_zz"_h,     "uqsub_z_zz"_h,     "fadd_z_zz"_h,
        "fmul_z_zz"_h,      "frecps_z_zz"_h,    "frsqrts_z_zz"_h,
        "fsub_z_zz"_h,      "ftsmul_z_zz"_h,    "ftssel_z_zz"_h}},
      {"'Zd.'t, 'Zn.'t, 'Zm.'t, #'u1110*90",
       {"cmla_z_zzz"_h, "sqrdcmlah_z_zzz"_h}},
      {"'Zd.'t, 'Zn.'t, 'Zm.d", {"asr_z_zw"_h, "lsl_z_zw"_h, "lsr_z_zw"_h}},
      {"'Zd.'t, 'Zn.'tq, 'Zm.'tq", {"sdot_z_zzz"_h, "udot_z_zzz"_h}},
      {"'Zd.'t, 'Zn.'tq, 'Zm.'tq, #'u1110*90", {"cdot_z_zzz"_h}},
      {"'Zd.'t, ['Zn.'t, 'Zm.'t'(1110?, lsl #'u1110)]",
       {"adr_z_az_sd_same_scaled"_h}},
      {"'Zd.'t, {'Zn.'t, 'Zn2.'t}, 'Zm.'t", {"tbl_z_zz_2"_h}},
      {"'Zd.'t, {'Zn.'t}, 'Zm.'t", {"tbl_z_zz_1"_h}},
      {"'Zd.'t, p'u1310, 'Zn.'t, 'Zm.'t", {"sel_z_p_zz"_h}},
      {"'Zd.'t, p'u1310/m, 'Zn.'t", {"mov_sel_z_p_zz"_h}},
      {"'Zd.'tf, 'Pgl/m, 'Zn.'tf", {"flogb_z_p_z"_h}},
      {"'Zd.'th, 'Zn.'t, 'Zm.'t",
       {"addhnb_z_zz"_h,
        "addhnt_z_zz"_h,
        "raddhnb_z_zz"_h,
        "raddhnt_z_zz"_h,
        "rsubhnb_z_zz"_h,
        "rsubhnt_z_zz"_h,
        "subhnb_z_zz"_h,
        "subhnt_z_zz"_h}},
      {"'Zd.'tl, 'Zd.'tl, 'ITriSvel",
       {"and_z_zi"_h, "eor_z_zi"_h, "orr_z_zi"_h}},
      {"'Zd.'tszd, 'Zn.'tszs, 'ITriSver",
       {"sshllb_z_zi"_h, "sshllt_z_zi"_h, "ushllb_z_zi"_h, "ushllt_z_zi"_h}},
      {"'Zd.'tszp, 'Pgl/m, 'Zd.'tszp, 'ITriSvep",
       {"lsl_z_p_zi"_h, "sqshl_z_p_zi"_h, "sqshlu_z_p_zi"_h, "uqshl_z_p_zi"_h}},
      {"'Zd.'tszp, 'Pgl/m, 'Zd.'tszp, 'ITriSveq",
       {"asrd_z_p_zi"_h,
        "asr_z_p_zi"_h,
        "lsr_z_p_zi"_h,
        "srshr_z_p_zi"_h,
        "urshr_z_p_zi"_h}},
      {"'Zd.'tszs, 'Zn.'tszd",
       {"sqxtnb_z_zz"_h,
        "sqxtnt_z_zz"_h,
        "sqxtunb_z_zz"_h,
        "sqxtunt_z_zz"_h,
        "uqxtnb_z_zz"_h,
        "uqxtnt_z_zz"_h}},
      {"'Zd.'tszs, 'Zn.'tszd, 'ITriSves",
       {"rshrnb_z_zi"_h,
        "rshrnt_z_zi"_h,
        "shrnb_z_zi"_h,
        "shrnt_z_zi"_h,
        "sqrshrnb_z_zi"_h,
        "sqrshrnt_z_zi"_h,
        "sqrshrunb_z_zi"_h,
        "sqrshrunt_z_zi"_h,
        "sqshrnb_z_zi"_h,
        "sqshrnt_z_zi"_h,
        "sqshrunb_z_zi"_h,
        "sqshrunt_z_zi"_h,
        "uqrshrnb_z_zi"_h,
        "uqrshrnt_z_zi"_h,
        "uqshrnb_z_zi"_h,
        "uqshrnt_z_zi"_h}},
      {"'Zd.'tszs, 'Zn.'tszs, 'ITriSver", {"lsl_z_zi"_h, "sli_z_zzi"_h}},
      {"'Zd.'tszs, 'Zn.'tszs, 'ITriSves",
       {"asr_z_zi"_h,
        "lsr_z_zi"_h,
        "sri_z_zzi"_h,
        "srsra_z_zi"_h,
        "ssra_z_zi"_h,
        "ursra_z_zi"_h,
        "usra_z_zi"_h}},
      {"'Zd.'tszs, 'Zd.'tszs, 'Zn.'tszs, 'ITriSves", {"xar_z_zzi"_h}},
      {"'Zd.b, 'Zd.b", {"aesimc_z_z"_h, "aesmc_z_z"_h}},
      {"'Zd.b, 'Zd.b, 'Zn.b", {"aesd_z_zz"_h, "aese_z_zz"_h}},
      {"'Zd.b, 'Zd.b, 'Zn.b, #'u2016_1210", {"ext_z_zi_des"_h}},
      {"'Zd.b, 'Zn.b, 'Zm.b", {"histseg_z_zz"_h, "pmul_z_zz"_h}},
      {"'Zd.b, {'Zn.b, 'Zn2.b}, #'u2016_1210", {"ext_z_zi_con"_h}},
      {"'Zd.d, 'Pgl/m, 'Zn.d",
       {"fcvtzs_z_p_z_d2x"_h,
        "fcvtzu_z_p_z_d2x"_h,
        "scvtf_z_p_z_x2d"_h,
        "ucvtf_z_p_z_x2d"_h}},
      {"'Zd.d, 'Pgl/m, 'Zn.h",
       {"fcvt_z_p_z_h2d"_h, "fcvtzs_z_p_z_fp162x"_h, "fcvtzu_z_p_z_fp162x"_h}},
      {"'Zd.d, 'Pgl/m, 'Zn.s",
       {"fcvt_z_p_z_s2d"_h,
        "fcvtlt_z_p_z_s2d"_h,
        "fcvtzs_z_p_z_s2x"_h,
        "fcvtzu_z_p_z_s2x"_h,
        "scvtf_z_p_z_w2d"_h,
        "ucvtf_z_p_z_w2d"_h}},
      {"'Zd.d, 'Zd.d, 'Zm.d, 'Zn.d",
       {"bcax_z_zzz"_h,
        "bsl1n_z_zzz"_h,
        "bsl2n_z_zzz"_h,
        "bsl_z_zzz"_h,
        "eor3_z_zzz"_h,
        "nbsl_z_zzz"_h}},
      {"'Zd.d, 'Zn.d", {"mov_orr_z_zz"_h}},
      {"'Zd.d, 'Zn.d, 'Zm.d",
       {"rax1_z_zz"_h, "and_z_zz"_h, "bic_z_zz"_h, "eor_z_zz"_h, "orr_z_zz"_h}},
      {"'Zd.d, 'Zn.d, z'u1916.d['u2020]",
       {"fmla_z_zzzi_d"_h,
        "fmls_z_zzzi_d"_h,
        "fmul_z_zzi_d"_h,
        "mla_z_zzzi_d"_h,
        "mls_z_zzzi_d"_h,
        "mul_z_zzi_d"_h,
        "sqdmulh_z_zzi_d"_h,
        "sqrdmulh_z_zzi_d"_h,
        "sqrdmlah_z_zzzi_d"_h,
        "sqrdmlsh_z_zzzi_d"_h}},
      {"'Zd.d, 'Zn.h, z'u1916.h['u2020]",
       {"sdot_z_zzzi_d"_h, "udot_z_zzzi_d"_h}},
      {"'Zd.d, 'Zn.h, z'u1916.h['u2020], #'u1110*90", {"cdot_z_zzzi_d"_h}},
      {"'Zd.d, 'Zn.s, z'u1916.s['u2020_1111]",
       {"smlalb_z_zzzi_d"_h,
        "smlalt_z_zzzi_d"_h,
        "smlslb_z_zzzi_d"_h,
        "smlslt_z_zzzi_d"_h,
        "smullb_z_zzi_d"_h,
        "smullt_z_zzi_d"_h,
        "sqdmullb_z_zzi_d"_h,
        "sqdmullt_z_zzi_d"_h,
        "sqdmlalb_z_zzzi_d"_h,
        "sqdmlalt_z_zzzi_d"_h,
        "sqdmlslb_z_zzzi_d"_h,
        "sqdmlslt_z_zzzi_d"_h,
        "umlalb_z_zzzi_d"_h,
        "umlalt_z_zzzi_d"_h,
        "umlslb_z_zzzi_d"_h,
        "umlslt_z_zzzi_d"_h,
        "umullb_z_zzi_d"_h,
        "umullt_z_zzi_d"_h}},
      {"'Zd.d, ['Zn.d, 'Zm.d, sxtw'(1110? #'u1110)]",
       {"adr_z_az_d_s32_scaled"_h}},
      {"'Zd.d, ['Zn.d, 'Zm.d, uxtw'(1110? #'u1110)]",
       {"adr_z_az_d_u32_scaled"_h}},
      {"'Zd.h, 'Pgl/m, 'Zn.d",
       {"fcvt_z_p_z_d2h"_h, "scvtf_z_p_z_x2fp16"_h, "ucvtf_z_p_z_x2fp16"_h}},
      {"'Zd.h, 'Pgl/m, 'Zn.h",
       {"fcvtzs_z_p_z_fp162h"_h,
        "fcvtzu_z_p_z_fp162h"_h,
        "scvtf_z_p_z_h2fp16"_h,
        "ucvtf_z_p_z_h2fp16"_h}},
      {"'Zd.h, 'Pgl/m, 'Zn.s",
       {"fcvt_z_p_z_s2h"_h,
        "fcvtnt_z_p_z_s2h"_h,
        "bfcvt_z_p_z_s2bf"_h,
        "bfcvtnt_z_p_z_s2bf"_h,
        "scvtf_z_p_z_w2fp16"_h,
        "ucvtf_z_p_z_w2fp16"_h}},
      {"'Zd.h, 'Zn.h, z'u1816.h['u2019], #'u1110*90",
       {"cmla_z_zzzi_h"_h, "fcmla_z_zzzi_h"_h, "sqrdcmlah_z_zzzi_h"_h}},
      {"'Zd.h, 'Zn.h, z'u1816.h['u2222_2019]",
       {"fmla_z_zzzi_h"_h,
        "fmls_z_zzzi_h"_h,
        "fmul_z_zzi_h"_h,
        "mla_z_zzzi_h"_h,
        "mls_z_zzzi_h"_h,
        "mul_z_zzi_h"_h,
        "sqdmulh_z_zzi_h"_h,
        "sqrdmulh_z_zzi_h"_h,
        "sqrdmlah_z_zzzi_h"_h,
        "sqrdmlsh_z_zzzi_h"_h}},
      {"'Zd.q, 'Zn.d, 'Zm.d", {"pmullb_z_zz_q"_h, "pmullt_z_zz_q"_h}},
      {"'Zd.s, 'Pgl/m, 'Zn.d",
       {"fcvt_z_p_z_d2s"_h,
        "fcvtnt_z_p_z_d2s"_h,
        "fcvtx_z_p_z_d2s"_h,
        "fcvtxnt_z_p_z_d2s"_h,
        "fcvtzs_z_p_z_d2w"_h,
        "fcvtzu_z_p_z_d2w"_h,
        "scvtf_z_p_z_x2s"_h,
        "ucvtf_z_p_z_x2s"_h}},
      {"'Zd.s, 'Pgl/m, 'Zn.h",
       {"fcvt_z_p_z_h2s"_h,
        "fcvtlt_z_p_z_h2s"_h,
        "fcvtzs_z_p_z_fp162w"_h,
        "fcvtzu_z_p_z_fp162w"_h}},
      {"'Zd.s, 'Pgl/m, 'Zn.s",
       {"fcvtzs_z_p_z_s2w"_h,
        "fcvtzu_z_p_z_s2w"_h,
        "urecpe_z_p_z"_h,
        "ursqrte_z_p_z"_h,
        "scvtf_z_p_z_w2s"_h,
        "ucvtf_z_p_z_w2s"_h}},
      {"'Zd.s, 'Zd.s, 'Zn.s", {"sm4e_z_zz"_h}},
      {"'Zd.s, 'Zn.b, 'Zm.b",
       {"smmla_z_zzz"_h, "ummla_z_zzz"_h, "usmmla_z_zzz"_h, "usdot_z_zzz_s"_h}},
      {"'Zd.s, 'Zn.b, z'u1816.b['u2019]",
       {"sdot_z_zzzi_s"_h,
        "sudot_z_zzzi_s"_h,
        "udot_z_zzzi_s"_h,
        "usdot_z_zzzi_s"_h}},
      {"'Zd.s, 'Zn.b, z'u1816.b['u2019], #'u1110*90", {"cdot_z_zzzi_s"_h}},
      {"'Zd.s, 'Zn.h, 'Zm.h",
       {"fmlalb_z_zzz"_h,
        "fmlalt_z_zzz"_h,
        "fmlslb_z_zzz"_h,
        "fmlslt_z_zzz"_h,
        "bfdot_z_zzz"_h,
        "bfmlalb_z_zzz"_h,
        "bfmlalt_z_zzz"_h,
        "bfmmla_z_zzz"_h}},
      {"'Zd.s, 'Zn.h, z'u1816.h['u2019_1111]",
       {"fmlalb_z_zzzi_s"_h,   "fmlalt_z_zzzi_s"_h,   "fmlslb_z_zzzi_s"_h,
        "fmlslt_z_zzzi_s"_h,   "sqdmlalb_z_zzzi_s"_h, "sqdmlalt_z_zzzi_s"_h,
        "sqdmlslb_z_zzzi_s"_h, "sqdmlslt_z_zzzi_s"_h, "bfmlalb_z_zzzi"_h,
        "bfmlalt_z_zzzi"_h,    "smlalb_z_zzzi_s"_h,   "smlalt_z_zzzi_s"_h,
        "smlslb_z_zzzi_s"_h,   "smlslt_z_zzzi_s"_h,   "smullb_z_zzi_s"_h,
        "smullt_z_zzi_s"_h,    "sqdmullb_z_zzi_s"_h,  "sqdmullt_z_zzi_s"_h,
        "umlalb_z_zzzi_s"_h,   "umlalt_z_zzzi_s"_h,   "umlslb_z_zzzi_s"_h,
        "umlslt_z_zzzi_s"_h,   "umullb_z_zzi_s"_h,    "umullt_z_zzi_s"_h}},
      {"'Zd.s, 'Zn.h, z'u1816.h['u2019]", {"bfdot_z_zzzi"_h}},
      {"'Zd.s, 'Zn.s, 'Zm.s", {"sm4ekey_z_zz"_h}},
      {"'Zd.s, 'Zn.s, z'u1816.s['u2019]",
       {"fmla_z_zzzi_s"_h,
        "fmls_z_zzzi_s"_h,
        "fmul_z_zzi_s"_h,
        "mla_z_zzzi_s"_h,
        "mls_z_zzzi_s"_h,
        "mul_z_zzi_s"_h,
        "sqdmulh_z_zzi_s"_h,
        "sqrdmulh_z_zzi_s"_h,
        "sqrdmlah_z_zzzi_s"_h,
        "sqrdmlsh_z_zzzi_s"_h}},
      {"'Zd.s, 'Zn.s, z'u1916.s['u2020], #'u1110*90",
       {"cmla_z_zzzi_s"_h, "fcmla_z_zzzi_s"_h, "sqrdcmlah_z_zzzi_s"_h}},
      {"'prefOp, 'ILLiteral 'LValue", {"prfm_p_loadlit"_h}},
      {"'prefOp, ['Xns'(2012?, #'s2012)]", {"prfum_p_ldst_unscaled"_h}},
      {"'prefOp, ['Xns'ILU]", {"prfm_p_ldst_pos"_h}},
      {"'prefOp, ['Xns, 'Offsetreg]", {"prfm_p_ldst_regoff"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns'(2116?, #'s2116, mul vl)]",
       {"prfb_i_p_bi_s"_h,
        "prfd_i_p_bi_s"_h,
        "prfh_i_p_bi_s"_h,
        "prfw_i_p_bi_s"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns, 'Rm'(2423?, lsl #'u2423)]",
       {"prfb_i_p_br_s"_h,
        "prfd_i_p_br_s"_h,
        "prfh_i_p_br_s"_h,
        "prfw_i_p_br_s"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns, 'Zm.d'(1413?, lsl #'u1413)]",
       {"prfb_i_p_bz_d_64_scaled"_h,
        "prfd_i_p_bz_d_64_scaled"_h,
        "prfh_i_p_bz_d_64_scaled"_h,
        "prfw_i_p_bz_d_64_scaled"_h}},
      {"'prefSVEOp, 'Pgl, ['Zn.d'(2016?, #'u2016)]",
       {"prfb_i_p_ai_d"_h,
        "prfd_i_p_ai_d"_h,
        "prfh_i_p_ai_d"_h,
        "prfw_i_p_ai_d"_h}},
      {"'prefSVEOp, 'Pgl, ['Zn.s'(2016?, #'u2016)]",
       {"prfb_i_p_ai_s"_h,
        "prfd_i_p_ai_s"_h,
        "prfh_i_p_ai_s"_h,
        "prfw_i_p_ai_s"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns, 'Zm.d, '?22:suxtw'(2423? #'u2423)]",
       {"prfb_i_p_bz_d_x32_scaled"_h,
        "prfd_i_p_bz_d_x32_scaled"_h,
        "prfh_i_p_bz_d_x32_scaled"_h,
        "prfw_i_p_bz_d_x32_scaled"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns, 'Zm.s, '?22:suxtw #1]",
       {"prfh_i_p_bz_s_x32_scaled"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns, 'Zm.s, '?22:suxtw #2]",
       {"prfw_i_p_bz_s_x32_scaled"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns, 'Zm.s, '?22:suxtw #3]",
       {"prfd_i_p_bz_s_x32_scaled"_h}},
      {"'prefSVEOp, 'Pgl, ['Xns, 'Zm.s, '?22:suxtw]",
       {"prfb_i_p_bz_s_x32_scaled"_h}},
      {"'t'u0400, 'Pgl, 'Zn.'t",
       {"lasta_v_p_z"_h,
        "lastb_v_p_z"_h,
        "faddv_v_p_z"_h,
        "fmaxnmv_v_p_z"_h,
        "fmaxv_v_p_z"_h,
        "fminnmv_v_p_z"_h,
        "fminv_v_p_z"_h}},
      {"'t'u0400, 'Pgl, 't'u0400, 'Zn.'t",
       {"clasta_v_p_z"_h, "clastb_v_p_z"_h, "fadda_v_p_z"_h}},
      {"p'u1310, 'Pn.b", {"ptest_p_p"_h}},
      {"{#0x'x2005}",
       {"dcps1_dc_exception"_h,
        "dcps2_dc_exception"_h,
        "dcps3_dc_exception"_h}},
      {"{'Vt.'{nload}}, ['Xns]'(23?, 'Xmr1)",
       {"ld1_asisdlse_r1_1v"_h,
        "ld1_asisdlsep_i1_i1"_h,
        "ld1_asisdlsep_r1_r1"_h,
        "st1_asisdlse_r1_1v"_h,
        "st1_asisdlsep_i1_i1"_h,
        "st1_asisdlsep_r1_r1"_h}},
      {"{'Vt.'{nload}}, ['Xns]'(23?, 'Xmz1)",
       {"ld1r_asisdlsop_r1_i"_h,
        "ld1r_asisdlsop_rx1_r"_h,
        "ld1r_asisdlso_r1"_h}},
      {"{'Vt.'{nload}, 'Vt2.'{nload}}, ['Xns]'(23?, 'Xmr2)",
       {"ld2_asisdlse_r2"_h,
        "ld2_asisdlsep_i2_i"_h,
        "ld2_asisdlsep_r2_r"_h,
        "st2_asisdlse_r2"_h,
        "st2_asisdlsep_i2_i"_h,
        "st2_asisdlsep_r2_r"_h,
        "ld1_asisdlse_r2_2v"_h,
        "ld1_asisdlsep_i2_i2"_h,
        "ld1_asisdlsep_r2_r2"_h,
        "st1_asisdlse_r2_2v"_h,
        "st1_asisdlsep_i2_i2"_h,
        "st1_asisdlsep_r2_r2"_h}},
      {"{'Vt.'{nload}, 'Vt2.'{nload}}, ['Xns]'(23?, 'Xmz2)",
       {"ld2r_asisdlsop_r2_i"_h,
        "ld2r_asisdlsop_rx2_r"_h,
        "ld2r_asisdlso_r2"_h}},
      {"{'Vt.'{nload}, 'Vt2.'{nload}, 'Vt3.'{nload}}, ['Xns]'(23?, 'Xmr3)",
       {"ld3_asisdlse_r3"_h,
        "ld3_asisdlsep_i3_i"_h,
        "ld3_asisdlsep_r3_r"_h,
        "st3_asisdlse_r3"_h,
        "st3_asisdlsep_i3_i"_h,
        "st3_asisdlsep_r3_r"_h,
        "ld1_asisdlse_r3_3v"_h,
        "ld1_asisdlsep_i3_i3"_h,
        "ld1_asisdlsep_r3_r3"_h,
        "st1_asisdlse_r3_3v"_h,
        "st1_asisdlsep_i3_i3"_h,
        "st1_asisdlsep_r3_r3"_h}},
      {"{'Vt.'{nload}, 'Vt2.'{nload}, 'Vt3.'{nload}}, ['Xns]'(23?, 'Xmz3)",
       {"ld3r_asisdlsop_r3_i"_h,
        "ld3r_asisdlsop_rx3_r"_h,
        "ld3r_asisdlso_r3"_h}},
      {"{'Vt.'{nload}, 'Vt2.'{nload}, 'Vt3.'{nload}, 'Vt4.'{nload}}, "
       "['Xns]'(23?, 'Xmr4)",
       {"ld4_asisdlse_r4"_h,
        "ld4_asisdlsep_i4_i"_h,
        "ld4_asisdlsep_r4_r"_h,
        "st4_asisdlse_r4"_h,
        "st4_asisdlsep_i4_i"_h,
        "st4_asisdlsep_r4_r"_h,
        "ld1_asisdlse_r4_4v"_h,
        "ld1_asisdlsep_i4_i4"_h,
        "ld1_asisdlsep_r4_r4"_h,
        "st1_asisdlse_r4_4v"_h,
        "st1_asisdlsep_i4_i4"_h,
        "st1_asisdlsep_r4_r4"_h}},
      {"{'Vt.'{nload}, 'Vt2.'{nload}, 'Vt3.'{nload}, 'Vt4.'{nload}}, "
       "['Xns]'(23?, 'Xmz4)",
       {"ld4r_asisdlsop_r4_i"_h,
        "ld4r_asisdlsop_rx4_r"_h,
        "ld4r_asisdlso_r4"_h}},
      {"{'Vt.b, 'Vt2.b, 'Vt3.b, 'Vt4.b}['u3030_1210], ['Xns]'(23?, 'Xmb4)",
       {"ld4_asisdlsop_b4_i4b"_h,
        "ld4_asisdlsop_bx4_r4b"_h,
        "st4_asisdlsop_b4_i4b"_h,
        "st4_asisdlsop_bx4_r4b"_h,
        "ld4_asisdlso_b4_4b"_h,
        "st4_asisdlso_b4_4b"_h}},
      {"{'Vt.b, 'Vt2.b, 'Vt3.b}['u3030_1210], ['Xns]'(23?, 'Xmb3)",
       {"ld3_asisdlsop_b3_i3b"_h,
        "ld3_asisdlsop_bx3_r3b"_h,
        "st3_asisdlsop_b3_i3b"_h,
        "st3_asisdlsop_bx3_r3b"_h,
        "ld3_asisdlso_b3_3b"_h,
        "st3_asisdlso_b3_3b"_h}},
      {"{'Vt.b, 'Vt2.b}['u3030_1210], ['Xns]'(23?, 'Xmb2)",
       {"ld2_asisdlsop_b2_i2b"_h,
        "ld2_asisdlsop_bx2_r2b"_h,
        "st2_asisdlsop_b2_i2b"_h,
        "st2_asisdlsop_bx2_r2b"_h,
        "ld2_asisdlso_b2_2b"_h,
        "st2_asisdlso_b2_2b"_h}},
      {"{'Vt.b}['u3030_1210], ['Xns]'(23?, 'Xmb1)",
       {"ld1_asisdlsop_b1_i1b"_h,
        "ld1_asisdlsop_bx1_r1b"_h,
        "st1_asisdlsop_b1_i1b"_h,
        "st1_asisdlsop_bx1_r1b"_h,
        "ld1_asisdlso_b1_1b"_h,
        "st1_asisdlso_b1_1b"_h}},
      {"{'Vt.d, 'Vt2.d, 'Vt3.d, 'Vt4.d}['u3030], ['Xns]'(23?, 'Xmb32)",
       {"ld4_asisdlsop_d4_i4d"_h,
        "ld4_asisdlsop_dx4_r4d"_h,
        "st4_asisdlsop_d4_i4d"_h,
        "st4_asisdlsop_dx4_r4d"_h,
        "ld4_asisdlso_d4_4d"_h,
        "st4_asisdlso_d4_4d"_h}},
      {"{'Vt.d, 'Vt2.d, 'Vt3.d}['u3030], ['Xns]'(23?, 'Xmb24)",
       {"ld3_asisdlsop_d3_i3d"_h,
        "ld3_asisdlsop_dx3_r3d"_h,
        "st3_asisdlsop_d3_i3d"_h,
        "st3_asisdlsop_dx3_r3d"_h,
        "ld3_asisdlso_d3_3d"_h,
        "st3_asisdlso_d3_3d"_h}},
      {"{'Vt.d, 'Vt2.d}['u3030], ['Xns]'(23?, 'Xmb16)",
       {"ld2_asisdlsop_d2_i2d"_h,
        "ld2_asisdlsop_dx2_r2d"_h,
        "st2_asisdlsop_d2_i2d"_h,
        "st2_asisdlsop_dx2_r2d"_h,
        "ld2_asisdlso_d2_2d"_h,
        "st2_asisdlso_d2_2d"_h}},
      {"{'Vt.d}['u3030], ['Xns]'(23?, 'Xmb8)",
       {"ld1_asisdlsop_d1_i1d"_h,
        "ld1_asisdlsop_dx1_r1d"_h,
        "st1_asisdlsop_d1_i1d"_h,
        "st1_asisdlsop_dx1_r1d"_h,
        "ld1_asisdlso_d1_1d"_h,
        "st1_asisdlso_d1_1d"_h}},
      {"{'Vt.h, 'Vt2.h, 'Vt3.h, 'Vt4.h}['u3030_1211], ['Xns]'(23?, 'Xmb8)",
       {"ld4_asisdlso_h4_4h"_h,
        "ld4_asisdlsop_h4_i4h"_h,
        "ld4_asisdlsop_hx4_r4h"_h,
        "st4_asisdlso_h4_4h"_h,
        "st4_asisdlsop_h4_i4h"_h,
        "st4_asisdlsop_hx4_r4h"_h}},
      {"{'Vt.h, 'Vt2.h, 'Vt3.h}['u3030_1211], ['Xns]'(23?, 'Xmb6)",
       {"ld3_asisdlso_h3_3h"_h,
        "ld3_asisdlsop_h3_i3h"_h,
        "ld3_asisdlsop_hx3_r3h"_h,
        "st3_asisdlso_h3_3h"_h,
        "st3_asisdlsop_h3_i3h"_h,
        "st3_asisdlsop_hx3_r3h"_h}},
      {"{'Vt.h, 'Vt2.h}['u3030_1211], ['Xns]'(23?, 'Xmb4)",
       {"ld2_asisdlso_h2_2h"_h,
        "ld2_asisdlsop_h2_i2h"_h,
        "ld2_asisdlsop_hx2_r2h"_h,
        "st2_asisdlso_h2_2h"_h,
        "st2_asisdlsop_h2_i2h"_h,
        "st2_asisdlsop_hx2_r2h"_h}},
      {"{'Vt.h}['u3030_1211], ['Xns]'(23?, 'Xmb2)",
       {"ld1_asisdlso_h1_1h"_h,
        "ld1_asisdlsop_h1_i1h"_h,
        "ld1_asisdlsop_hx1_r1h"_h,
        "st1_asisdlso_h1_1h"_h,
        "st1_asisdlsop_h1_i1h"_h,
        "st1_asisdlsop_hx1_r1h"_h}},
      {"{'Vt.s, 'Vt2.s, 'Vt3.s, 'Vt4.s}['u3030_1212], ['Xns]'(23?, 'Xmb16)",
       {"ld4_asisdlsop_s4_i4s"_h,
        "ld4_asisdlsop_sx4_r4s"_h,
        "st4_asisdlsop_s4_i4s"_h,
        "st4_asisdlsop_sx4_r4s"_h,
        "ld4_asisdlso_s4_4s"_h,
        "st4_asisdlso_s4_4s"_h}},
      {"{'Vt.s, 'Vt2.s, 'Vt3.s}['u3030_1212], ['Xns]'(23?, 'Xmb12)",
       {"ld3_asisdlsop_s3_i3s"_h,
        "ld3_asisdlsop_sx3_r3s"_h,
        "st3_asisdlsop_s3_i3s"_h,
        "st3_asisdlsop_sx3_r3s"_h,
        "ld3_asisdlso_s3_3s"_h,
        "st3_asisdlso_s3_3s"_h}},
      {"{'Vt.s, 'Vt2.s}['u3030_1212], ['Xns]'(23?, 'Xmb8)",
       {"ld2_asisdlsop_s2_i2s"_h,
        "ld2_asisdlsop_sx2_r2s"_h,
        "st2_asisdlsop_s2_i2s"_h,
        "st2_asisdlsop_sx2_r2s"_h,
        "ld2_asisdlso_s2_2s"_h,
        "st2_asisdlso_s2_2s"_h}},
      {"{'Vt.s}['u3030_1212], ['Xns]'(23?, 'Xmb4)",
       {"ld1_asisdlsop_s1_i1s"_h,
        "ld1_asisdlsop_sx1_r1s"_h,
        "st1_asisdlsop_s1_i1s"_h,
        "st1_asisdlsop_sx1_r1s"_h,
        "ld1_asisdlso_s1_1s"_h,
        "st1_asisdlso_s1_1s"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns'(1916?, #'s1916, mul vl)]",
       {"ld1b_z_p_bi_u16"_h,    "ld1b_z_p_bi_u32"_h,    "ld1b_z_p_bi_u64"_h,
        "ld1b_z_p_bi_u8"_h,     "ld1d_z_p_bi_u64"_h,    "ld1h_z_p_bi_u16"_h,
        "ld1h_z_p_bi_u32"_h,    "ld1h_z_p_bi_u64"_h,    "ld1sb_z_p_bi_s16"_h,
        "ld1sb_z_p_bi_s32"_h,   "ld1sb_z_p_bi_s64"_h,   "ld1sh_z_p_bi_s32"_h,
        "ld1sh_z_p_bi_s64"_h,   "ld1sw_z_p_bi_s64"_h,   "ld1w_z_p_bi_u32"_h,
        "ld1w_z_p_bi_u64"_h,    "ldnf1b_z_p_bi_u16"_h,  "ldnf1b_z_p_bi_u32"_h,
        "ldnf1b_z_p_bi_u64"_h,  "ldnf1b_z_p_bi_u8"_h,   "ldnf1d_z_p_bi_u64"_h,
        "ldnf1h_z_p_bi_u16"_h,  "ldnf1h_z_p_bi_u32"_h,  "ldnf1h_z_p_bi_u64"_h,
        "ldnf1sb_z_p_bi_s16"_h, "ldnf1sb_z_p_bi_s32"_h, "ldnf1sb_z_p_bi_s64"_h,
        "ldnf1sh_z_p_bi_s32"_h, "ldnf1sh_z_p_bi_s64"_h, "ldnf1sw_z_p_bi_s64"_h,
        "ldnf1w_z_p_bi_u32"_h,  "ldnf1w_z_p_bi_u64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns'(2016=31?:, 'Xm)]",
       {"ldff1b_z_p_br_u16"_h,
        "ldff1b_z_p_br_u32"_h,
        "ldff1b_z_p_br_u64"_h,
        "ldff1b_z_p_br_u8"_h,
        "ldff1sb_z_p_br_s16"_h,
        "ldff1sb_z_p_br_s32"_h,
        "ldff1sb_z_p_br_s64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns'(2016=31?:, 'Xm, lsl #1)]",
       {"ldff1h_z_p_br_u16"_h,
        "ldff1h_z_p_br_u32"_h,
        "ldff1h_z_p_br_u64"_h,
        "ldff1sh_z_p_br_s32"_h,
        "ldff1sh_z_p_br_s64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns'(2016=31?:, 'Xm, lsl #2)]",
       {"ldff1w_z_p_br_u32"_h, "ldff1w_z_p_br_u64"_h, "ldff1sw_z_p_br_s64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns'(2016=31?:, 'Xm, lsl #3)]",
       {"ldff1d_z_p_br_u64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns, 'Xm, lsl #'u2423]",
       {"ld1d_z_p_br_u64"_h,
        "ld1h_z_p_br_u16"_h,
        "ld1h_z_p_br_u32"_h,
        "ld1h_z_p_br_u64"_h,
        "ld1w_z_p_br_u32"_h,
        "ld1w_z_p_br_u64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns, 'Xm, lsl #1]",
       {"ld1sh_z_p_br_s32"_h, "ld1sh_z_p_br_s64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns, 'Xm, lsl #2]", {"ld1sw_z_p_br_s64"_h}},
      {"{'Zt.'tlss}, 'Pgl/z, ['Xns, 'Xm]",
       {"ld1b_z_p_br_u16"_h,
        "ld1b_z_p_br_u32"_h,
        "ld1b_z_p_br_u64"_h,
        "ld1b_z_p_br_u8"_h,
        "ld1sb_z_p_br_s16"_h,
        "ld1sb_z_p_br_s32"_h,
        "ld1sb_z_p_br_s64"_h}},
      {"{'Zt.'tls}, 'Pgl, ['Xns'(1916?, #'s1916, mul vl)]",
       {"st1b_z_p_bi"_h, "st1d_z_p_bi"_h, "st1h_z_p_bi"_h, "st1w_z_p_bi"_h}},
      {"{'Zt.'tls}, 'Pgl, ['Xns, 'Xm'(2423?, lsl #'u2423)]",
       {"st1b_z_p_br"_h, "st1d_z_p_br"_h, "st1h_z_p_br"_h, "st1w_z_p_br"_h}},
      {"{'Zt.'tmsz, 'Zt2.'tmsz, 'Zt3.'tmsz, 'Zt4.'tmsz}, 'Pgl'(30?:/z), "
       "['Xns'(1916?, #'s1916*4, mul vl)]",
       {"st4b_z_p_bi_contiguous"_h,
        "st4d_z_p_bi_contiguous"_h,
        "st4h_z_p_bi_contiguous"_h,
        "st4w_z_p_bi_contiguous"_h,
        "ld4b_z_p_bi_contiguous"_h,
        "ld4d_z_p_bi_contiguous"_h,
        "ld4h_z_p_bi_contiguous"_h,
        "ld4w_z_p_bi_contiguous"_h}},
      {"{'Zt.'tmsz, 'Zt2.'tmsz, 'Zt3.'tmsz, 'Zt4.'tmsz}, 'Pgl'(30?:/z), "
       "['Xns, 'Xm'(2423?, lsl #'u2423)]",
       {"st4b_z_p_br_contiguous"_h,
        "st4d_z_p_br_contiguous"_h,
        "st4h_z_p_br_contiguous"_h,
        "st4w_z_p_br_contiguous"_h,
        "ld4b_z_p_br_contiguous"_h,
        "ld4d_z_p_br_contiguous"_h,
        "ld4h_z_p_br_contiguous"_h,
        "ld4w_z_p_br_contiguous"_h}},
      {"{'Zt.'tmsz, 'Zt2.'tmsz, 'Zt3.'tmsz}, 'Pgl'(30?:/z), ['Xns'(1916?, "
       "#'s1916*3, mul vl)]",
       {"st3b_z_p_bi_contiguous"_h,
        "st3d_z_p_bi_contiguous"_h,
        "st3h_z_p_bi_contiguous"_h,
        "st3w_z_p_bi_contiguous"_h,
        "ld3b_z_p_bi_contiguous"_h,
        "ld3d_z_p_bi_contiguous"_h,
        "ld3h_z_p_bi_contiguous"_h,
        "ld3w_z_p_bi_contiguous"_h}},
      {"{'Zt.'tmsz, 'Zt2.'tmsz, 'Zt3.'tmsz}, 'Pgl'(30?:/z), ['Xns, "
       "'Xm'(2423?, lsl #'u2423)]",
       {"st3b_z_p_br_contiguous"_h,
        "st3d_z_p_br_contiguous"_h,
        "st3h_z_p_br_contiguous"_h,
        "st3w_z_p_br_contiguous"_h,
        "ld3b_z_p_br_contiguous"_h,
        "ld3d_z_p_br_contiguous"_h,
        "ld3h_z_p_br_contiguous"_h,
        "ld3w_z_p_br_contiguous"_h}},
      {"{'Zt.'tmsz, 'Zt2.'tmsz}, 'Pgl'(30?:/z), ['Xns'(1916?, #'s1916*2, mul "
       "vl)]",
       {"st2b_z_p_bi_contiguous"_h,
        "st2d_z_p_bi_contiguous"_h,
        "st2h_z_p_bi_contiguous"_h,
        "st2w_z_p_bi_contiguous"_h,
        "ld2b_z_p_bi_contiguous"_h,
        "ld2d_z_p_bi_contiguous"_h,
        "ld2h_z_p_bi_contiguous"_h,
        "ld2w_z_p_bi_contiguous"_h}},
      {"{'Zt.'tmsz, 'Zt2.'tmsz}, 'Pgl'(30?:/z), ['Xns, 'Xm'(2423?, lsl "
       "#'u2423)]",
       {"st2b_z_p_br_contiguous"_h,
        "st2d_z_p_br_contiguous"_h,
        "st2h_z_p_br_contiguous"_h,
        "st2w_z_p_br_contiguous"_h,
        "ld2b_z_p_br_contiguous"_h,
        "ld2d_z_p_br_contiguous"_h,
        "ld2h_z_p_br_contiguous"_h,
        "ld2w_z_p_br_contiguous"_h}},
      {"{'Zt.'tmsz}, 'Pgl/z, ['Xns'(1916?, #'s1916*16)]",
       {"ld1rqb_z_p_bi_u8"_h,
        "ld1rqd_z_p_bi_u64"_h,
        "ld1rqh_z_p_bi_u16"_h,
        "ld1rqw_z_p_bi_u32"_h}},
      {"{'Zt.'tmsz}, 'Pgl/z, ['Xns'(1916?, #'s1916*32)]",
       {"ld1rob_z_p_bi_u8"_h,
        "ld1rod_z_p_bi_u64"_h,
        "ld1roh_z_p_bi_u16"_h,
        "ld1row_z_p_bi_u32"_h}},
      {"{'Zt.'tmsz}, 'Pgl/z, ['Xns, 'Rm, lsl #'u2423]",
       {"ld1rqd_z_p_br_contiguous"_h,
        "ld1rqh_z_p_br_contiguous"_h,
        "ld1rqw_z_p_br_contiguous"_h,
        "ld1rod_z_p_br_contiguous"_h,
        "ld1roh_z_p_br_contiguous"_h,
        "ld1row_z_p_br_contiguous"_h}},
      {"{'Zt.'tmsz}, 'Pgl/z, ['Xns, 'Rm]",
       {"ld1rqb_z_p_br_contiguous"_h, "ld1rob_z_p_br_contiguous"_h}},
      {"{'Zt.b}, 'Pgl, ['Xns, 'Rm]", {"stnt1b_z_p_br_contiguous"_h}},
      {"{'Zt.b}, 'Pgl/z, ['Xns, 'Rm]", {"ldnt1b_z_p_br_contiguous"_h}},
      {"{'Zt.b}, 'Pgl/z, ['Xns'(2116?, #'u2116)]", {"ld1rb_z_p_bi_u8"_h}},
      {"{'Zt.b}, 'Pgl'(20?:/z), ['Xns'(1916?, #'s1916, mul vl)]",
       {"ldnt1b_z_p_bi_contiguous"_h, "stnt1b_z_p_bi_contiguous"_h}},
      {"{'Zt.d}, 'Pgl'(20?:/z), ['Xns'(1916?, #'s1916, mul vl)]",
       {"ldnt1d_z_p_bi_contiguous"_h, "stnt1d_z_p_bi_contiguous"_h}},
      {"{'Zt.d}, 'Pgl'(29?:/z), ['Zn.d'(2016=31?:, 'Xm)]",
       {"stnt1b_z_p_ar_d_64_unscaled"_h,
        "stnt1d_z_p_ar_d_64_unscaled"_h,
        "stnt1h_z_p_ar_d_64_unscaled"_h,
        "stnt1w_z_p_ar_d_64_unscaled"_h,
        "ldnt1b_z_p_ar_d_64_unscaled"_h,
        "ldnt1d_z_p_ar_d_64_unscaled"_h,
        "ldnt1h_z_p_ar_d_64_unscaled"_h,
        "ldnt1sb_z_p_ar_d_64_unscaled"_h,
        "ldnt1sh_z_p_ar_d_64_unscaled"_h,
        "ldnt1sw_z_p_ar_d_64_unscaled"_h,
        "ldnt1w_z_p_ar_d_64_unscaled"_h}},
      {"{'Zt.d}, 'Pgl, ['Xns, 'Rm, lsl #3]", {"stnt1d_z_p_br_contiguous"_h}},
      {"{'Zt.d}, 'Pgl, ['Xns, 'Zm.d, '?14:suxtw #'u2423]",
       {"st1d_z_p_bz_d_x32_scaled"_h,
        "st1h_z_p_bz_d_x32_scaled"_h,
        "st1w_z_p_bz_d_x32_scaled"_h}},
      {"{'Zt.d}, 'Pgl, ['Xns, 'Zm.d, '?14:suxtw]",
       {"st1b_z_p_bz_d_x32_unscaled"_h,
        "st1d_z_p_bz_d_x32_unscaled"_h,
        "st1h_z_p_bz_d_x32_unscaled"_h,
        "st1w_z_p_bz_d_x32_unscaled"_h}},
      {"{'Zt.d}, 'Pgl, ['Xns, 'Zm.d, lsl #'u2423]",
       {"st1d_z_p_bz_d_64_scaled"_h,
        "st1h_z_p_bz_d_64_scaled"_h,
        "st1w_z_p_bz_d_64_scaled"_h}},
      {"{'Zt.d}, 'Pgl, ['Xns, 'Zm.d]",
       {"st1b_z_p_bz_d_64_unscaled"_h,
        "st1d_z_p_bz_d_64_unscaled"_h,
        "st1h_z_p_bz_d_64_unscaled"_h,
        "st1w_z_p_bz_d_64_unscaled"_h}},
      {"{'Zt.d}, 'Pgl, ['Zn.d'(2016?, #'u2016)]", {"st1b_z_p_ai_d"_h}},
      {"{'Zt.d}, 'Pgl, ['Zn.d'(2016?, #'u2016*2)]", {"st1h_z_p_ai_d"_h}},
      {"{'Zt.d}, 'Pgl, ['Zn.d'(2016?, #'u2016*4)]", {"st1w_z_p_ai_d"_h}},
      {"{'Zt.d}, 'Pgl, ['Zn.d'(2016?, #'u2016*8)]", {"st1d_z_p_ai_d"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns'(2116?, #'u2116)]",
       {"ld1rb_z_p_bi_u64"_h, "ld1rsb_z_p_bi_s64"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns'(2116?, #'u2116*2)]",
       {"ld1rh_z_p_bi_u64"_h, "ld1rsh_z_p_bi_s64"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns'(2116?, #'u2116*4)]",
       {"ld1rw_z_p_bi_u64"_h, "ld1rsw_z_p_bi_s64"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns'(2116?, #'u2116*8)]", {"ld1rd_z_p_bi_u64"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns, 'Rm, lsl #3]", {"ldnt1d_z_p_br_contiguous"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns, 'Zm.d, '?22:suxtw #'u2423]",
       {"ld1d_z_p_bz_d_x32_scaled"_h,
        "ld1h_z_p_bz_d_x32_scaled"_h,
        "ld1sh_z_p_bz_d_x32_scaled"_h,
        "ld1sw_z_p_bz_d_x32_scaled"_h,
        "ld1w_z_p_bz_d_x32_scaled"_h,
        "ldff1d_z_p_bz_d_x32_scaled"_h,
        "ldff1h_z_p_bz_d_x32_scaled"_h,
        "ldff1sh_z_p_bz_d_x32_scaled"_h,
        "ldff1sw_z_p_bz_d_x32_scaled"_h,
        "ldff1w_z_p_bz_d_x32_scaled"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns, 'Zm.d, '?22:suxtw]",
       {"ld1b_z_p_bz_d_x32_unscaled"_h,
        "ld1d_z_p_bz_d_x32_unscaled"_h,
        "ld1h_z_p_bz_d_x32_unscaled"_h,
        "ld1sb_z_p_bz_d_x32_unscaled"_h,
        "ld1sh_z_p_bz_d_x32_unscaled"_h,
        "ld1sw_z_p_bz_d_x32_unscaled"_h,
        "ld1w_z_p_bz_d_x32_unscaled"_h,
        "ldff1b_z_p_bz_d_x32_unscaled"_h,
        "ldff1d_z_p_bz_d_x32_unscaled"_h,
        "ldff1h_z_p_bz_d_x32_unscaled"_h,
        "ldff1sb_z_p_bz_d_x32_unscaled"_h,
        "ldff1sh_z_p_bz_d_x32_unscaled"_h,
        "ldff1sw_z_p_bz_d_x32_unscaled"_h,
        "ldff1w_z_p_bz_d_x32_unscaled"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns, 'Zm.d, lsl #'u2423]",
       {"ld1d_z_p_bz_d_64_scaled"_h,
        "ld1h_z_p_bz_d_64_scaled"_h,
        "ld1sh_z_p_bz_d_64_scaled"_h,
        "ld1sw_z_p_bz_d_64_scaled"_h,
        "ld1w_z_p_bz_d_64_scaled"_h,
        "ldff1d_z_p_bz_d_64_scaled"_h,
        "ldff1h_z_p_bz_d_64_scaled"_h,
        "ldff1sh_z_p_bz_d_64_scaled"_h,
        "ldff1sw_z_p_bz_d_64_scaled"_h,
        "ldff1w_z_p_bz_d_64_scaled"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Xns, 'Zm.d]",
       {"ld1b_z_p_bz_d_64_unscaled"_h,
        "ld1d_z_p_bz_d_64_unscaled"_h,
        "ld1h_z_p_bz_d_64_unscaled"_h,
        "ld1sb_z_p_bz_d_64_unscaled"_h,
        "ld1sh_z_p_bz_d_64_unscaled"_h,
        "ld1sw_z_p_bz_d_64_unscaled"_h,
        "ld1w_z_p_bz_d_64_unscaled"_h,
        "ldff1b_z_p_bz_d_64_unscaled"_h,
        "ldff1d_z_p_bz_d_64_unscaled"_h,
        "ldff1h_z_p_bz_d_64_unscaled"_h,
        "ldff1sb_z_p_bz_d_64_unscaled"_h,
        "ldff1sh_z_p_bz_d_64_unscaled"_h,
        "ldff1sw_z_p_bz_d_64_unscaled"_h,
        "ldff1w_z_p_bz_d_64_unscaled"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Zn.d'(2016?, #'u2016)]",
       {"ld1b_z_p_ai_d"_h,
        "ld1sb_z_p_ai_d"_h,
        "ldff1b_z_p_ai_d"_h,
        "ldff1sb_z_p_ai_d"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Zn.d'(2016?, #'u2016*2)]",
       {"ld1h_z_p_ai_d"_h,
        "ld1sh_z_p_ai_d"_h,
        "ldff1h_z_p_ai_d"_h,
        "ldff1sh_z_p_ai_d"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Zn.d'(2016?, #'u2016*4)]",
       {"ld1sw_z_p_ai_d"_h,
        "ld1w_z_p_ai_d"_h,
        "ldff1sw_z_p_ai_d"_h,
        "ldff1w_z_p_ai_d"_h}},
      {"{'Zt.d}, 'Pgl/z, ['Zn.d'(2016?, #'u2016*8)]",
       {"ld1d_z_p_ai_d"_h, "ldff1d_z_p_ai_d"_h}},
      {"{'Zt.h}, 'Pgl'(30?:/z), ['Xns, 'Rm, lsl #1]",
       {"ldnt1h_z_p_br_contiguous"_h, "stnt1h_z_p_br_contiguous"_h}},
      {"{'Zt.h}, 'Pgl'(20?:/z), ['Xns'(1916?, #'s1916, mul vl)]",
       {"ldnt1h_z_p_bi_contiguous"_h, "stnt1h_z_p_bi_contiguous"_h}},
      {"{'Zt.h}, 'Pgl/z, ['Xns'(2116?, #'u2116*2)]",
       {"ld1rb_z_p_bi_u16"_h, "ld1rsb_z_p_bi_s16"_h}},
      {"{'Zt.h}, 'Pgl/z, ['Xns'(2116?, #'u2116*4)]", {"ld1rh_z_p_bi_u16"_h}},
      {"{'Zt.s}, 'Pgl'(29?:/z), ['Zn.s'(2016=31?:, 'Xm)]",
       {"stnt1b_z_p_ar_s_x32_unscaled"_h,
        "stnt1h_z_p_ar_s_x32_unscaled"_h,
        "stnt1w_z_p_ar_s_x32_unscaled"_h,
        "ldnt1b_z_p_ar_s_x32_unscaled"_h,
        "ldnt1h_z_p_ar_s_x32_unscaled"_h,
        "ldnt1sb_z_p_ar_s_x32_unscaled"_h,
        "ldnt1sh_z_p_ar_s_x32_unscaled"_h,
        "ldnt1w_z_p_ar_s_x32_unscaled"_h}},
      {"{'Zt.s}, 'Pgl, ['Xns, 'Rm, lsl #2]", {"stnt1w_z_p_br_contiguous"_h}},
      {"{'Zt.s}, 'Pgl, ['Xns, 'Zm.s, '?14:suxtw #'u2423]",
       {"st1h_z_p_bz_s_x32_scaled"_h, "st1w_z_p_bz_s_x32_scaled"_h}},
      {"{'Zt.s}, 'Pgl, ['Xns, 'Zm.s, '?14:suxtw]",
       {"st1b_z_p_bz_s_x32_unscaled"_h,
        "st1h_z_p_bz_s_x32_unscaled"_h,
        "st1w_z_p_bz_s_x32_unscaled"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Xns'(2116?, #'u2116)]",
       {"ld1rb_z_p_bi_u32"_h, "ld1rsb_z_p_bi_s32"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Xns'(2116?, #'u2116*2)]",
       {"ld1rh_z_p_bi_u32"_h, "ld1rsh_z_p_bi_s32"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Xns'(2116?, #'u2116*4)]",
       {"ld1rw_z_p_bi_u32"_h, "ld1rsw_z_p_bi_s32"_h}},
      {"{'Zt.s}, 'Pgl'(20?:/z), ['Xns'(1916?, #'s1916, mul vl)]",
       {"ldnt1w_z_p_bi_contiguous"_h, "stnt1w_z_p_bi_contiguous"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Xns, 'Rm, lsl #2]", {"ldnt1w_z_p_br_contiguous"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Xns, 'Zm.s, '?22:suxtw #1]",
       {"ld1h_z_p_bz_s_x32_scaled"_h,
        "ld1sh_z_p_bz_s_x32_scaled"_h,
        "ldff1h_z_p_bz_s_x32_scaled"_h,
        "ldff1sh_z_p_bz_s_x32_scaled"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Xns, 'Zm.s, '?22:suxtw #2]",
       {"ld1w_z_p_bz_s_x32_scaled"_h, "ldff1w_z_p_bz_s_x32_scaled"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Xns, 'Zm.s, '?22:suxtw]",
       {"ld1b_z_p_bz_s_x32_unscaled"_h,
        "ld1h_z_p_bz_s_x32_unscaled"_h,
        "ld1sb_z_p_bz_s_x32_unscaled"_h,
        "ld1sh_z_p_bz_s_x32_unscaled"_h,
        "ld1w_z_p_bz_s_x32_unscaled"_h,
        "ldff1b_z_p_bz_s_x32_unscaled"_h,
        "ldff1h_z_p_bz_s_x32_unscaled"_h,
        "ldff1sb_z_p_bz_s_x32_unscaled"_h,
        "ldff1sh_z_p_bz_s_x32_unscaled"_h,
        "ldff1w_z_p_bz_s_x32_unscaled"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Zn.s'(2016?, #'u2016)]",
       {"ld1b_z_p_ai_s"_h,
        "ld1sb_z_p_ai_s"_h,
        "ldff1b_z_p_ai_s"_h,
        "ldff1sb_z_p_ai_s"_h}},
      {"{'Zt.s}, 'Pgl, ['Zn.s'(2016?, #'u2016)]", {"st1b_z_p_ai_s"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Zn.s'(2016?, #'u2016*2)]",
       {"ld1h_z_p_ai_s"_h,
        "ld1sh_z_p_ai_s"_h,
        "ldff1h_z_p_ai_s"_h,
        "ldff1sh_z_p_ai_s"_h}},
      {"{'Zt.s}, 'Pgl, ['Zn.s'(2016?, #'u2016*2)]", {"st1h_z_p_ai_s"_h}},
      {"{'Zt.s}, 'Pgl/z, ['Zn.s'(2016?, #'u2016*4)]",
       {"ld1w_z_p_ai_s"_h, "ldff1w_z_p_ai_s"_h}},
      {"{'Zt.s}, 'Pgl, ['Zn.s'(2016?, #'u2016*4)]", {"st1w_z_p_ai_s"_h}},
      {"'Zd.'t, 'Pgl/m, 'Zd.'t, 'Zn.d",
       {"asr_z_p_zw"_h, "lsl_z_p_zw"_h, "lsr_z_p_zw"_h}},
      {"'Zd.'t, 'Zn.'t, 'Zm.'th",
       {"saddwb_z_zz"_h,
        "saddwt_z_zz"_h,
        "ssubwb_z_zz"_h,
        "ssubwt_z_zz"_h,
        "uaddwb_z_zz"_h,
        "uaddwt_z_zz"_h,
        "usubwb_z_zz"_h,
        "usubwt_z_zz"_h}},
      {"'Zd.'t, 'Zn.'th",
       {"sunpkhi_z_z"_h, "sunpklo_z_z"_h, "uunpkhi_z_z"_h, "uunpklo_z_z"_h}},
      {"'Zd.'t, 'Zn.'th, 'Zm.'th",
       {"smlalb_z_zzz"_h,   "smlalt_z_zzz"_h,   "smlslb_z_zzz"_h,
        "smlslt_z_zzz"_h,   "sqdmlalb_z_zzz"_h, "sqdmlalbt_z_zzz"_h,
        "sqdmlalt_z_zzz"_h, "sqdmlslb_z_zzz"_h, "sqdmlslbt_z_zzz"_h,
        "sqdmlslt_z_zzz"_h, "umlalb_z_zzz"_h,   "umlalt_z_zzz"_h,
        "umlslb_z_zzz"_h,   "umlslt_z_zzz"_h,   "sabalb_z_zzz"_h,
        "sabalt_z_zzz"_h,   "sabdlb_z_zz"_h,    "sabdlt_z_zz"_h,
        "saddlb_z_zz"_h,    "saddlbt_z_zz"_h,   "saddlt_z_zz"_h,
        "smullb_z_zz"_h,    "smullt_z_zz"_h,    "sqdmullb_z_zz"_h,
        "sqdmullt_z_zz"_h,  "ssublb_z_zz"_h,    "ssublbt_z_zz"_h,
        "ssublt_z_zz"_h,    "ssubltb_z_zz"_h,   "uabalb_z_zzz"_h,
        "uabalt_z_zzz"_h,   "uabdlb_z_zz"_h,    "uabdlt_z_zz"_h,
        "uaddlb_z_zz"_h,    "uaddlt_z_zz"_h,    "umullb_z_zz"_h,
        "umullt_z_zz"_h,    "usublb_z_zz"_h,    "usublt_z_zz"_h,
        "pmullb_z_zz"_h,    "pmullt_z_zz"_h}},
      {"'Zt, ['Xns'(2110=16?:, #'s2116_1210, mul vl)]",
       {"ldr_z_bi"_h, "str_z_bi"_h}},
      {"x16", {"chkfeat_hf_hints"_h}}};

  for (auto &itm : forms) {
    const std::unordered_set<uint32_t> &s = forms.at(itm.first);
    for (const uint32_t &its : s) {
      fts->insert(std::make_pair(its, itm.first.c_str()));
    }
  }
}

const Disassembler::FormToVisitorFnMap *Disassembler::GetFormToVisitorFnMap() {
  static const FormToVisitorFnMap form_to_visitor = {
      DEFAULT_FORM_TO_VISITOR_MAP(Disassembler),
      {"cpyen_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyern_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyewn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpye_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfen_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfern_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfewn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfe_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfmn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfmrn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfmwn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfm_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfpn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfprn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfpwn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyfp_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpymn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpymrn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpymwn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpym_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpypn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyprn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpypwn_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"cpyp_cpy_memcms"_h, &Disassembler::DisassembleCpy},
      {"seten_set_memcms"_h, &Disassembler::DisassembleSet},
      {"sete_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setgen_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setge_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setgmn_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setgm_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setgpn_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setgp_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setmn_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setm_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setpn_set_memcms"_h, &Disassembler::DisassembleSet},
      {"setp_set_memcms"_h, &Disassembler::DisassembleSet},
  };
  return &form_to_visitor;
}  // NOLINT(readability/fn_size)

Disassembler::Disassembler() {
  buffer_size_ = 256;
  buffer_ = reinterpret_cast<char *>(malloc(buffer_size_));
  buffer_pos_ = 0;
  own_buffer_ = true;
  code_address_offset_ = 0;

  PopulateFormToStringMap(&form_to_string_);
  PopulatePerInstructionUnallocatedMap(&form_to_unalloc_);
}

Disassembler::Disassembler(char *text_buffer, int buffer_size) {
  buffer_size_ = buffer_size;
  buffer_ = text_buffer;
  buffer_pos_ = 0;
  own_buffer_ = false;
  code_address_offset_ = 0;

  PopulateFormToStringMap(&form_to_string_);
  PopulatePerInstructionUnallocatedMap(&form_to_unalloc_);
}

Disassembler::~Disassembler() {
  if (own_buffer_) {
    free(buffer_);
  }
}

char *Disassembler::GetOutput() { return buffer_; }

bool Disassembler::IsMovzMovnImm(unsigned reg_size, uint64_t value) {
  VIXL_ASSERT((reg_size == kXRegSize) ||
              ((reg_size == kWRegSize) && (value <= 0xffffffff)));

  // Test for movz: 16 bits set at positions 0, 16, 32 or 48.
  if (((value & UINT64_C(0xffffffffffff0000)) == 0) ||
      ((value & UINT64_C(0xffffffff0000ffff)) == 0) ||
      ((value & UINT64_C(0xffff0000ffffffff)) == 0) ||
      ((value & UINT64_C(0x0000ffffffffffff)) == 0)) {
    return true;
  }

  // Test for movn: NOT(16 bits set at positions 0, 16, 32 or 48).
  if ((reg_size == kXRegSize) &&
      (((~value & UINT64_C(0xffffffffffff0000)) == 0) ||
       ((~value & UINT64_C(0xffffffff0000ffff)) == 0) ||
       ((~value & UINT64_C(0xffff0000ffffffff)) == 0) ||
       ((~value & UINT64_C(0x0000ffffffffffff)) == 0))) {
    return true;
  }
  if ((reg_size == kWRegSize) && (((value & 0xffff0000) == 0xffff0000) ||
                                  ((value & 0x0000ffff) == 0x0000ffff))) {
    return true;
  }
  return false;
}

// clang-format off
#define LOAD_STORE_EXCLUSIVE_LIST(V)   \
  V(STXRB_w,  "'Ws, 'Wt")              \
  V(STXRH_w,  "'Ws, 'Wt")              \
  V(STXR_w,   "'Ws, 'Wt")              \
  V(STXR_x,   "'Ws, 'Xt")              \
  V(LDXR_x,   "'Xt")                   \
  V(STXP_w,   "'Ws, 'Wt, 'Wt2")        \
  V(STXP_x,   "'Ws, 'Xt, 'Xt2")        \
  V(LDXP_w,   "'Wt, 'Wt2")             \
  V(LDXP_x,   "'Xt, 'Xt2")             \
  V(STLXRB_w, "'Ws, 'Wt")              \
  V(STLXRH_w, "'Ws, 'Wt")              \
  V(STLXR_w,  "'Ws, 'Wt")              \
  V(STLXR_x,  "'Ws, 'Xt")              \
  V(LDAXR_x,  "'Xt")                   \
  V(STLXP_w,  "'Ws, 'Wt, 'Wt2")        \
  V(STLXP_x,  "'Ws, 'Xt, 'Xt2")        \
  V(LDAXP_w,  "'Wt, 'Wt2")             \
  V(LDAXP_x,  "'Xt, 'Xt2")             \
  V(STLR_x,   "'Xt")                   \
  V(LDAR_x,   "'Xt")                   \
  V(STLLR_x,  "'Xt")                   \
  V(LDLAR_x,  "'Xt")                   \
  V(CAS_w,    "'Ws, 'Wt")              \
  V(CAS_x,    "'Xs, 'Xt")              \
  V(CASA_w,   "'Ws, 'Wt")              \
  V(CASA_x,   "'Xs, 'Xt")              \
  V(CASL_w,   "'Ws, 'Wt")              \
  V(CASL_x,   "'Xs, 'Xt")              \
  V(CASAL_w,  "'Ws, 'Wt")              \
  V(CASAL_x,  "'Xs, 'Xt")              \
  V(CASB,     "'Ws, 'Wt")              \
  V(CASAB,    "'Ws, 'Wt")              \
  V(CASLB,    "'Ws, 'Wt")              \
  V(CASALB,   "'Ws, 'Wt")              \
  V(CASH,     "'Ws, 'Wt")              \
  V(CASAH,    "'Ws, 'Wt")              \
  V(CASLH,    "'Ws, 'Wt")              \
  V(CASALH,   "'Ws, 'Wt")              \
  V(CASP_w,   "'Ws, 'Ws+, 'Wt, 'Wt+")  \
  V(CASP_x,   "'Xs, 'Xs+, 'Xt, 'Xt+")  \
  V(CASPA_w,  "'Ws, 'Ws+, 'Wt, 'Wt+")  \
  V(CASPA_x,  "'Xs, 'Xs+, 'Xt, 'Xt+")  \
  V(CASPL_w,  "'Ws, 'Ws+, 'Wt, 'Wt+")  \
  V(CASPL_x,  "'Xs, 'Xs+, 'Xt, 'Xt+")  \
  V(CASPAL_w, "'Ws, 'Ws+, 'Wt, 'Wt+")  \
  V(CASPAL_x, "'Xs, 'Xs+, 'Xt, 'Xt+")
// clang-format on

void Disassembler::VisitLoadStoreExclusive(const Instruction *instr) {
  const char *form = "'Wt";
  const char *suffix = ", ['Xns]";

  switch (instr->Mask(LoadStoreExclusiveMask)) {
#define LSX(A, B) \
  case A:         \
    form = B;     \
    break;
    LOAD_STORE_EXCLUSIVE_LIST(LSX)
#undef LSX
  }

  switch (instr->Mask(LoadStoreExclusiveMask)) {
    case CASP_w:
    case CASP_x:
    case CASPA_w:
    case CASPA_x:
    case CASPL_w:
    case CASPL_x:
    case CASPAL_w:
    case CASPAL_x:
      if ((instr->GetRs() % 2 == 1) || (instr->GetRt() % 2 == 1)) {
        VisitUnallocated(instr);
        return;
      }
      break;
  }

  FormatWithDecodedMnemonic(instr, form, suffix);
}

void Disassembler::VisitSystem(const Instruction *instr) {
  const char *mnemonic = mnemonic_.c_str();
  const char *form = "";
  const char *suffix = NULL;

  switch (form_hash_) {
    case Hash("dsb_bo_barriers"): {
      int crm = instr->GetCRm();
      if (crm == 0) {
        mnemonic = "ssbb";
        form = "";
      } else if (crm == 4) {
        mnemonic = "pssbb";
        form = "";
      } else {
        form = "'M";
      }
      break;
    }
    case Hash("sys_cr_systeminstrs"): {
      const std::map<uint32_t, const char *> dcop = {
          {IVAU, "ivau"},
          {CVAC, "cvac"},
          {CVAU, "cvau"},
          {CVAP, "cvap"},
          {CVADP, "cvadp"},
          {CIVAC, "civac"},
          {ZVA, "zva"},
          {GVA, "gva"},
          {GZVA, "gzva"},
          {CGVAC, "cgvac"},
          {CGDVAC, "cgdvac"},
          {CGVAP, "cgvap"},
          {CGDVAP, "cgdvap"},
          {CIGVAC, "cigvac"},
          {CIGDVAC, "cigdvac"},
      };

      uint32_t sysop = instr->GetSysOp();
      if (dcop.count(sysop)) {
        if (sysop == IVAU) {
          mnemonic = "ic";
        } else {
          mnemonic = "dc";
        }
        form = dcop.at(sysop);
        suffix = ", 'Xt";
      } else if (sysop == GCSSS1) {
        mnemonic = "gcsss1";
        form = "'Xt";
      } else if (sysop == GCSPUSHM) {
        mnemonic = "gcspushm";
        form = "'Xt";
      } else {
        mnemonic = "sys";
        form = "'G1, 'Kn, 'Km, 'G2";
        if (instr->GetRt() < 31) {
          suffix = ", 'Xt";
        }
      }
      break;
    }
    case "sysl_rc_systeminstrs"_h:
      uint32_t sysop = instr->GetSysOp();
      if (sysop == GCSPOPM) {
        mnemonic = "gcspopm";
        form = (instr->GetRt() == 31) ? "" : "'Xt";
      } else if (sysop == GCSSS2) {
        mnemonic = "gcsss2";
        form = "'Xt";
      }
      break;
  }
  Format(instr, mnemonic, form, suffix);
}

static bool SVEMoveMaskPreferred(uint64_t value, int lane_bytes_log2) {
  VIXL_ASSERT(IsUintN(8 << lane_bytes_log2, value));

  // Duplicate lane-sized value across double word.
  switch (lane_bytes_log2) {
    case 0:
      value *= 0x0101010101010101;
      break;
    case 1:
      value *= 0x0001000100010001;
      break;
    case 2:
      value *= 0x0000000100000001;
      break;
    case 3:  // Nothing to do
      break;
    default:
      VIXL_UNREACHABLE();
  }

  if ((value & 0xff) == 0) {
    // mov z.d, #signed_16bit_imm
    if (value == SignExtend(value, 16)) {
      return false;
    }

    // mov z.s, #signed_16bit_imm
    uint32_t value32 = static_cast<uint32_t>(value);
    if (AllWordsMatch(value) && (value32 == SignExtend(value32, 16))) {
      return false;
    }

    // mov z.h, #signed_16bit_imm
    if (AllHalfwordsMatch(value)) {
      return false;
    }
  } else {
    // mov z.d, #signed_8bit_imm
    if (value == SignExtend(value, 8)) {
      return false;
    }

    // mov z.s, #signed_8bit_imm
    uint32_t value32 = static_cast<uint32_t>(value);
    if (AllWordsMatch(value) && (value32 == SignExtend(value32, 8))) {
      return false;
    }

    // mov z.h, #signed_8bit_imm
    uint16_t value16 = static_cast<uint16_t>(value);
    if (AllHalfwordsMatch(value) && (value16 == SignExtend(value16, 8))) {
      return false;
    }

    // mov z.b, #signed_8bit_imm
    if (AllBytesMatch(value)) {
      return false;
    }
  }
  return true;
}

void Disassembler::VisitSVEBroadcastBitmaskImm(const Instruction *instr) {
  uint64_t imm = instr->GetSVEImmLogical();
  if (imm == 0) {
    VisitUnallocated(instr);
  } else {
    int lane_size = instr->GetSVEBitwiseImmLaneSizeInBytesLog2();
    const char *mnemonic =
        SVEMoveMaskPreferred(imm, lane_size) ? "mov" : "dupm";
    const char *form = "'Zd.'tl, 'ITriSvel";
    Format(instr, mnemonic, form);
  }
}

void Disassembler::VisitSVEBroadcastIndexElement(const Instruction *instr) {
  const char *mnemonic = "unimplemented";
  const char *form = "(SVEBroadcastIndexElement)";

  switch (instr->Mask(SVEBroadcastIndexElementMask)) {
    case DUP_z_zi: {
      // The tsz field must not be zero.
      int tsz = instr->ExtractBits(20, 16);
      if (tsz != 0) {
        // The preferred disassembly for dup is "mov".
        mnemonic = "mov";
        int imm2 = instr->ExtractBits(23, 22);
        if ((CountSetBits(imm2) + CountSetBits(tsz)) == 1) {
          // If imm2:tsz has one set bit, the index is zero. This is
          // disassembled as a mov from a b/h/s/d/q scalar register.
          form = "'Zd.'ti, 'ti'u0905";
        } else {
          form = "'Zd.'ti, 'Zn.'ti['IVInsSVEIndex]";
        }
      }
      break;
    }
    default:
      break;
  }
  Format(instr, mnemonic, form);
}

void Disassembler::VisitReserved(const Instruction *instr) {
  FormatWithDecodedMnemonic(instr, "#0x'x1500");
}

void Disassembler::VisitUnimplemented(const Instruction *instr) {
  Format(instr, "unimplemented", "(Unimplemented)");
}

void Disassembler::VisitUnallocated(const Instruction *instr) {
  Format(instr, "unallocated", "(Unallocated)");
}

void Disassembler::Visit(Metadata *metadata, const Instruction *instr) {
  VIXL_ASSERT(metadata->count("form") > 0);
  std::string form = (*metadata)["form"];
  form_hash_ = Hash(form.c_str());

  // Check for unallocated encodings.
  auto range = form_to_unalloc_.equal_range(form_hash_);
  for (auto itu = range.first; itu != range.second; ++itu) {
    uint32_t mask = itu->second >> 32;
    uint32_t value = itu->second & 0xffffffff;
    if (instr->Mask(mask) == value) {
      VisitUnallocated(instr);
      return;
    }
  }

  // Find the alias of the decoded instruction, if any.
  std::string alias = GetMnemonicAlias(instr);
  if (alias.length() > 0) {
    form = alias + "_" + form;
    form_hash_ = Hash(form.c_str());
  }

  // Get the disassembly string for this form or alias.
  FormToStringMap::const_iterator its = form_to_string_.find(form_hash_);
  if (its != form_to_string_.end()) {
    SetMnemonicFromForm(form);
    FormatWithDecodedMnemonic(instr, its->second);
    return;
  }

  if (alias.length() > 0) {
    printf("Unhandled %s\n", form.c_str());
  }
  // All aliases should be handled by this point.
  VIXL_ASSERT(alias.length() == 0);

  // Call a legacy visitor-based handler.
  const FormToVisitorFnMap *fv = Disassembler::GetFormToVisitorFnMap();
  FormToVisitorFnMap::const_iterator it = fv->find(form_hash_);
  if (it == fv->end()) {
    VisitUnimplemented(instr);
  } else {
    SetMnemonicFromForm(form);
    (it->second)(this, instr);
  }
}

void Disassembler::DisassembleCpy(const Instruction *instr) {
  const char *form = "['Xd]!, ['Xs]!, 'Xn!";

  int d = instr->GetRd();
  int n = instr->GetRn();
  int s = instr->GetRs();

  // Aliased registers and sp/zr are disallowed.
  if ((d == n) || (d == s) || (n == s) || (d == 31) || (n == 31) || (s == 31)) {
    form = NULL;
  }

  // Bits 31 and 30 must be zero.
  if (instr->ExtractBits(31, 30)) {
    form = NULL;
  }

  Format(instr, mnemonic_.c_str(), form);
}

void Disassembler::DisassembleSet(const Instruction *instr) {
  const char *form = "['Xd]!, 'Xn!, 'Xs";

  int d = instr->GetRd();
  int n = instr->GetRn();
  int s = instr->GetRs();

  // Aliased registers are disallowed. Only Xs may be xzr.
  if ((d == n) || (d == s) || (n == s) || (d == 31) || (n == 31)) {
    form = NULL;
  }

  // Bits 31 and 30 must be zero.
  if (instr->ExtractBits(31, 30)) {
    form = NULL;
  }

  Format(instr, mnemonic_.c_str(), form);
}

void Disassembler::ProcessOutput(const Instruction * /*instr*/) {
  // The base disasm does nothing more than disassembling into a buffer.
}

void Disassembler::AppendRegisterNameToOutput(const Instruction *instr,
                                              const CPURegister &reg) {
  USE(instr);
  VIXL_ASSERT(reg.IsValid());
  char reg_char;

  if (reg.IsRegister()) {
    reg_char = reg.Is64Bits() ? 'x' : 'w';
  } else {
    VIXL_ASSERT(reg.IsVRegister());
    switch (reg.GetSizeInBits()) {
      case kBRegSize:
        reg_char = 'b';
        break;
      case kHRegSize:
        reg_char = 'h';
        break;
      case kSRegSize:
        reg_char = 's';
        break;
      case kDRegSize:
        reg_char = 'd';
        break;
      default:
        VIXL_ASSERT(reg.Is128Bits());
        reg_char = 'q';
    }
  }

  if (reg.IsVRegister() || !(reg.Aliases(sp) || reg.Aliases(xzr))) {
    // A core or scalar/vector register: [wx]0 - 30, [bhsdq]0 - 31.
    AppendToOutput("%c%d", reg_char, reg.GetCode());
  } else if (reg.Aliases(sp)) {
    // Disassemble w31/x31 as stack pointer wsp/sp.
    AppendToOutput("%s", reg.Is64Bits() ? "sp" : "wsp");
  } else {
    // Disassemble w31/x31 as zero register wzr/xzr.
    AppendToOutput("%czr", reg_char);
  }
}

void Disassembler::AppendPCRelativeOffsetToOutput(const Instruction *instr,
                                                  int64_t offset) {
  USE(instr);
  if (offset < 0) {
    // Cast to uint64_t so that INT64_MIN is handled in a well-defined way.
    uint64_t abs_offset = UnsignedNegate(static_cast<uint64_t>(offset));
    AppendToOutput("#-0x%" PRIx64, abs_offset);
  } else {
    AppendToOutput("#+0x%" PRIx64, offset);
  }
}

void Disassembler::AppendAddressToOutput(const Instruction *instr,
                                         const void *addr) {
  USE(instr);
  AppendToOutput("(addr 0x%" PRIxPTR ")", reinterpret_cast<uintptr_t>(addr));
}

void Disassembler::AppendCodeAddressToOutput(const Instruction *instr,
                                             const void *addr) {
  AppendAddressToOutput(instr, addr);
}

void Disassembler::AppendDataAddressToOutput(const Instruction *instr,
                                             const void *addr) {
  AppendAddressToOutput(instr, addr);
}

void Disassembler::AppendCodeRelativeAddressToOutput(const Instruction *instr,
                                                     const void *addr) {
  USE(instr);
  int64_t rel_addr = CodeRelativeAddress(addr);
  if (rel_addr >= 0) {
    AppendToOutput("(addr 0x%" PRIx64 ")", rel_addr);
  } else {
    AppendToOutput("(addr -0x%" PRIx64 ")", -rel_addr);
  }
}

void Disassembler::AppendCodeRelativeCodeAddressToOutput(
    const Instruction *instr, const void *addr) {
  AppendCodeRelativeAddressToOutput(instr, addr);
}

void Disassembler::AppendCodeRelativeDataAddressToOutput(
    const Instruction *instr, const void *addr) {
  AppendCodeRelativeAddressToOutput(instr, addr);
}

void Disassembler::MapCodeAddress(int64_t base_address,
                                  const Instruction *instr_address) {
  set_code_address_offset(base_address -
                          reinterpret_cast<intptr_t>(instr_address));
}
int64_t Disassembler::CodeRelativeAddress(const void *addr) {
  return reinterpret_cast<intptr_t>(addr) + code_address_offset();
}

void Disassembler::Format(const Instruction *instr,
                          const char *mnemonic,
                          const char *format0,
                          const char *format1) {
  if ((mnemonic == NULL) || (format0 == NULL)) {
    VisitUnallocated(instr);
  } else {
    ResetOutput();
    Substitute(instr, mnemonic);
    if (format0[0] != 0) {  // Not a zero-length string.
      VIXL_ASSERT(buffer_pos_ < buffer_size_);
      buffer_[buffer_pos_++] = ' ';
      int chars_written = Substitute(instr, format0);
      // TODO: consider using a zero-length string here, too.
      if (format1 != NULL) {
        chars_written += Substitute(instr, format1);
      }

      if (chars_written == 0) {
        // Erase the space written earlier, as there are no arguments to the
        // instruction.
        buffer_pos_--;
      }
    }
    VIXL_ASSERT(buffer_pos_ < buffer_size_);
    buffer_[buffer_pos_] = 0;
    ProcessOutput(instr);
  }
}

void Disassembler::FormatWithDecodedMnemonic(const Instruction *instr,
                                             const char *format0,
                                             const char *format1) {
  Format(instr, mnemonic_.c_str(), format0, format1);
}

int Disassembler::Substitute(const Instruction *instr, const char *string) {
  uint32_t buffer_pos_init = buffer_pos_;
  char chr = *string++;
  while (chr != '\0') {
    if (chr == '\'') {
      int offset = SubstituteField(instr, string);
      if (offset == 0) break;
      string += offset;
    } else {
      VIXL_ASSERT(buffer_pos_ < buffer_size_);
      buffer_[buffer_pos_++] = chr;
    }
    chr = *string++;
  }
  return static_cast<int>(buffer_pos_ - buffer_pos_init);
}

int Disassembler::SubstituteField(const Instruction *instr,
                                  const char *format) {
  switch (format[0]) {
    // NB. The remaining substitution prefix upper-case characters are: JU.
    case 'R':  // Register. X or W, selected by sf (or alternative) bit.
    case 'F':  // FP register. S or D, selected by type field.
    case 'V':  // Vector register, V, vector format.
    case 'Z':  // Scalable vector register.
    case 'W':
    case 'X':
    case 'B':
    case 'H':
    case 'S':
    case 'D':
    case 'Q':
      return SubstituteRegisterField(instr, format);
    case 'P':
      return SubstitutePredicateRegisterField(instr, format);
    case 'I':
      return SubstituteImmediateField(instr, format);
    case 'L':
      return SubstituteLiteralField(instr, format);
    case 'N':
      return SubstituteShiftField(instr, format);
    case 'C':
      return SubstituteConditionField(instr, format);
    case 'E':
      return SubstituteExtendField(instr, format);
    case 'A':
      return SubstitutePCRelAddressField(instr, format);
    case 'T':
      return SubstituteBranchTargetField(instr, format);
    case 'O':
      return SubstituteLSRegOffsetField(instr, format);
    case 'M':
      return SubstituteBarrierField(instr, format);
    case 'K':
      return SubstituteCrField(instr, format);
    case 'G':
      return SubstituteSysOpField(instr, format);
    case 'p':
      return SubstitutePrefetchField(instr, format);
    case 'u':
    case 's':
    case 'x':
      return SubstituteIntField(instr, format);
    case 't':
      return SubstituteSVESize(instr, format);
    case '?':
      return SubstituteTernary(instr, format);
    case '(':
      return SubstituteConditionalBlock(instr, format);
    case '{':
      return SubstituteGeneric(instr, format);
    case '$':
      return SubstituteEnd(instr, format);
    default: {
      VIXL_UNREACHABLE();
      return 1;
    }
  }
}

std::pair<unsigned, unsigned> Disassembler::GetRegNumForField(
    const Instruction *instr, char reg_prefix, const char *field) {
  unsigned reg_num = UINT_MAX;
  unsigned field_len = 1;

  switch (field[0]) {
    case 'd':
      reg_num = instr->GetRd();
      break;
    case 'n':
      reg_num = instr->GetRn();
      break;
    case 'm':
      reg_num = instr->GetRm();
      break;
    case 'e':
      // This is register Rm, but using a 4-bit specifier. Used in NEON
      // by-element instructions.
      reg_num = instr->GetRmLow16();
      break;
    case 'f':
      // This is register Rm, but using an element size dependent number of bits
      // in the register specifier.
      reg_num =
          (instr->GetNEONSize() < 2) ? instr->GetRmLow16() : instr->GetRm();
      break;
    case 'a':
      reg_num = instr->GetRa();
      break;
    case 's':
      reg_num = instr->GetRs();
      break;
    case 't':
      reg_num = instr->GetRt();
      break;
    default:
      VIXL_UNREACHABLE();
  }

  switch (field[1]) {
    case '2':
    case '3':
    case '4':
      if ((reg_prefix == 'V') || (reg_prefix == 'Z')) {  // t2/3/4, n2/3/4
        VIXL_ASSERT((field[0] == 't') || (field[0] == 'n'));
        reg_num = (reg_num + field[1] - '1') % 32;
        field_len++;
      } else {
        VIXL_ASSERT((field[0] == 't') && (field[1] == '2'));
        reg_num = instr->GetRt2();
        field_len++;
      }
      break;
    case '+':  // Rt+, Rs+ (ie. Rt + 1, Rs + 1)
      VIXL_ASSERT((reg_prefix == 'W') || (reg_prefix == 'X'));
      VIXL_ASSERT((field[0] == 's') || (field[0] == 't'));
      reg_num++;
      field_len++;
      break;
    case 's':  // Core registers that are (w)sp rather than zr.
      VIXL_ASSERT((reg_prefix == 'W') || (reg_prefix == 'X'));
      reg_num = (reg_num == kZeroRegCode) ? kSPRegInternalCode : reg_num;
      field_len++;
      break;
  }

  VIXL_ASSERT(reg_num != UINT_MAX);
  return std::make_pair(reg_num, field_len);
}

int Disassembler::SubstituteRegisterField(const Instruction *instr,
                                          const char *format) {
  unsigned field_len = 1;  // Initially, count only the first character.

  // The first character of the register format field, eg R, X, S, etc.
  char reg_prefix = format[0];

  // Pointer to the character after the prefix. This may be one of the standard
  // symbols representing a register encoding, or a two digit bit position,
  // handled by the following code.
  const char *reg_field = &format[1];

  if (reg_prefix == 'R') {
    bool is_x = instr->GetSixtyFourBits() == 1;
    if (strspn(reg_field, "0123456789") == 2) {  // r20d, r31n, etc.
      // Core W or X registers where the type is determined by a specified bit
      // position, eg. 'R20d, 'R05n. This is like the 'Rd syntax, where bit 31
      // is implicitly used to select between W and X.
      int bitpos = ((reg_field[0] - '0') * 10) + (reg_field[1] - '0');
      VIXL_ASSERT(bitpos <= 31);
      is_x = (instr->ExtractBit(bitpos) == 1);
      reg_field = &format[3];
      field_len += 2;
    }
    reg_prefix = is_x ? 'X' : 'W';
  }

  std::pair<unsigned, unsigned> rn =
      GetRegNumForField(instr, reg_prefix, reg_field);
  unsigned reg_num = rn.first;
  field_len += rn.second;

  if (reg_field[0] == 'm') {
    switch (reg_field[1]) {
      // Handle registers tagged with b (bytes), z (instruction), or
      // r (registers), used for address updates in NEON load/store
      // instructions.
      case 'r':
      case 'b':
      case 'z': {
        VIXL_ASSERT(reg_prefix == 'X');
        field_len = 3;
        char *eimm;
        int imm = static_cast<int>(strtol(&reg_field[2], &eimm, 10));
        field_len += static_cast<unsigned>(eimm - &reg_field[2]);
        if (reg_num == 31) {
          switch (reg_field[1]) {
            case 'z':
              imm *= (1 << instr->GetNEONLSSize());
              break;
            case 'r':
              imm *= (instr->GetNEONQ() == 0) ? kDRegSizeInBytes
                                              : kQRegSizeInBytes;
              break;
            case 'b':
              break;
          }
          AppendToOutput("#%d", imm);
          return field_len;
        }
        break;
      }
    }
  }

  CPURegister::RegisterType reg_type = CPURegister::kRegister;
  unsigned reg_size = kXRegSize;

  if (reg_prefix == 'F') {
    switch (instr->GetFPType()) {
      case 3:
        reg_prefix = 'H';
        break;
      case 0:
        reg_prefix = 'S';
        break;
      default:
        reg_prefix = 'D';
    }
  }

  switch (reg_prefix) {
    case 'W':
      reg_type = CPURegister::kRegister;
      reg_size = kWRegSize;
      break;
    case 'X':
      reg_type = CPURegister::kRegister;
      reg_size = kXRegSize;
      break;
    case 'B':
      reg_type = CPURegister::kVRegister;
      reg_size = kBRegSize;
      break;
    case 'H':
      reg_type = CPURegister::kVRegister;
      reg_size = kHRegSize;
      break;
    case 'S':
      reg_type = CPURegister::kVRegister;
      reg_size = kSRegSize;
      break;
    case 'D':
      reg_type = CPURegister::kVRegister;
      reg_size = kDRegSize;
      break;
    case 'Q':
      reg_type = CPURegister::kVRegister;
      reg_size = kQRegSize;
      break;
    case 'V':
      if (reg_field[1] == 'v') {
        reg_type = CPURegister::kVRegister;
        reg_size = 1 << (instr->GetSVESize() + 3);
        field_len++;
        break;
      }
      AppendToOutput("v%d", reg_num);
      return field_len;
    case 'Z':
      AppendToOutput("z%d", reg_num);
      return field_len;
    default:
      VIXL_UNREACHABLE();
  }

  AppendRegisterNameToOutput(instr, CPURegister(reg_num, reg_size, reg_type));

  return field_len;
}

int Disassembler::SubstitutePredicateRegisterField(const Instruction *instr,
                                                   const char *format) {
  VIXL_ASSERT(format[0] == 'P');
  switch (format[1]) {
    // This field only supports P register that are always encoded in the same
    // position.
    case 'd':
    case 't':
      AppendToOutput("p%u", instr->GetPt());
      break;
    case 'n':
      AppendToOutput("p%u", instr->GetPn());
      break;
    case 'm':
      AppendToOutput("p%u", instr->GetPm());
      break;
    case 'g':
      VIXL_ASSERT(format[2] == 'l');
      AppendToOutput("p%u", instr->GetPgLow8());
      return 3;
    default:
      VIXL_UNREACHABLE();
  }
  return 2;
}

int Disassembler::SubstituteImmediateField(const Instruction *instr,
                                           const char *format) {
  VIXL_ASSERT(format[0] == 'I');

  switch (format[1]) {
    case 'M': {  // IMoveImm or IMoveNeg.
      VIXL_ASSERT((format[5] == 'I') || (format[5] == 'N'));
      uint64_t imm = static_cast<uint64_t>(instr->GetImmMoveWide())
                     << (16 * instr->GetShiftMoveWide());
      if (format[5] == 'N') imm = ~imm;
      if (!instr->GetSixtyFourBits()) imm &= UINT64_C(0xffffffff);
      AppendToOutput("#0x%" PRIx64, imm);
      return 8;
    }
    case 'L': {
      switch (format[2]) {
        case 'L': {  // ILLiteral - Immediate Load Literal.
          AppendToOutput("pc%+" PRId32,
                         instr->GetImmLLiteral() *
                             static_cast<int>(kLiteralEntrySize));
          return 9;
        }
        case 'U': {  // ILU - Immediate Load/Store Unsigned.
          if (instr->GetImmLSUnsigned() != 0) {
            int shift = instr->GetSizeLS();
            AppendToOutput(", #%" PRId32, instr->GetImmLSUnsigned() << shift);
          }
          return 3;
        }
        case 'A': {  // ILA - Immediate Load with pointer authentication.
          if (instr->GetImmLSPAC() != 0) {
            AppendToOutput(", #%" PRId32, instr->GetImmLSPAC());
          }
          return 3;
        }
        default: {
          VIXL_UNIMPLEMENTED();
          return 0;
        }
      }
    }
    case 'A': {  // IAddSub.
      int64_t imm = instr->GetImmAddSub() << (12 * instr->GetImmAddSubShift());
      AppendToOutput("#0x%" PRIx64 " (%" PRId64 ")", imm, imm);
      return 7;
    }
    case 'F': {  // IFP, IFPNeon, IFPSve or IFPFBits.
      int imm8 = 0;
      size_t len = strlen("IFP");
      switch (format[3]) {
        case 'F':
          VIXL_ASSERT(strncmp(format, "IFPFBits", strlen("IFPFBits")) == 0);
          AppendToOutput("#%" PRId32, 64 - instr->GetFPScale());
          return static_cast<int>(strlen("IFPFBits"));
        case 'N':
          VIXL_ASSERT(strncmp(format, "IFPNeon", strlen("IFPNeon")) == 0);
          imm8 = instr->GetImmNEONabcdefgh();
          len += strlen("Neon");
          break;
        case 'S':
          VIXL_ASSERT(strncmp(format, "IFPSve", strlen("IFPSve")) == 0);
          imm8 = instr->ExtractBits(12, 5);
          len += strlen("Sve");
          break;
        default:
          VIXL_ASSERT(strncmp(format, "IFP", strlen("IFP")) == 0);
          imm8 = instr->GetImmFP();
          break;
      }
      AppendToOutput("#0x%" PRIx32 " (%.4f)",
                     imm8,
                     Instruction::Imm8ToFP32(imm8));
      return static_cast<int>(len);
    }
    case 'T': {  // ITri - Immediate Triangular Encoded.
      if (format[4] == 'S') {
        VIXL_ASSERT((format[5] == 'v') && (format[6] == 'e'));
        switch (format[7]) {
          case 'l':
            // SVE logical immediate encoding.
            AppendToOutput("#0x%" PRIx64, instr->GetSVEImmLogical());
            return 8;
          case 'p': {
            // SVE predicated shift immediate encoding, lsl.
            std::pair<int, int> shift_and_lane_size =
                instr->GetSVEImmShiftAndLaneSizeLog2(
                    /* is_predicated = */ true);
            int lane_bits = 8 << shift_and_lane_size.second;
            AppendToOutput("#%" PRId32, lane_bits - shift_and_lane_size.first);
            return 8;
          }
          case 'q': {
            // SVE predicated shift immediate encoding, asr and lsr.
            std::pair<int, int> shift_and_lane_size =
                instr->GetSVEImmShiftAndLaneSizeLog2(
                    /* is_predicated = */ true);
            AppendToOutput("#%" PRId32, shift_and_lane_size.first);
            return 8;
          }
          case 'r': {
            // SVE unpredicated shift immediate encoding, left shifts.
            std::pair<int, int> shift_and_lane_size =
                instr->GetSVEImmShiftAndLaneSizeLog2(
                    /* is_predicated = */ false);
            int lane_bits = 8 << shift_and_lane_size.second;
            AppendToOutput("#%" PRId32, lane_bits - shift_and_lane_size.first);
            return 8;
          }
          case 's': {
            // SVE unpredicated shift immediate encoding, right shifts.
            std::pair<int, int> shift_and_lane_size =
                instr->GetSVEImmShiftAndLaneSizeLog2(
                    /* is_predicated = */ false);
            AppendToOutput("#%" PRId32, shift_and_lane_size.first);
            return 8;
          }
          default:
            VIXL_UNREACHABLE();
            return 0;
        }
      } else {
        AppendToOutput("#0x%" PRIx64, instr->GetImmLogical());
        return 4;
      }
    }
    case 'N': {  // INzcv.
      int nzcv = (instr->GetNzcv() << Flags_offset);
      AppendToOutput("#%c%c%c%c",
                     ((nzcv & NFlag) == 0) ? 'n' : 'N',
                     ((nzcv & ZFlag) == 0) ? 'z' : 'Z',
                     ((nzcv & CFlag) == 0) ? 'c' : 'C',
                     ((nzcv & VFlag) == 0) ? 'v' : 'V');
      return 5;
    }
    case 'B': {  // Bitfields.
      return SubstituteBitfieldImmediateField(instr, format);
    }
    case 's': {  // Is - Shift (immediate).
      switch (format[2]) {
        case 'R': {  // IsR - right shifts.
          int shift = 16 << HighestSetBitPosition(instr->GetImmNEONImmh());
          shift -= instr->GetImmNEONImmhImmb();
          AppendToOutput("#%d", shift);
          return 3;
        }
        case 'L': {  // IsL - left shifts.
          int shift = instr->GetImmNEONImmhImmb();
          shift -= 8 << HighestSetBitPosition(instr->GetImmNEONImmh());
          AppendToOutput("#%d", shift);
          return 3;
        }
        default: {
          VIXL_UNIMPLEMENTED();
          return 0;
        }
      }
    }
    case 'V': {  // Immediate Vector.
      switch (format[2]) {
        case 'B': {  // IVByElemIndex.
          int ret = static_cast<int>(strlen("IVByElemIndex"));
          uint32_t vm_index = instr->GetNEONH() << 2;
          vm_index |= instr->GetNEONL() << 1;
          vm_index |= instr->GetNEONM();

          static const char *format_rot = "IVByElemIndexRot";
          static const char *format_fhm = "IVByElemIndexFHM";
          if (strncmp(format, format_rot, strlen(format_rot)) == 0) {
            // FCMLA uses 'H' bit index when SIZE is 2, else H:L
            VIXL_ASSERT((instr->GetNEONSize() == 1) ||
                        (instr->GetNEONSize() == 2));
            vm_index >>= instr->GetNEONSize();
            ret = static_cast<int>(strlen(format_rot));
          } else if (strncmp(format, format_fhm, strlen(format_fhm)) == 0) {
            // Nothing to do - FMLAL and FMLSL use H:L:M.
            ret = static_cast<int>(strlen(format_fhm));
          } else {
            if (instr->GetNEONSize() == 2) {
              // S-sized elements use H:L.
              vm_index >>= 1;
            } else if (instr->GetNEONSize() == 3) {
              // D-sized elements use H.
              vm_index >>= 2;
            }
          }
          AppendToOutput("%d", vm_index);
          return ret;
        }
        case 'I': {  // INS element.
          if (strncmp(format, "IVInsIndex", strlen("IVInsIndex")) == 0) {
            unsigned rd_index, rn_index;
            unsigned imm5 = instr->GetImmNEON5();
            unsigned imm4 = instr->GetImmNEON4();
            int tz = CountTrailingZeros(imm5, 32);
            if (tz <= 3) {  // Defined for tz = 0 to 3 only.
              rd_index = imm5 >> (tz + 1);
              rn_index = imm4 >> tz;
              if (strncmp(format, "IVInsIndex1", strlen("IVInsIndex1")) == 0) {
                AppendToOutput("%d", rd_index);
                return static_cast<int>(strlen("IVInsIndex1"));
              } else if (strncmp(format,
                                 "IVInsIndex2",
                                 strlen("IVInsIndex2")) == 0) {
                AppendToOutput("%d", rn_index);
                return static_cast<int>(strlen("IVInsIndex2"));
              }
            }
            return 0;
          } else if (strncmp(format,
                             "IVInsSVEIndex",
                             strlen("IVInsSVEIndex")) == 0) {
            std::pair<int, int> index_and_lane_size =
                instr->GetSVEPermuteIndexAndLaneSizeLog2();
            AppendToOutput("%d", index_and_lane_size.first);
            return static_cast<int>(strlen("IVInsSVEIndex"));
          }
          VIXL_FALLTHROUGH();
        }
        case 'M': {  // Modified Immediate cases.
          if (strncmp(format, "IVMIImm", strlen("IVMIImm")) == 0) {
            uint64_t imm8 = instr->GetImmNEONabcdefgh();
            uint64_t imm = 0;
            for (int i = 0; i < 8; ++i) {
              if (imm8 & (UINT64_C(1) << i)) {
                imm |= (UINT64_C(0xff) << (8 * i));
              }
            }
            AppendToOutput("#0x%" PRIx64, imm);
            return static_cast<int>(strlen("IVMIImm"));
          } else {
            VIXL_UNIMPLEMENTED();
            return 0;
          }
        }
        default: {
          VIXL_UNIMPLEMENTED();
          return 0;
        }
      }
    }
    case 'Y': {  // IY - system register immediate.
      switch (instr->GetImmSystemRegister()) {
        case NZCV:
          AppendToOutput("nzcv");
          break;
        case FPCR:
          AppendToOutput("fpcr");
          break;
        case RNDR:
          AppendToOutput("rndr");
          break;
        case RNDRRS:
          AppendToOutput("rndrrs");
          break;
        case DCZID_EL0:
          AppendToOutput("dczid_el0");
          break;
        default:
          AppendToOutput("S%d_%d_c%d_c%d_%d",
                         instr->GetSysOp0(),
                         instr->GetSysOp1(),
                         instr->GetCRn(),
                         instr->GetCRm(),
                         instr->GetSysOp2());
          break;
      }
      return 2;
    }
    case 'p': {  // Ipc - SVE predicate constraint specifier.
      VIXL_ASSERT(format[2] == 'c');
      unsigned pattern = instr->GetImmSVEPredicateConstraint();
      switch (pattern) {
        // VL1-VL8 are encoded directly.
        case SVE_VL1:
        case SVE_VL2:
        case SVE_VL3:
        case SVE_VL4:
        case SVE_VL5:
        case SVE_VL6:
        case SVE_VL7:
        case SVE_VL8:
          AppendToOutput("vl%u", pattern);
          break;
        // VL16-VL256 are encoded as log2(N) + c.
        case SVE_VL16:
        case SVE_VL32:
        case SVE_VL64:
        case SVE_VL128:
        case SVE_VL256:
          AppendToOutput("vl%u", 16 << (pattern - SVE_VL16));
          break;
        // Special cases.
        case SVE_POW2:
          AppendToOutput("pow2");
          break;
        case SVE_MUL4:
          AppendToOutput("mul4");
          break;
        case SVE_MUL3:
          AppendToOutput("mul3");
          break;
        case SVE_ALL:
          AppendToOutput("all");
          break;
        default:
          AppendToOutput("#0x%x", pattern);
          break;
      }
      return 3;
    }
    default: {
      VIXL_UNIMPLEMENTED();
      return 0;
    }
  }
}

int Disassembler::SubstituteBitfieldImmediateField(const Instruction *instr,
                                                   const char *format) {
  VIXL_ASSERT((format[0] == 'I') && (format[1] == 'B'));
  unsigned r = instr->GetImmR();
  unsigned s = instr->GetImmS();

  switch (format[2]) {
    case 's':  // IBs-r+1.
      VIXL_ASSERT(format[3] == '-');
      AppendToOutput("#%d", s - r + 1);
      return 7;
    case 'Z': {  // IBZ-r.
      VIXL_ASSERT((format[3] == '-') && (format[4] == 'r'));
      unsigned reg_size =
          (instr->GetSixtyFourBits() == 1) ? kXRegSize : kWRegSize;
      AppendToOutput("#%d", reg_size - r);
      return 5;
    }
    default: {
      VIXL_UNREACHABLE();
      return 0;
    }
  }
}

int Disassembler::SubstituteLiteralField(const Instruction *instr,
                                         const char *format) {
  VIXL_ASSERT(strncmp(format, "LValue", 6) == 0);
  USE(format);

  const void *address = instr->GetLiteralAddress<const void *>();
  switch (instr->Mask(LoadLiteralMask)) {
    case LDR_w_lit:
    case LDR_x_lit:
    case LDRSW_x_lit:
    case LDR_s_lit:
    case LDR_d_lit:
    case LDR_q_lit:
      AppendCodeRelativeDataAddressToOutput(instr, address);
      break;
    case PRFM_lit: {
      // Use the prefetch hint to decide how to print the address.
      switch (instr->GetPrefetchHint()) {
        case 0x0:  // PLD: prefetch for load.
        case 0x2:  // PST: prepare for store.
          AppendCodeRelativeDataAddressToOutput(instr, address);
          break;
        case 0x1:  // PLI: preload instructions.
          AppendCodeRelativeCodeAddressToOutput(instr, address);
          break;
        case 0x3:  // Unallocated hint.
          AppendCodeRelativeAddressToOutput(instr, address);
          break;
      }
      break;
    }
    default:
      VIXL_UNREACHABLE();
  }

  return 6;
}

int Disassembler::SubstituteShiftField(const Instruction *instr,
                                       const char *format) {
  VIXL_ASSERT(format[0] == 'N');
  VIXL_ASSERT(instr->GetShiftDP() <= 0x3);

  switch (format[1]) {
    case 'D': {  // NDP.
      VIXL_ASSERT(instr->GetShiftDP() != ROR);
      VIXL_FALLTHROUGH();
    }
    case 'L': {  // NLo.
      if (instr->GetImmDPShift() != 0) {
        const char *shift_type[] = {"lsl", "lsr", "asr", "ror"};
        AppendToOutput(", %s #%" PRId32,
                       shift_type[instr->GetShiftDP()],
                       instr->GetImmDPShift());
      }
      return 3;
    }
    default:
      VIXL_UNIMPLEMENTED();
      return 0;
  }
}

int Disassembler::SubstituteConditionField(const Instruction *instr,
                                           const char *format) {
  VIXL_ASSERT(format[0] == 'C');
  const char *condition_code[] = {"eq",
                                  "ne",
                                  "hs",
                                  "lo",
                                  "mi",
                                  "pl",
                                  "vs",
                                  "vc",
                                  "hi",
                                  "ls",
                                  "ge",
                                  "lt",
                                  "gt",
                                  "le",
                                  "al",
                                  "nv"};
  int cond;
  switch (format[1]) {
    case 'B':
      cond = instr->GetConditionBranch();
      break;
    case 'I': {
      cond = InvertCondition(static_cast<Condition>(instr->GetCondition()));
      break;
    }
    default:
      cond = instr->GetCondition();
  }
  AppendToOutput("%s", condition_code[cond]);
  return 4;
}

int Disassembler::SubstitutePCRelAddressField(const Instruction *instr,
                                              const char *format) {
  VIXL_ASSERT((strcmp(format, "AddrPCRelByte") == 0) ||  // Used by `adr`.
              (strcmp(format, "AddrPCRelPage") == 0));   // Used by `adrp`.

  int64_t offset = instr->GetImmPCRel();

  // Compute the target address based on the effective address (after applying
  // code_address_offset). This is required for correct behaviour of adrp.
  const Instruction *base = instr + code_address_offset();
  if (format[9] == 'P') {
    offset *= kPageSize;
    base = AlignDown(base, kPageSize);
  }
  // Strip code_address_offset before printing, so we can use the
  // semantically-correct AppendCodeRelativeAddressToOutput.
  const void *target =
      reinterpret_cast<const void *>(base + offset - code_address_offset());

  AppendPCRelativeOffsetToOutput(instr, offset);
  AppendToOutput(" ");
  AppendCodeRelativeAddressToOutput(instr, target);
  return 13;
}

int Disassembler::SubstituteBranchTargetField(const Instruction *instr,
                                              const char *format) {
  VIXL_ASSERT(strncmp(format, "TImm", 4) == 0);

  int64_t offset = 0;
  switch (format[5]) {
    // BImmUncn - unconditional branch immediate.
    case 'n':
      offset = instr->GetImmUncondBranch();
      break;
    // BImmCond - conditional branch immediate.
    case 'o':
      offset = instr->GetImmCondBranch();
      break;
    // BImmCmpa - compare and branch immediate.
    case 'm':
      offset = instr->GetImmCmpBranch();
      break;
    // BImmTest - test and branch immediate.
    case 'e':
      offset = instr->GetImmTestBranch();
      break;
    default:
      VIXL_UNIMPLEMENTED();
  }
  offset *= static_cast<int>(kInstructionSize);
  const void *target_address = reinterpret_cast<const void *>(instr + offset);
  VIXL_STATIC_ASSERT(sizeof(*instr) == 1);

  AppendPCRelativeOffsetToOutput(instr, offset);
  AppendToOutput(" ");
  AppendCodeRelativeCodeAddressToOutput(instr, target_address);

  return 8;
}

int Disassembler::SubstituteExtendField(const Instruction *instr,
                                        const char *format) {
  VIXL_ASSERT(strncmp(format, "Ext", 3) == 0);
  VIXL_ASSERT(instr->GetExtendMode() <= 7);
  USE(format);

  const char *extend_mode[] =
      {"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};

  // If rd or rn is SP, uxtw on 32-bit registers and uxtx on 64-bit
  // registers becomes lsl.
  if (((instr->GetRd() == kZeroRegCode) || (instr->GetRn() == kZeroRegCode)) &&
      (((instr->GetExtendMode() == UXTW) && (instr->GetSixtyFourBits() == 0)) ||
       (instr->GetExtendMode() == UXTX))) {
    if (instr->GetImmExtendShift() > 0) {
      AppendToOutput(", lsl #%" PRId32, instr->GetImmExtendShift());
    }
  } else {
    AppendToOutput(", %s", extend_mode[instr->GetExtendMode()]);
    if (instr->GetImmExtendShift() > 0) {
      AppendToOutput(" #%" PRId32, instr->GetImmExtendShift());
    }
  }
  return 3;
}

int Disassembler::SubstituteLSRegOffsetField(const Instruction *instr,
                                             const char *format) {
  VIXL_ASSERT(strncmp(format, "Offsetreg", 9) == 0);
  const char *extend_mode[] = {"undefined",
                               "undefined",
                               "uxtw",
                               "lsl",
                               "undefined",
                               "undefined",
                               "sxtw",
                               "sxtx"};
  USE(format);

  unsigned shift = instr->GetImmShiftLS();
  Extend ext = static_cast<Extend>(instr->GetExtendMode());
  char reg_type = ((ext == UXTW) || (ext == SXTW)) ? 'w' : 'x';

  unsigned rm = instr->GetRm();
  if (rm == kZeroRegCode) {
    AppendToOutput("%czr", reg_type);
  } else {
    AppendToOutput("%c%d", reg_type, rm);
  }

  // Extend mode UXTX is an alias for shift mode LSL here.
  if (!((ext == UXTX) && (shift == 0))) {
    AppendToOutput(", %s", extend_mode[ext]);
    if (shift != 0) {
      AppendToOutput(" #%d", instr->GetSizeLS());
    }
  }
  return 9;
}

int Disassembler::SubstitutePrefetchField(const Instruction *instr,
                                          const char *format) {
  VIXL_ASSERT(format[0] == 'p');
  USE(format);

  bool is_sve =
      (strncmp(format, "prefSVEOp", strlen("prefSVEOp")) == 0) ? true : false;
  int placeholder_length = is_sve ? 9 : 6;
  static const char *stream_options[] = {"keep", "strm"};

  auto get_hints = [](bool want_sve_hint) -> std::vector<std::string> {
    static const std::vector<std::string> sve_hints = {"ld", "st"};
    static const std::vector<std::string> core_hints = {"ld", "li", "st"};
    return (want_sve_hint) ? sve_hints : core_hints;
  };

  std::vector<std::string> hints = get_hints(is_sve);
  unsigned hint =
      is_sve ? instr->GetSVEPrefetchHint() : instr->GetPrefetchHint();
  unsigned target = instr->GetPrefetchTarget() + 1;
  unsigned stream = instr->GetPrefetchStream();

  if ((hint >= hints.size()) || (target > 3)) {
    // Unallocated prefetch operations.
    if (is_sve) {
      std::bitset<4> prefetch_mode(instr->GetSVEImmPrefetchOperation());
      AppendToOutput("#0b%s", prefetch_mode.to_string().c_str());
    } else {
      std::bitset<5> prefetch_mode(instr->GetImmPrefetchOperation());
      AppendToOutput("#0b%s", prefetch_mode.to_string().c_str());
    }
  } else {
    VIXL_ASSERT(stream < ArrayLength(stream_options));
    AppendToOutput("p%sl%d%s",
                   hints[hint].c_str(),
                   target,
                   stream_options[stream]);
  }
  return placeholder_length;
}

int Disassembler::SubstituteBarrierField(const Instruction *instr,
                                         const char *format) {
  VIXL_ASSERT(format[0] == 'M');
  USE(format);

  static const char *options[4][4] = {{"sy (0b0000)", "oshld", "oshst", "osh"},
                                      {"sy (0b0100)", "nshld", "nshst", "nsh"},
                                      {"sy (0b1000)", "ishld", "ishst", "ish"},
                                      {"sy (0b1100)", "ld", "st", "sy"}};
  int domain = instr->GetImmBarrierDomain();
  int type = instr->GetImmBarrierType();

  AppendToOutput("%s", options[domain][type]);
  return 1;
}

int Disassembler::SubstituteSysOpField(const Instruction *instr,
                                       const char *format) {
  VIXL_ASSERT(format[0] == 'G');
  int op = -1;
  switch (format[1]) {
    case '1':
      op = instr->GetSysOp1();
      break;
    case '2':
      op = instr->GetSysOp2();
      break;
    default:
      VIXL_UNREACHABLE();
  }
  AppendToOutput("#%d", op);
  return 2;
}

int Disassembler::SubstituteCrField(const Instruction *instr,
                                    const char *format) {
  VIXL_ASSERT(format[0] == 'K');
  int cr = -1;
  switch (format[1]) {
    case 'n':
      cr = instr->GetCRn();
      break;
    case 'm':
      cr = instr->GetCRm();
      break;
    default:
      VIXL_UNREACHABLE();
  }
  AppendToOutput("C%d", cr);
  return 2;
}

int BitPositionFromString(const char *c) {
  VIXL_ASSERT(strspn(c, "0123456789") >= 2);
  int pos = ((c[0] - '0') * 10) + (c[1] - '0');
  VIXL_ASSERT(pos <= 31);
  return pos;
}

int Disassembler::SubstituteIntField(const Instruction *instr,
                                     const char *format) {
  VIXL_ASSERT((format[0] == 'u') || (format[0] == 's') || (format[0] == 'x'));

  // A generic signed or unsigned int field uses a placeholder of the form
  // 'sAABB and 'uAABB respectively where AA and BB are two digit bit positions
  // between 00 and 31, and AA >= BB. The placeholder is substituted with the
  // decimal integer represented by the bits in the instruction between
  // positions AA and BB inclusive.
  //
  // In addition, split fields can be represented using 'sAABB_CCDD, where CCDD
  // become the least-significant bits of the result, and bit AA is the sign bit
  // (if 's is used).
  //
  // For unsigned fields, 'u may be replaced with 'x to substitute the
  // hexadecimal representation instead of a decimal.
  int32_t bits = 0;
  int width = 0;
  const char *c = format;
  do {
    c++;  // Skip the 'u', 's', 'x' or '_'.
    VIXL_ASSERT(strspn(c, "0123456789") == 4);
    int msb = BitPositionFromString(&c[0]);
    int lsb = BitPositionFromString(&c[2]);
    c += 4;  // Skip the characters we just read.
    int chunk_width = msb - lsb + 1;
    VIXL_ASSERT((chunk_width > 0) && (chunk_width < 32));
    bits = (bits << chunk_width) | (instr->ExtractBits(msb, lsb));
    width += chunk_width;
  } while (*c == '_');
  VIXL_ASSERT(IsUintN(width, bits));

  if (format[0] == 's') {
    bits = ExtractSignedBitfield32(width - 1, 0, bits);
  }

  if (*c == '+') {
    // A "+n" trailing the format specifier indicates the extracted value should
    // be incremented by n. This is for cases where the encoding is zero-based,
    // but range of values is not, eg. values [1, 16] encoded as [0, 15]
    char *new_c;
    uint64_t value = strtoul(c + 1, &new_c, 10);
    c = new_c;
    VIXL_ASSERT(IsInt32(value));
    bits = static_cast<int32_t>(bits + value);
  } else if (*c == '*') {
    // Similarly, a "*n" trailing the format specifier indicates the extracted
    // value should be multiplied by n. This is for cases where the encoded
    // immediate is scaled, for example by access size.
    char *new_c;
    uint64_t value = strtoul(c + 1, &new_c, 10);
    c = new_c;
    VIXL_ASSERT(IsInt32(value));
    bits = static_cast<int32_t>(bits * value);
  }

  AppendToOutput(format[0] == 'x' ? "%x" : "%d", bits);

  return static_cast<int>(c - format);
}

int Disassembler::SubstituteGeneric(const Instruction *instr,
                                    const char *format) {
  USE(instr);
  VIXL_ASSERT(format[0] == '{');
  const char *close = strchr(format, '}');
  VIXL_ASSERT(close != nullptr);
  int keylen = static_cast<int>(close - format - 1);
  std::string key(format, 1, keylen);

  struct SubstList {
    std::vector<int> bit_positions;
    std::vector<std::string> substitutions;
  };
  static const std::map<std::string, SubstList> subst = {
      {"n", {{30, 23, 22}, {"8b", "4h", "2s", "1d", "16b", "8h", "4s", "2d"}}},
      {"nl", {{23, 22}, {"8h", "4s", "2d", ""}}},
      {"nf", {{22, 30}, {"2s", "4s", "1d", "2d"}}},
      {"nload",
       {{30, 11, 10}, {"8b", "4h", "2s", "1d", "16b", "8h", "4s", "2d"}}},
      {"npair", {{30, 23, 22}, {"4h", "2s", "1d", "", "8h", "4s", "2d", ""}}},
      {"nscal", {{23, 22}, {"b", "h", "s", "d"}}},
      {"nscall", {{23, 22}, {"h", "s", "d", "q"}}},
      {"nshift",
       {{22, 21, 20, 19, 30},
        {"",   "",   "8b", "16b", "4h", "8h", "4h", "8h", "2s", "4s", "2s",
         "4s", "2s", "4s", "2s",  "4s", "",   "2d", "",   "2d", "",   "2d",
         "",   "2d", "",   "2d",  "",   "2d", "",   "2d", "",   "2d"}}},
      {"nshiftln",
       {{21, 20, 19}, {"", "8h", "4s", "4s", "2d", "2d", "2d", "2d"}}},
      {"nshiftscal",
       {{22, 21, 20, 19},
        {"",
         "b",
         "h",
         "h",
         "s",
         "s",
         "s",
         "s",
         "d",
         "d",
         "d",
         "d",
         "d",
         "d",
         "d",
         "d"}}},
      {"ntri",
       {{19, 18, 17, 16, 30},
        {"",   "",   "8b", "16b", "4h", "8h", "8b", "16b",
         "2s", "4s", "8b", "16b", "4h", "8h", "8b", "16b",
         "",   "2d", "8b", "16b", "4h", "8h", "8b", "16b",
         "2s", "4s", "8b", "16b", "4h", "8h", "8b", "16b"}}},
      {"ntriscal",
       {{19, 18, 17, 16},
        {"",
         "b",
         "h",
         "b",
         "s",
         "b",
         "h",
         "b",
         "d",
         "b",
         "h",
         "b",
         "s",
         "b",
         "h",
         "b"}}},
  };
  VIXL_ASSERT(subst.count(key) == 1);
  auto x = subst.at(key);
  int index = 0;
  for (auto b : x.bit_positions) {
    index <<= 1;
    index |= instr->ExtractBit(b);
  }
  AppendToOutput("%s", x.substitutions.at(index).c_str());
  return keylen + 2;  // +2 for the braces.
}

int Disassembler::SubstituteSVESize(const Instruction *instr,
                                    const char *format) {
  VIXL_ASSERT(format[0] == 't');

  static const char sizes[] = {'b', 'h', 's', 'd', 'q'};
  unsigned size_in_bytes_log2 = instr->GetSVESize();
  int placeholder_length = 1;
  switch (format[1]) {
    case 'f':  // 'tf - FP size encoded in <18:17>
      placeholder_length++;
      size_in_bytes_log2 = instr->ExtractBits(18, 17);
      break;
    case 'l':
      placeholder_length++;
      if (format[2] == 's') {
        // 'tls: Loads and stores
        size_in_bytes_log2 = instr->ExtractBits(22, 21);
        placeholder_length++;
        if (format[3] == 's') {
          // Sign extension load.
          unsigned msize = instr->ExtractBits(24, 23);
          if (msize > size_in_bytes_log2) size_in_bytes_log2 ^= 0x3;
          placeholder_length++;
        }
      } else {
        // 'tl: Logical operations
        size_in_bytes_log2 = instr->GetSVEBitwiseImmLaneSizeInBytesLog2();
      }
      break;
    case 'm':  // 'tmsz
      VIXL_ASSERT(strncmp(format, "tmsz", 4) == 0);
      placeholder_length += 3;
      size_in_bytes_log2 = instr->ExtractBits(24, 23);
      break;
    case 'i': {  // 'ti: indices.
      std::pair<int, int> index_and_lane_size =
          instr->GetSVEPermuteIndexAndLaneSizeLog2();
      placeholder_length++;
      size_in_bytes_log2 = index_and_lane_size.second;
      break;
    }
    case 's':
      if (format[2] == 'z') {
        VIXL_ASSERT((format[3] == 'p') || (format[3] == 's') ||
                    (format[3] == 'd'));
        bool is_predicated = (format[3] == 'p');
        std::pair<int, int> shift_and_lane_size =
            instr->GetSVEImmShiftAndLaneSizeLog2(is_predicated);
        size_in_bytes_log2 = shift_and_lane_size.second;
        if (format[3] == 'd') {  // Double size lanes.
          size_in_bytes_log2++;
        }
        placeholder_length += 3;  // skip "sz(p|s|d)"
      }
      break;
    case 'h':
      // Half size of the lane size field.
      size_in_bytes_log2 -= 1;
      placeholder_length++;
      break;
    case 'q':
      // Quarter size of the lane size field.
      size_in_bytes_log2 -= 2;
      placeholder_length++;
      break;
    default:
      break;
  }

  VIXL_ASSERT(size_in_bytes_log2 < ArrayLength(sizes));
  AppendToOutput("%c", sizes[size_in_bytes_log2]);

  return placeholder_length;
}

int Disassembler::SubstituteEnd(const Instruction *instr, const char *format) {
  USE(instr);
  USE(format);
  VIXL_ASSERT(format[0] == '$');
  AppendToOutput("%c", '\0');
  return 0;
}

int Disassembler::SubstituteTernary(const Instruction *instr,
                                    const char *format) {
  VIXL_ASSERT((format[0] == '?') && (format[3] == ':'));

  // The ternary substitution of the format "'?bb:TF" is replaced by a single
  // character, either T or F, depending on the value of the bit at position
  // bb in the instruction. For example, "'?31:xw" is substituted with "x" if
  // bit 31 is true, and "w" otherwise.
  VIXL_ASSERT(strspn(&format[1], "0123456789") == 2);
  char *c;
  uint64_t value = strtoul(&format[1], &c, 10);
  VIXL_ASSERT(value < (kInstructionSize * kBitsPerByte));
  VIXL_ASSERT((*c == ':') && (strlen(c) >= 3));  // Minimum of ":TF"
  c++;
  AppendToOutput("%c", c[1 - instr->ExtractBit(static_cast<int>(value))]);
  return 6;
}

int Disassembler::SubstituteConditionalBlock(const Instruction *instr,
                                             const char *format) {
  VIXL_ASSERT(strlen(format) >= 6);
  VIXL_ASSERT((format[0] == '(') &&
              (format[3] == '?' || format[5] == '?' || (format[5] == '=')));
  VIXL_ASSERT(strchr(format, ')') != nullptr);

  // A conditional block uses the placeholder '(AABB?xxx:yyyy)' where AA and
  // BB are two digit bit positions between 00 and 31, and AA >= BB. If the
  // bits of the instruction in the range AA to BB are non-zero, the placeholder
  // is substituted with the string represented by xxx, else yyyy. The strings
  // are of variable length and may contain other placeholders for further
  // substitutions. The ':yyyy' section may be omitted, implying a zero-length
  // string is substituted if instruction bits in the range AA to BB are zero.
  //
  // Alternatively, a specific value for the bits in the range AA to BB can
  // be specified using the placeholder '(AABB=zzz?xxx:yyyy)'. If the bits in
  // the range AA to BB are equal to zzz, xxx is substitued, else yyyy. As
  // above, :yyyy may be omitted.
  const char *c = &format[1];
  uint32_t bits = 0;
  uint64_t value = 0;
  bool use_explicit_value = false;
  int msb = BitPositionFromString(&c[0]);
  if ((format[5] == '?') || (format[5] == '=')) {  // Extract a range of bits.
    int lsb = BitPositionFromString(&c[2]);
    bits = instr->ExtractBits(msb, lsb);

    if (format[5] == '=') {
      use_explicit_value = true;
      char *temp;
      VIXL_ASSERT(strspn(&format[6], "0123456789") > 0);
      value = strtoul(&format[6], &temp, 10);
      c = temp;
    } else {
      c += 4;  // Skip the bit positions we read above.
    }
  } else {
    // Extract a single bit.
    VIXL_ASSERT(format[3] == '?');
    bits = instr->ExtractBit(msb);
    c += 2;
  }

  // Skip '?'
  VIXL_ASSERT(*c == '?');
  c++;

  char temp[256] = {0};
  const char *close = strchr(format, ')');
  size_t subst_len = close - c;
  VIXL_ASSERT(subst_len < sizeof(temp));

  // Copy the substitution string into a temporary buffer and set up pointers
  // for the left-hand (true) and right-hand (false) sides.
  memcpy(temp, c, subst_len);

  char *lhs = temp;
  char *rhs = nullptr;
  char *colon = strchr(temp, ':');
  if (colon != nullptr) {
    // If there's a colon, set it to zero to act as the terminator for the
    // left-hand string.
    *colon = 0;
    rhs = colon + 1;
  }

  bool use_lhs;
  if (use_explicit_value) {
    use_lhs = (bits == value);
  } else {
    use_lhs = (bits != 0);
  }

  char *subst = use_lhs ? lhs : rhs;
  if ((subst != nullptr) && (strlen(subst) > 0)) {
    Substitute(instr, subst);
  }

  return static_cast<int>(1 + close - format);
}

void Disassembler::ResetOutput() {
  buffer_pos_ = 0;
  buffer_[buffer_pos_] = 0;
}

void Disassembler::AppendToOutput(const char *format, ...) {
  va_list args;
  va_start(args, format);
  buffer_pos_ += vsnprintf(&buffer_[buffer_pos_],
                           buffer_size_ - buffer_pos_,
                           format,
                           args);
  va_end(args);
}

void PrintDisassembler::Disassemble(const Instruction *instr) {
  Decoder decoder;
  if (cpu_features_auditor_ != NULL) {
    decoder.AppendVisitor(cpu_features_auditor_);
  }
  decoder.AppendVisitor(this);
  decoder.Decode(instr);
}

void PrintDisassembler::DisassembleBuffer(const Instruction *start,
                                          const Instruction *end) {
  Decoder decoder;
  if (cpu_features_auditor_ != NULL) {
    decoder.AppendVisitor(cpu_features_auditor_);
  }
  decoder.AppendVisitor(this);
  decoder.Decode(start, end);
}

void PrintDisassembler::DisassembleBuffer(const Instruction *start,
                                          uint64_t size) {
  DisassembleBuffer(start, start + size);
}

void PrintDisassembler::ProcessOutput(const Instruction *instr) {
  int64_t address = CodeRelativeAddress(instr);

  uint64_t abs_address;
  const char *sign;
  if (signed_addresses_) {
    if (address < 0) {
      sign = "-";
      abs_address = UnsignedNegate(static_cast<uint64_t>(address));
    } else {
      // Leave a leading space, to maintain alignment.
      sign = " ";
      abs_address = address;
    }
  } else {
    sign = "";
    abs_address = address;
  }

  int bytes_printed = fprintf(stream_,
                              "%s0x%016" PRIx64 "  %08" PRIx32 "\t\t%s",
                              sign,
                              abs_address,
                              instr->GetInstructionBits(),
                              GetOutput());
  if (cpu_features_auditor_ != NULL) {
    CPUFeatures needs = cpu_features_auditor_->GetInstructionFeatures();
    needs.Remove(cpu_features_auditor_->GetAvailableFeatures());
    if (needs != CPUFeatures::None()) {
      // Try to align annotations. This value is arbitrary, but based on looking
      // good with most instructions. Note that, for historical reasons, the
      // disassembly itself is printed with tab characters, so bytes_printed is
      // _not_ equivalent to the number of occupied screen columns. However, the
      // prefix before the tabs is always the same length, so the annotation
      // indentation does not change from one line to the next.
      const int indent_to = 70;
      // Always allow some space between the instruction and the annotation.
      const int min_pad = 2;

      int pad = std::max(min_pad, (indent_to - bytes_printed));
      fprintf(stream_, "%*s", pad, "");

      std::stringstream features;
      features << needs;
      fprintf(stream_,
              "%s%s%s",
              cpu_features_prefix_,
              features.str().c_str(),
              cpu_features_suffix_);
    }
  }
  fprintf(stream_, "\n");
}

}  // namespace aarch64
}  // namespace vixl
