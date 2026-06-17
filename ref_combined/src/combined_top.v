// MIT License

// Copyright (c) 2025 KU Leuven - COSIC

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/*
 * From our research paper "High-Performance Hardware Implementation of CRYSTALS-Dilithium"
 * by Luke Beckwith, Duc Tri Nguyen, Kris Gaj
 * at George Mason University, USA
 * https://eprint.iacr.org/2021/1451.pdf
 * =============================================================================
 * Copyright (c) 2021 by Cryptographic Engineering Research Group (CERG)
 * ECE Department, George Mason University
 * Fairfax, VA, U.S.A.
 * Author: Luke Beckwith
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =============================================================================
 * @author   Luke Beckwith <lbeckwit@gmu.edu>
 */

`timescale 1ns / 1ps

module combined_top #(
    parameter BUS_W     = 4,
    parameter SAMPLE_W  = 23,
    parameter W         = 64
    ) (
    input clk,
    input rst,
    input start,
    input [1:0]        mode,
    input [2:0]        sec_lvl,
    input              valid_i,
    output reg         ready_i = 0,
    input [W-1:0]      data_i,
    output reg         valid_o = 0,
    input              ready_o,
    output reg [W-1:0] data_o = 0,
    // Diagnostic outputs (read-only, for debug)
    output [62:0]      diag
    );
    
    localparam
        KG_INIT        = 4'd0,
        KG_HASH_Z      = 4'd1,     
        KG_UNLOAD_HASH = 4'd2,
        KG_SAMPLE_S1   = 4'd3,
        KG_SAMPLE_S2   = 4'd4,
        KG_MULT_AS1    = 4'd5,
        KG_NTTI_T      = 4'd6,
        KG_ADD_T_S2    = 4'd7,
        KG_ENCODE_T0   = 4'd8,
        KG_UNLOAD_TR   = 4'd9,
        KG_ENCODE_T1   = 4'd10;
    
    localparam
        VY_INIT       = 5'd0,
        VY_LOAD_RHO   = 5'd1,
        VY_LOAD_C     = 5'd2,
        VY_DECODE_Z   = 5'd3,
        VY_NTT_Z      = 5'd4,
        VY_NTT_T1     = 5'd5, 
        VY_NTT_C      = 5'd6, 
        VY_MULT_AZ    = 5'd7,
        VY_MULT_CT1   = 5'd8,
        VY_SUB_AZ_CT1 = 5'd9,
        VY_INTT       = 5'd10,
        VY_GENW1      = 5'd11,
        VY_HASH_CH    = 5'd12,
        VY_COMPARE    = 5'd13;
    
    localparam
        FSM0_INIT      = 5'd0,
        FSM0_LOAD_RHO  = 5'd1,
        FSM0_LOAD_MU   = 5'd2,
        FSM0_DECODE_S1 = 5'd3,
        FSM0_NTT_S1   = 5'd4,
        FSM0_NTT_S2   = 5'd5,
        FSM0_NTT_T0   = 5'd6,
        FSM0_STALL    = 5'd7,
        FSM0_UNLOAD_Z = 5'd8,
        FSM0_UNLOAD_H = 5'd9,
        FSM0_UNLOAD_C = 5'd10;
    
    localparam
        FSM1_STALL    = 4'd0,
        FSM1_GENY     = 4'd1,
        FSM1_WAIT     = 4'd2,
        FSM1_NTT_Y    = 4'd3,
        FSM1_MULT_A_Y = 4'd4,
        FSM1_NTTI_W   = 4'd5;
        
    localparam
        FSM2_STALL   = 5'd0,
        FSM2_DECOMP  = 5'd1,
        FSM2_GEN_C   = 5'd2,
        FSM2_NTT_C   = 5'd3,
        FSM2_MULTACC = 5'd4,
        FSM2_MULT_CS2 = 5'd5,
        FSM2_MULT_CT0 = 5'd6,
        FSM2_NTTI_Z   = 5'd7,
        FSM2_NTTI_CS2 = 5'd8,
        FSM2_NTTI_CT0 = 5'd9,
        FSM2_SUB_W0_CS2 = 5'd10,
        FSM2_MAKEHINT   = 5'd11;
        
    reg [31:0] mlen;
    reg [31:0] mlen_PLUS48, mlen_PLUS64,mlen_PLUS80, mlen_PLUS112, mlen_PLUS128, mlen_PLUS144, mlen_PLUS152;
    reg [4:0] cstate0, nstate0;
    reg [4:0] cstate1, nstate1;
    reg [4:0] cstate2, nstate2;
    reg [10:0] ctr, ctr_next;
    reg [10:0] ctrfsm2, ctrfsm2_next;
    reg [10:0] ctrfsm1, ctrfsm1_next;
    
    reg [10:0] ctr0fsm2, ctr0fsm2_next;
    
    reg [512 - 1 : 0] C  = 0;
    reg [512 - 1 : 0] TR = 0;
    reg [255:0] RHO = 0;
    reg [511:0] MU = 0;
    
    reg fsm1_even, COMP_FAIL, fail;
    reg [63:0] dout_compare_diag;  // captures first dout[2] during VY_COMPARE
    reg [63:0] c_compare_diag;     // captures first C[383:320] during VY_COMPARE
    reg [63:0] tr_verify_diag;     // TR[511:448] after VY_NTT_Z completes
    reg [63:0] mu_verify_diag;     // MU[511:448] after VY_NTT_T1 completes
    reg [63:0] rho_verify_diag;    // RHO[255:192] captured at VY_DECODE_Z ctr0==2
    reg [63:0] tr_low_diag;        // TR[63:0] at VY_NTT_Z→VY_NTT_T1 transition
    reg [63:0] ntt_z_ctr0_diag;    // ctr0 at VY_NTT_Z→VY_NTT_T1 transition
    
    reg cstart_fsm0, cstart_fsm1, cstart_fsm2;
    reg nstart_fsm0, nstart_fsm1, nstart_fsm2;
    
    reg en_ram0, wea_ram0, web_ram0;
    reg [$clog2(4096)-1:0] addra_ram0, addrb_ram0;
    reg [96-1:0] dia_ram0, dib_ram0;
    wire [96-1:0] doa_ram0,dob_ram0;
    dual_port_ram #(.WIDTH(96), .LENGTH(4096))  
        BRAM_0 (clk,clk,en_ram0,en_ram0,wea_ram0,web_ram0,
                addra_ram0,addrb_ram0,dia_ram0,dib_ram0,
                doa_ram0,dob_ram0);  
    
    reg en_ram1, wea_ram1, web_ram1;
    reg [$clog2(1024)-1:0] addra_ram1, addrb_ram1;
    reg [96-1:0] dia_ram1, dib_ram1;
    wire [96-1:0] doa_ram1,dob_ram1;
    dual_port_ram #(.WIDTH(96), .LENGTH(1024))  
        BRAM_1 (clk,clk,en_ram1,en_ram1,wea_ram1,web_ram1,
                addra_ram1,addrb_ram1,dia_ram1,dib_ram1,
                doa_ram1,dob_ram1);  
    
    reg en_ram2, wea_ram2, web_ram2;
    reg [$clog2(1024)-1:0] addra_ram2, addrb_ram2;
    reg [96-1:0] dia_ram2, dib_ram2;
    wire [96-1:0] doa_ram2,dob_ram2;
    dual_port_ram #(.WIDTH(96), .LENGTH(1024))  
        BRAM_2 (clk,clk,en_ram2,en_ram2,wea_ram2,web_ram2,
                addra_ram2,addrb_ram2,dia_ram2,dib_ram2,
                doa_ram2,dob_ram2);  
    
    reg en_ram3, wea_ram3, web_ram3;
    reg [$clog2(1024)-1:0] addra_ram3, addrb_ram3;
    reg [96-1:0] dia_ram3, dib_ram3;
    wire [96-1:0] doa_ram3,dob_ram3;
    dual_port_ram #(.WIDTH(96), .LENGTH(1024))  
        BRAM_3 (clk,clk,en_ram3,en_ram3,wea_ram3,web_ram3,
                addra_ram3,addrb_ram3,dia_ram3,dib_ram3,
                doa_ram3,dob_ram3);  
    
    reg en_ram4, wea_ram4, web_ram4;
    reg [$clog2(1024)-1:0] addra_ram4, addrb_ram4;
    reg [96-1:0] dia_ram4, dib_ram4;
    wire [96-1:0] doa_ram4,dob_ram4;
    dual_port_ram #(.WIDTH(96), .LENGTH(1024))  
        BRAM_4 (clk,clk,en_ram4,en_ram4,wea_ram4,web_ram4,
                addra_ram4,addrb_ram4,dia_ram4,dib_ram4,
                doa_ram4,dob_ram4);  
    
    reg en_ram5, wea_ram5, web_ram5;
    reg [$clog2(1024)-1:0] addra_ram5, addrb_ram5;
    reg [96-1:0] dia_ram5, dib_ram5;
    wire [96-1:0] doa_ram5,dob_ram5;
    dual_port_ram #(.WIDTH(96), .LENGTH(1024))  
        BRAM_5 (clk,clk,en_ram5,en_ram5,wea_ram5,web_ram5,
                addra_ram5,addrb_ram5,dia_ram5,dib_ram5,
                doa_ram5,dob_ram5);  
    
    reg en_ram6, wea_ram6, web_ram6;
    reg [$clog2(1024)-1:0] addra_ram6, addrb_ram6;
    reg [96-1:0] dia_ram6, dib_ram6;
    wire [96-1:0] doa_ram6,dob_ram6;
    dual_port_ram #(.WIDTH(96), .LENGTH(1024))  
        BRAM_6 (clk,clk,en_ram6,en_ram6,wea_ram6,web_ram6,
                addra_ram6,addrb_ram6,dia_ram6,dib_ram6,
                doa_ram6,dob_ram6);  
    
    localparam
        G2_SUB_BETA = 3'd0,
        G1_SUB_BETA = 3'd1,
        G2          = 3'd2;
    
    reg [1:0]  mode_norm;
    reg        validi_norm;
    reg [95:0] di_norm;
    wire rej_norm;
    reg  norm_rejected;
    
    norm_check REJ_CHECK(
        sec_lvl, mode_norm, validi_norm, di_norm, rej_norm
    );
    
      
    // Keccak
    reg  [2:0] rst_k;
    reg  [63:0] din [2:0];
    wire [63:0] dout [2:0];   
    reg  [2:0]  src_ready;
    wire [2:0]  src_read;
    wire [2:0]  dst_write;
    reg  [2:0]  dst_ready;
    
    reg  rst_k_fsm;
    reg  [63:0] din_fsm;
    reg  [63:0] dout_fsm;   
    reg  src_ready_fsm;
    reg  src_read_fsm;
    reg  dst_write_fsm;
    reg  dst_ready_fsm;

    genvar g;
    generate
        for (g = 0; g < 3; g = g + 1) begin
            keccak_top KECCAK(      
                    rst_k[g], clk, src_ready[g], src_read[g], dst_ready[g], dst_write[g], din[g], dout[g]
                ); 
        end
    endgenerate

    // Gen S polys submodule
    reg             start_s, rst_s;
    reg  [63:0]     din_s;
    wire [23*4-1:0] samples_s;
    reg  valid_i_s;
    wire ready_i_s;
    wire valid_o_s;
    reg  ready_o_s;
    reg  mux_ctrl_k;
    wire done_s;

    wire        rst_k_s;
    wire [63:0] kdin_s;
    wire        src_ready_s;
    wire        src_read_s;
    wire        dst_write_s;
    wire        dst_ready_s;

    // Connect diagnostic wires to actual Keccak bus signals
    // (src_read_s/dst_write_s were undriven passthrough names;
    //  the actual Keccak[2] bus signals are src_read[2] and dst_write[2])
    assign src_read_s  = src_read[2];
    assign dst_write_s = dst_write[2];

    // Diagnostic wires from gen_s
    wire [4:0]  gs_sample_state;
    wire        gs_done_latch;
    wire        gs_mode;
    wire [2:0]  gs_sampler_state;
    wire [7:0]  gs_sampler_sample_ctr;

    gen_s SECRET_SAMPLER (
        start_s, rst_s, clk, sec_lvl,
        valid_i_s, ready_i_s, din_s, samples_s,
        valid_o_s, ready_o_s, done_s,
        gs_sample_state, gs_done_latch, gs_mode, gs_sampler_state, gs_sampler_sample_ctr,
        mux_ctrl_k, rst_k_s, kdin_s, dout[2], src_ready_s,
        src_read[2] & mux_ctrl_k, dst_write[2] & mux_ctrl_k, dst_ready_s
        );
    
    // Gen C Poly Submodules
    reg             start_c, rst_c, mode_c;
    reg  [63:0]     din_c;
    wire [23*4-1:0] samples_c;
    reg         valid_i_c;
    wire        ready_i_c;
    wire        valid_o_c;
    reg         ready_o_c;
    wire [63:0] ch_c;
    reg read_ch_c;
    wire        done_c;
    
    wire rst_k_c;
    wire  [63:0] din_k_c;
    wire src_ready_c;
    wire dst_ready_c; 
    
    wire src_read_c, dst_write_c;
    wire [63:0] dout_c;

    assign src_read_c = (mode == 2) ? src_read[1]   && (cstate0 == FSM0_STALL) : src_read[2];
    assign dst_write_c = (mode == 2) ? dst_write[1] && (cstate0 == FSM0_STALL)  : dst_write[2];
    assign dout_c = (mode == 2) ? dout[1] : dout[2];


    gen_c CHALLENGE_SAMPLER(
        start_c, rst_c, clk, sec_lvl, mode_c,
        valid_i_c, ready_i_c, din_c,
        samples_c, valid_o_c, ready_o_c,
        read_ch_c, ch_c, done_c,
        rst_k_c, din_k_c, dout_c, src_ready_c,
        src_read_c, dst_write_c, dst_ready_c
        ); 
    

    // GenA submodule
    reg                start_a, rst_a;
    reg  [63:0]        din_a;
    wire [5:0]        sample_state;
    wire [23*4*2-1:0] samples_a;
    reg         valid_i_a;
    wire        ready_i_a;
    wire [1:0]  valid_o_a;
    reg  [1:0]  ready_o_a;
    wire        done_a;

    wire     [2-1:0] rst_k_a;
    wire     [2*64-1:0] din_k_a;
    wire      [2*64-1:0] dout_a;  
    wire     [2-1:0]  src_ready_a;
    wire      [2-1:0]  src_read_a;
    wire      [2-1:0]  dst_write_a;
    wire      [2-1:0]  dst_ready_a;

    assign dout_a[64*0+:64] = dout[0];
    assign dout_a[64*1+:64] = dout[1];
    assign src_read_a[0] = src_read[0];
    assign src_read_a[1] = src_read[1];
    assign dst_write_a[0] = dst_write[0];
    assign dst_write_a[1] = dst_write[1];


    gen_a_ext PUBLIC_SAMPLER (
        start_a, rst_a, clk, sec_lvl,
        valid_i_a, ready_i_a, din_a,
        samples_a, sample_state,
        valid_o_a, ready_o_a,
        done_a, rst_k_a, din_k_a, dout_a, 
        src_ready_a, src_read_a, dst_write_a,
        dst_ready_a
    ); 
    
    // Gen Y submodule
    reg start_geny, rst_geny;
    reg  [63:0]       di_geny;
    wire [63:0]       do_mu;
    wire              valid_mu;
    wire [4*23-1:0] do_geny;
    reg  valid_i_geny;
    wire ready_i_geny;
    wire valid_o_geny;
    reg  ready_o_geny;
    wire done_geny;
    wire rst_k_y;
    wire  [63:0] din_k_y;
    wire src_ready_y;
    wire dst_ready_y;

    wire [3:0] geny_cstate;
    wire [31:0] geny_ctr;
    expandmask_ext GEN_Y(
        start_geny, rst_geny, clk, sec_lvl, mlen,
        valid_i_geny, ready_i_geny, di_geny, do_mu, valid_mu,
        do_geny, valid_o_geny, ready_o_geny, done_geny,
        rst_k_y, din_k_y, dout[2], src_ready_y,
        src_read[2], dst_write[2], dst_ready_y,
        geny_cstate,
        geny_ctr
        );   
    
    // Encoder and Decoder submodules
    localparam
        DILITHIUM_Q = 23'd8380417,
        ENCODE_T0   = 3'd0,
        ENCODE_T1   = 3'd1,
        ENCODE_S1   = 3'd2,
        ENCODE_S2   = 3'd3,
        ENCODE_W1   = 3'd4,
        ENCODE_Z    = 3'd5;
    
    reg         rst_dec;
    reg [2:0]   mode_dec;
    reg         valid_i_dec;
    wire        ready_i_dec;
    reg         ready_o_dec;
    wire        valid_o_dec;
    reg  [63:0]  di_dec;
    wire [BUS_W*SAMPLE_W-1:0]  do_dec;
    
    mldsa_decoder DECODER (
        rst_dec, clk, sec_lvl, mode_dec,
        valid_i_dec, ready_i_dec, di_dec,
        do_dec, valid_o_dec, ready_o_dec
        );
     
    wire [63:0]     do_enc;
    reg  [23*4-1:0] di_enc;
    reg  [2:0] mode_enc;
    reg  rst_enc;
    reg  valid_i_enc;
    wire ready_i_enc;
    wire valid_o_enc;
    reg  ready_o_enc;
    
    mldsa_encoder ENCODER (
        rst_enc,clk,sec_lvl,mode_enc,
        valid_i_enc, ready_i_enc, di_enc,
        do_enc, valid_o_enc, ready_o_enc
        );
    
    // Decomposer submodule
    reg  rst_decomp, valid_i_decomp, ready_o_decomp;
    wire ready_i_decomp;
    reg  [95:0] di_decomp;
    wire [95:0] doa_decomp, dob_decomp;
    wire valid_o_decomp;
    reg  ready_i_decomp_last;
    
    decomposer_unit DECOMPOSER(
        rst_decomp, clk, sec_lvl, valid_i_decomp, ready_i_decomp,
        di_decomp, doa_decomp, dob_decomp, valid_o_decomp, ready_o_decomp
    );
    
    // Hint 
    reg  rst_hint;
    reg  start_hint;
    reg  valid_i_hint;
    wire ready_i_hint;
    reg  poly_valid_i_hint;
    wire poly_ready_i_hint;
    wire poly_valid_o_hint;
    wire [256*8-1:0] hint_poly_data;
    wire [10:0] hint_ctr;
    reg  poly_ready_o_hint;
    reg  [63:0] di_hint;
    reg  [95:0] poly_di0_hint, poly_di1_hint;
    wire [95:0] poly_do_hint;

    usehint HINT_APPLIER(
        rst_hint, clk, start_hint,
        sec_lvl, di_hint, valid_i_hint,
        ready_i_hint, poly_di0_hint, poly_di1_hint,
        poly_valid_i_hint, poly_ready_i_hint,
        poly_do_hint, poly_valid_o_hint,
        poly_ready_o_hint,
        hint_poly_data, hint_ctr
    );
        
    // MakeHint
    reg  rst_mh;
    wire reject_mh;
    reg  [95:0] polyi0_mh, polyi1_mh;
    reg  validi_mh;
    wire readyi_mh;
    wire [63:0] hint_o;
    wire valido_mh;
    reg  readyo_mh;
    makehint CREATE_HINT(
        rst_mh, clk, sec_lvl, reject_mh,
        polyi0_mh, polyi1_mh,
        validi_mh, readyi_mh,
        hint_o, valido_mh, readyo_mh);
    
    // Operator
    localparam
        FORWARD_NTT_MODE = 3'd0,
        INVERSE_NTT_MODE = 3'd1,
        MULT_MODE        = 3'd2,
        ADD_MODE         = 3'd3,
        SUB_MODE         = 3'd4;
    
    localparam NUM_OPERATORS = 2;
    reg  [3:0] addr1_sel_op [NUM_OPERATORS-1:0];
    reg  [5:0] addr2_sel_op [NUM_OPERATORS-1:0];
    reg  [3:0] addr3_sel_op [NUM_OPERATORS-1:0];
    
    reg  [2:0] naddr1_sel_op [NUM_OPERATORS-1:0];
    reg  [5:0] naddr2_sel_op [NUM_OPERATORS-1:0];
    reg  [2:0] naddr3_sel_op [NUM_OPERATORS-1:0];
    
    reg  [NUM_OPERATORS-1:0] start_op;
    reg  [NUM_OPERATORS-1:0] rst_op;
    reg  [2:0] mode_op [NUM_OPERATORS-1:0];
    reg  [1:0] encode_mode_op [NUM_OPERATORS-1:0];
    wire [NUM_OPERATORS-1:0] done_op;
    wire [5:0] addra1_op [NUM_OPERATORS-1:0];
    wire [5:0] addrb1_op [NUM_OPERATORS-1:0];
    wire [5:0] addra2_op [NUM_OPERATORS-1:0];
    wire [5:0] addrb2_op [NUM_OPERATORS-1:0];
    reg [95:0] doa1_op [NUM_OPERATORS-1:0];
    reg [95:0] dob1_op [NUM_OPERATORS-1:0];
    reg [95:0] doa2_op [NUM_OPERATORS-1:0];
    wire [NUM_OPERATORS-1:0] web1_op;
    wire [NUM_OPERATORS-1:0] web2_op;
    wire [95:0] dib1_op [NUM_OPERATORS-1:0];
    wire [95:0] dib2_op [NUM_OPERATORS-1:0];

    localparam 
        DECODE_TRUE = 2'd0,
        ENCODE_TRUE = 2'd1,
        STANDARD    = 2'd2;

    generate
        for (g = 0; g < NUM_OPERATORS; g = g + 1) begin
            operation_module OPERATOR(
                clk, rst_op[g], start_op[g], mode_op[g], encode_mode_op[g], done_op[g],
                // BRAM 1
                addra1_op[g], addrb1_op[g], doa1_op[g], dob1_op[g],
                web1_op[g], dib1_op[g],
                // BRAM 2  
                addra2_op[g], addrb2_op[g], doa2_op[g],
                web2_op[g], dib2_op[g]
            );
        end
    endgenerate
    
    reg shake_verif_done;
    reg ntt_verif_done;
    reg ntt_z_done;            // sticky: all L Z NTTs completed in VY_NTT_Z
    reg s1_ntt_all_done = 0;  // sticky: all L S1 NTTs completed
    reg s2_ntt_all_done = 0;  // sticky: all K S2 NTTs completed
    

    reg [12:0] T0_LEN, T1_LEN, S1_LEN, S2_LEN, K, L, Z_LEN, W1_LEN;
    reg [32 - 1 : 0] ctilde_out_len;
    reg [10 - 1 : 0] C_SIPO_START;
    reg [10:0] ctr0, ctr0_next;
    reg [10:0] ctr1, ctr1_next;
    reg [9:0] ctr_s1 = 0, ctr_s2 = 0;
    reg [5:0] ctr_a1 = 0, ctr_a2 = 0;
    reg [9:0] ctr_t = 0, ctr_c = 0;
    reg [9:0] ctr_dec = 0;
    reg s2_prereq_done = 0;
    reg enc_phase = 0; // 0=READ (wait for RAM), 1=HOLD (wait for encoder)

    // Per-phase diagnostic counters
    reg [9:0] out_word_total = 0;
    reg sticky_entered_t0 = 0;
    reg sticky_entered_tr = 0;
    // Per-phase output word counters (count valid_o && ready_o per state)
    reg [9:0] owt_hash = 0;    // KG_HASH_Z + KG_UNLOAD_HASH
    reg [9:0] owt_s1 = 0;      // KG_SAMPLE_S1
    reg [9:0] owt_s2 = 0;      // KG_SAMPLE_S2
    reg [9:0] owt_t1 = 0;      // KG_ENCODE_T1
    reg [9:0] owt_t0 = 0;      // KG_ENCODE_T0
    reg [9:0] owt_tr = 0;      // KG_UNLOAD_TR
    // Sticky diagnostic flags for Sign debug
    reg sticky_cstart_fsm1 = 0;
    reg sticky_start_geny  = 0;
    reg sticky_src_read2   = 0;   // did Keccak[2] src_read ever fire?
    reg sticky_valid_geny  = 0;   // did valid_i_geny ever go high?
    reg sticky_ready_geny  = 0;   // did ready_i_geny ever go high?
    reg [3:0] geny_cstate_at_mu_exit = 4'hF;  // GenY state when LOAD_MU exits
    reg [7:0] keccak_word_cnt = 0; // counts src_read[2] when k_fsm=1
    // Sticky MULTACC debug
    reg sticky_multacc_entered = 0;   // FSM2_MULTACC ever entered
    reg sticky_web6_fired      = 0;   // web_ram6 ever fired in MULTACC
    reg sticky_start_op1_mult  = 0;   // start_op[1] ever fired while in MULTACC
    reg sticky_dib6_nonzero_multacc = 0;  // dib_ram6 ever non-zero in MULTACC
    reg sticky_dib6_nonzero_anywhere = 0; // dib_ram6 ever non-zero anywhere (web_ram6)
    reg [15:0] multacc_web_count = 0;       // counts web_ram6 pulses in MULTACC (16-bit to avoid overflow)
    reg [15:0] nttiz_web_count   = 0;       // counts web_ram6 pulses in NTTI_Z
    reg [31:0] first_multacc_dib_low  = 0;  // low 32 bits of first non-zero MULTACC write
    reg        first_multacc_captured = 0;
    reg [31:0] first_nttiz_dib_low    = 0;  // low 32 bits of first non-zero NTTI_Z write
    reg        first_nttiz_captured   = 0;
    reg [9:0]  unload_addr_max = 0;          // max addra_ram6 reached in UNLOAD_Z
    reg [7:0]  multacc_done_count = 0;       // counts done_op[1] pulses in MULTACC (polynomials processed)
    reg [7:0]  nttiz_done_count   = 0;       // counts done_op[1] pulses in NTTI_Z
    reg [3:0]  multacc_addr1_max  = 0;       // max addr1_sel_op[1] seen in MULTACC
    reg [3:0]  nttiz_addr1_max    = 0;       // max addr1_sel_op[1] seen in NTTI_Z
    reg [3:0]  multacc_addr1_at_exit = 0;    // addr1_sel_op[1] when MULTACC exits to MULT_CS2
    reg [9:0]  multacc_last_addrb = 0;       // last addrb_ram6 in MULTACC
    reg [31:0] last_multacc_dib_low = 0;     // last dib_ram6[31:0] written in MULTACC
    reg [31:0] last_nttiz_dib_low   = 0;     // last dib_ram6[31:0] written in NTTI_Z
    reg [31:0] or_multacc_dib_low   = 0;     // OR of all dib_ram6[31:0] writes in MULTACC
    reg [31:0] or_nttiz_dib_low     = 0;     // OR of all dib_ram6[31:0] writes in NTTI_Z
    reg [15:0] nttiz_nonzero_count  = 0;     // # of non-zero dib writes in NTTI_Z
    reg [15:0] multacc_nonzero_count= 0;     // # of non-zero dib writes in MULTACC
    reg [9:0]  multacc_addrb_max = 0;        // max addrb_ram6 in MULTACC
    reg [9:0]  multacc_addrb_min = 10'h3FF;  // min addrb_ram6 in MULTACC
    reg [9:0]  nttiz_addrb_max   = 0;        // max addrb_ram6 in NTTI_Z

    reg [255:0] rho;
    reg [63:0] keccak_fifo [319:0];
    reg [319:0] keccak_valid;
        
    initial begin
        cstate0 = FSM0_INIT;
        cstate1 = FSM1_STALL;
        cstate2 = FSM2_STALL;
    end

    always @(*) begin
        // Byte-len of vectors
        case(sec_lvl)
        2: begin   
            K = 4;
            L = 4;
            T0_LEN = 4*416; 
            T1_LEN = 4*320;
            S1_LEN = 4*96;
            S2_LEN = 4*96;
            Z_LEN  = 4*576;
            W1_LEN = 4*192;
            ctilde_out_len = 32*8;
            C_SIPO_START = 256;
        end
        3: begin
            K = 6;
            L = 5;
            T0_LEN = 6*416;
            T1_LEN = 6*320;
            S1_LEN = 5*128;
            S2_LEN = 6*128;
            Z_LEN  = 5*640;
            W1_LEN = 6*128;
            ctilde_out_len = 48*8;
            C_SIPO_START = 384;
        end
        default: begin
            K = 8;
            L = 7;
            T0_LEN = 8*416;
            T1_LEN = 8*320;
            S1_LEN = 7*96;
            S2_LEN = 8*96;
            Z_LEN  = 7*640;
            W1_LEN = 8*128;
            ctilde_out_len = 64*8;
            C_SIPO_START = 512;
        end
        endcase
    end
    
    reg  curr_y_used;
    reg  k_fsm;
    always @(*) begin

        // Keccak MUX
        rst_k[0] = rst_k_a[0];
        din[0]   = din_k_a[63:0]; 
        src_ready[0] = src_ready_a[0];
        dst_ready[0] = ~dst_ready_a[0]; 

        if (cstate0 == FSM0_STALL && mode == 2) begin
            rst_k[1] = rst_k_c;
            din[1]   = din_k_c;
            src_ready[1] = src_ready_c;
            dst_ready[1] = dst_ready_c; 
        end else begin
            rst_k[1] = rst_k_a[1];
            din[1] = din_k_a[127:64]; 
            src_ready[1] = src_ready_a[1];
            dst_ready[1] = ~dst_ready_a[1];   
        end

        case(k_fsm)
        0: begin
            rst_k[2] = rst_k_y;
            din[2]   = din_k_y;
            src_ready[2] = src_ready_y;
            dst_ready[2] = ~dst_ready_y; 
            end 
        1: begin
            rst_k[2] = rst_k_fsm;
            din[2]   = din_fsm;
            src_ready[2] = src_ready_fsm;
            dst_ready[2] = dst_ready_fsm; 
        end
        endcase
    end

    reg [2:0] ready_i_mux;
    always @(*) begin
        case(ready_i_mux)
            0: ready_i = 0;
            1: ready_i = src_read[2];
            2: ready_i = ready_i_a;
            3: ready_i = ready_i_c;
            4: ready_i = ready_i_dec;
            5: ready_i = ready_i_hint;
            6: ready_i = ready_i_geny;
            7: ready_i = 1;
        endcase

    end
    
    
    // MAIN FSM
    
    always @(*) begin
        nstate0 = cstate0;
        nstate1 = cstate1;
        nstate2 = cstate2;
        
        ctr0fsm2_next = ctr0fsm2;
        ctrfsm2_next  = ctrfsm2;
        mode_enc = 0;
        
        rst_k_fsm = 0;
        din_fsm = 0;
        src_ready_fsm = 1;
        dst_ready_fsm = 1;

        valid_o = 0;
        data_o = 0;

        k_fsm = 0;
    
        nstart_fsm0 = 0;
        nstart_fsm1 = 0;
        nstart_fsm2 = 0;
        
        ctr_next = ctr;
        ctr0_next = ctr0;
        ctr1_next = ctr1;
    
        rst_enc  = rst;
        rst_dec    = rst;
        rst_geny   = 0;
        rst_a      = 0;
        rst_c      = 0;
        start_a    = 0;
        start_c    = 0;
        start_geny = 0;

        rst_s     = 0;
        valid_i_s = 0;
        start_s   = 0;
        din_s     = 0;
        ready_o_s = 0;

        ready_i_mux = 0; 
        ready_o_geny = 0;
        valid_i_geny = 0;
        di_geny      = 0;
        ready_o_a    = 0;
        valid_i_a    = 0;
        din_a        = 0;
        ready_o_c    = 0;
        valid_i_c    = valid_mu;
        din_c        = do_mu;
        ready_o_enc = 0;
        valid_i_enc = 0;
        di_enc      = 0;
        ready_o_dec = 0;
        valid_i_dec = 0;
        di_dec      = 0;
        mode_dec    = 0;
        
        read_ch_c = 0;
        
        
        encode_mode_op[0] = STANDARD;
        rst_op[0]  = 0;
        mode_op[0] = FORWARD_NTT_MODE;
        naddr1_sel_op[0] = addr1_sel_op[0]; 
        naddr2_sel_op[0] = addr2_sel_op[0]; 
        naddr3_sel_op[0] = addr3_sel_op[0];
        
        mux_ctrl_k = 0;
        
        encode_mode_op[1] = STANDARD;
        rst_op[1]  = 0;
        mode_op[1] = FORWARD_NTT_MODE;
        naddr1_sel_op[1] = addr1_sel_op[1]; 
        naddr2_sel_op[1] = addr2_sel_op[1]; 
        naddr3_sel_op[1] = addr3_sel_op[1];

        // Gen Y
        valid_i_geny = 0;
        di_geny      = 0;
        ready_o_geny = 0;
    
        // Decomp
        rst_decomp = 0;
        valid_i_decomp = 0; ready_o_decomp = 0;
        di_decomp = 0;
         
        // Make Hint
        rst_mh = rst;
        polyi0_mh = 0; 
        polyi1_mh = 0;
        validi_mh = 0;
        readyo_mh = 0;
         
        // BRAM Defaults
        en_ram0 = 1; en_ram1 = 1; en_ram2 = 1; 
        en_ram3 = 1; en_ram4 = 1; en_ram5 = 1; en_ram6 = 1;
        wea_ram0   = 0; web_ram0   = 0;
        addra_ram0 = 0; addrb_ram0 = 0;
        dia_ram0   = 0; dib_ram0   = 0;
        wea_ram1   = 0; web_ram1   = 0;
        addra_ram1 = 0; addrb_ram1 = 0;
        dia_ram1   = 0; dib_ram1   = 0;
        wea_ram2   = 0; web_ram2   = 0;
        addra_ram2 = 0; addrb_ram2 = 0;
        dia_ram2   = 0; dib_ram2   = 0;
        wea_ram3   = 0; web_ram3   = 0;
        addra_ram3 = 0; addrb_ram3 = 0;
        dia_ram3   = 0; dib_ram3   = 0;
        wea_ram4   = 0; web_ram4   = 0;
        addra_ram4 = 0; addrb_ram4 = 0;
        dia_ram4   = 0; dib_ram4   = 0;
        wea_ram5   = 0; web_ram5   = 0;
        addra_ram5 = 0; addrb_ram5 = 0;
        dia_ram5   = 0; dib_ram5   = 0;
        wea_ram6   = 0; web_ram6   = 0;
        addra_ram6 = 0; addrb_ram6 = 0;
        dia_ram6   = 0; dib_ram6   = 0;
        
        ctrfsm1_next = ctrfsm1;
       
        doa1_op[0] = 0; dob1_op[0] = 0; 
        doa2_op[0] = 0;
        
        doa1_op[1] = 0; dob1_op[1] = 0; 
        doa2_op[1] = 0; 
        
        mode_c = (mode == 1) ? 1 : 0; 
        
        // norm
        mode_norm = G2_SUB_BETA ;
        validi_norm = 0;
        di_norm = 0;
        
        // Hint
        rst_hint     = 0;
        start_hint   = 0;
        valid_i_hint = 0;
        di_hint      = 0;
        poly_valid_i_hint = 0;
        poly_di0_hint      = 0;
        poly_di1_hint      = 0;
        poly_ready_o_hint = 0;
        
        case({mode,cstate0})
        {2'd0,KG_INIT}: begin
            k_fsm = 1;
            rst_k_fsm     = (start) ? 0 : 1;
            rst_a     = (start) ? 0 : 1;
            rst_s     = (start) ? 0 : 1;
            start_a   = (start) ? 1 : 0;
            start_s   = (start) ? 1 : 0;
            rst_op    = (start) ? 0 : 1;

            rst_enc = 1;
            
            naddr1_sel_op[0] = 0; 
            naddr2_sel_op[0] = 0; 
            naddr3_sel_op[0] = 0;   
                     
            ctr_next  = 0;
            nstate0    = (start) ? KG_HASH_Z : KG_INIT;
        end
        {2'd0,KG_HASH_Z}: begin
            k_fsm = 1;
            if (ctr == 0) begin
                // init keccak
                din_fsm       = {4'hE, 28'd1024, 32'd272}; // 32 Byte seed + 2 byte domain separation
                src_ready_fsm = 0;  
            end else if (ctr == 5) begin
                din_fsm       = {K[8 - 1 : 0], L[8 - 1 : 0], 48'h0}; // Domain-Separation
                src_ready_fsm = 0;
                nstate0    = (src_read[2]) ? KG_UNLOAD_HASH : KG_HASH_Z;
            end else begin
                din_fsm       = data_i;
                src_ready_fsm = ~valid_i;
                ready_i_mux = 1;
            end
            
            ctr_next  = (ctr == 5 && src_read[2] && ~src_ready_fsm) ? 0 
                      : (src_read[2] && ~src_ready_fsm) ? ctr + 1 : ctr;      
        end   
        {2'd0,KG_UNLOAD_HASH}: begin
            // sampler s control
            wea_ram1   = valid_o_s && ready_o_s;
            addra_ram1 = ctr_s1;
            dia_ram1   = {1'd0, samples_s[3*23+:23], 1'd0, samples_s[2*23+:23], 1'd0, samples_s[1*23+:23], 1'd0, samples_s[0*23+:23]};
            
            // sampler a ctr
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
        
            if (ctr < 4) begin
                // Unload rho from SHAKE to GenA (and AXI: 32 bytes)
                dst_ready_fsm = !ready_i_a;
                valid_i_a = dst_write[2];
                din_a     = dout[2];
                ctr_next  = (valid_i_a && ready_i_a) ? ctr + 1 : ctr;
                
                valid_o  = dst_write[2];
                data_o    = dout[2];
            end else if (ctr < 12) begin
                // Unload rho' from SHAKE to GenS (64 bytes)
                dst_ready_fsm = !ready_i_s;
                valid_i_s = dst_write[2];
                din_s     = dout[2];
                ctr_next  = (valid_i_s && ready_i_s) ? ctr + 1 : ctr;
            end else begin
                // Unload K from SHAKE to AXI output (32 bytes)
                dst_ready_fsm = !ready_o;
                valid_o  = dst_write[2];
                data_o    = dout[2];
                ctr_next    = (ctr == 15 && valid_o && ready_o) ? 0 
                            : (valid_o && ready_o) ? ctr + 1 : ctr;
            end
            
            nstate0    = (ctr == 15 && valid_o && ready_o) ? KG_SAMPLE_S1 : KG_UNLOAD_HASH;
            rst_k_fsm     = (ctr == 15 && valid_o && ready_o) ? 1 : 0;
            k_fsm = 1;
        end
        {2'd0,KG_SAMPLE_S1}: begin
            // ENCODER
            mode_enc    = ENCODE_S1;
            ready_o_s   = ready_i_enc;
            valid_i_enc = valid_o_s;
            di_enc      = samples_s;
        
            // sampler s control
            wea_ram1   = valid_o_s && ready_o_s;
            addra_ram1 = ctr_s1;
            dia_ram1   = {1'd0, samples_s[3*23+:23], 1'd0, samples_s[2*23+:23], 1'd0, samples_s[1*23+:23], 1'd0, samples_s[0*23+:23]};
            
            // sampler a ctr
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
                  
            mux_ctrl_k = 1;
            k_fsm = 1;
            rst_k_fsm = rst_k_s;
            din_fsm   = kdin_s;
            src_ready_fsm = src_ready_s;
            dst_ready_fsm = dst_ready_s; 
            
            // Unload S1 to encoder->AXI
            valid_o     = valid_o_enc;
            ready_o_enc = ready_o;
            data_o      = {do_enc[7:0],do_enc[15:8], do_enc[23:16], do_enc[31:24], do_enc[39:32], do_enc[47:40],do_enc[55:48], do_enc[63:56]};
            ctr_next    = (valid_o  && ready_o) ? ctr + 1 : ctr;
            nstate0      = (ctr == S1_LEN[10:3]-1 && valid_o && ready_o) ? KG_SAMPLE_S2 : KG_SAMPLE_S1;  
        end
        {2'd0,KG_SAMPLE_S2}: begin
            // ENCODER
            mode_enc    = ENCODE_S2;
            ready_o_s   = ready_i_enc;
            valid_i_enc = valid_o_s;
            di_enc      = samples_s;
        
            // sampler s control
            wea_ram2   = valid_o_s && ready_o_s;
            addra_ram2 = ctr_s2;
            dia_ram2   = {1'd0, samples_s[3*23+:23], 1'd0, samples_s[2*23+:23], 1'd0, samples_s[1*23+:23], 1'd0, samples_s[0*23+:23]};
            
            // sampler a ctr
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
        
            mux_ctrl_k = 1;
            k_fsm = 1;
            rst_k_fsm = rst_k_s;
            din_fsm   = kdin_s;
            src_ready_fsm = src_ready_s;
            dst_ready_fsm = dst_ready_s; 
        
            // NTT on S1
            addra_ram1 = {addr1_sel_op[0], addra1_op[0]};
            addrb_ram1 = {addr1_sel_op[0], addrb1_op[0]};
            web_ram1   = web1_op[0];
            dib_ram1   = dib1_op[0];
            doa1_op[0]  = doa_ram1;
            dob1_op[0]  = dob_ram1;
        
            // Unload S2 encoder->AXI
            valid_o     = valid_o_enc;
            ready_o_enc = ready_o;
            data_o      = {do_enc[7:0],do_enc[15:8], do_enc[23:16], do_enc[31:24], do_enc[39:32], do_enc[47:40],do_enc[55:48], do_enc[63:56]};
            ctr_next    = (valid_o  && ready_o) ? ctr + 1 : ctr;

            nstate0    = ((done_op[0] && addr1_sel_op[0] == K - 1 && sec_lvl == 2) ||
                          (a_generated && sec_lvl != 2 &&
                           ((ctr == S2_LEN[10:3]-1 && valid_o && ready_o) ||
                            (ctr >= S2_LEN[10:3])))) ? KG_MULT_AS1 : KG_SAMPLE_S2;
            rst_op[0]    = (done_op[0]) ? 1 : 0;
            // fix: force addr1=0 when transitioning to MULT_AS1. The original code
            // relied on transition firing synchronously with the last NTT's
            // done_op[0] pulse (so naddr1 wrapped via the ==K-1 condition). The
            // current modified transition condition can fire on cycles when
            // done_op[0]=0 (waiting on ctr/S2_LEN), leaving addr1=K-1=5 stuck —
            // MULT then reads RAM1[5,...] which has no s1 poly, producing wrong T.
            naddr1_sel_op[0] = (nstate0 == KG_MULT_AS1) ? 4'd0
                             : (done_op[0] && addr1_sel_op[0] == K - 1) ? 0
                             : (done_op[0]) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];

        end
        {2'd0,KG_MULT_AS1}: begin
            // A*s1 - MULT-ACC
            // multa: s1, multb: a, acc: t
            rst_enc = 1; // Clear encoder pipeline between S2 and T1
            addra_ram1 = {addr1_sel_op[0], addra1_op[0]};
            addra_ram0  = {addr2_sel_op[0], addra2_op[0]};
            addra_ram3  = {addr3_sel_op[0], addrb1_op[0]};
            // write
            addrb_ram3 = {addr3_sel_op[0], addrb2_op[0]};
            web_ram3   = web2_op[0];
            dib_ram3   = dib2_op[0];
            
            doa1_op[0]  = doa_ram1;
            doa2_op[0]  = doa_ram0;
            dob1_op[0]  = (addr1_sel_op[0] == 0) ? 0 : doa_ram3; 
        
            // s1: naddr1_sel_op, a: naddr2_sel_op, t: naddr3_sel_op 
            mode_op[0]  = MULT_MODE;
            encode_mode_op[0] = ENCODE_TRUE;
            
            if (done_op[0]) begin
                rst_op[0] = 1;
                naddr2_sel_op[0] = addr2_sel_op[0] + 1;
                if (naddr1_sel_op[0] == L - 1) begin
                    naddr1_sel_op[0] = 0;
                    if (naddr3_sel_op[0] == K - 1) begin
                        naddr3_sel_op[0] = 0;
                        naddr2_sel_op[0] = 0;
                        
                        // end of mult
                        nstate0 = KG_NTTI_T;
                    end else begin
                        naddr3_sel_op[0] = addr3_sel_op[0] + 1;
                    end
                end else begin
                    naddr1_sel_op[0] = addr1_sel_op[0] + 1;
                end
            end
        end
        {2'd0,KG_NTTI_T}: begin
            // NTTI on T
            rst_enc = 1;
            addra_ram3 = {addr1_sel_op[0], addra1_op[0]};
            addrb_ram3 = {addr1_sel_op[0], addrb1_op[0]};
            web_ram3   = web1_op[0];
            dib_ram3   = dib1_op[0];
            doa1_op[0]  = doa_ram3;
            dob1_op[0]  = dob_ram3;
        
            // wait until NTT is complete
            nstate0    = (done_op[0] && naddr1_sel_op[0] == K-1) ? KG_ADD_T_S2 : KG_NTTI_T;
            rst_op[0]    = (done_op[0]) ? 1 : 0;
            mode_op[0]  = (done_op[0] && naddr1_sel_op[0] == K-1) ? ADD_MODE : INVERSE_NTT_MODE;
            encode_mode_op[0] = ENCODE_TRUE;
            naddr1_sel_op[0] = (done_op[0] && naddr1_sel_op[0] == K-1) ? 0 
                             : (done_op[0]) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];
                             
            // load rho back into Keccak
            k_fsm = 1;
            if (ctr == 0) begin
                // init keccak
                din_fsm       = {4'hE, 28'd512, 32'd256+{T1_LEN, 3'd0}}; //tr = 64 bytes
                src_ready_fsm = 0;  
            end else begin
                din_fsm       = rho[255:256-64];
                src_ready_fsm = (ctr == 5) ? 1 : 0;
            end
            
            ctr_next  = (ctr != 5 && src_read[2] && ~src_ready_fsm) ? ctr + 1 : ctr;            
        end
        {2'd0,KG_ADD_T_S2}: begin
            // ADD T and S2 (no encoder output — T1 encoded separately in KG_ENCODE_T1)
            rst_enc = 1;
            addra_ram3 = {addr1_sel_op[0], addra1_op[0]};
            addra_ram2 = {addr1_sel_op[0], addra2_op[0]};
            doa1_op[0]  = doa_ram3;
            doa2_op[0]  = doa_ram2;

            // write T to T
            addrb_ram3 = {addr1_sel_op[0], addrb2_op[0]};
            web_ram3   = web2_op[0];
            dib_ram3   = dib2_op[0];

            mode_op[0]  = ADD_MODE;

            rst_op[0]   = (done_op[0]) ? 1 : 0;
            naddr1_sel_op[0] = (done_op[0] && naddr1_sel_op[0] == K-1) ? 0
                             : (done_op[0] ) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];

            k_fsm = 1;
            nstate0 = (done_op[0] && addr1_sel_op[0] == K-1) ? KG_ENCODE_T1 : KG_ADD_T_S2;

        end
        {2'd0,KG_ENCODE_T1}: begin
            // Read T1 from RAM3 and encode
            mode_enc    = ENCODE_T1;
            addra_ram3  = ctr_t;
            valid_i_enc = enc_phase;
            di_enc      = {doa_ram3[24*3+:23],doa_ram3[24*2+:23],doa_ram3[24*1+:23],doa_ram3[24*0+:23]};

            // Unload T1 to encoder->AXI
            valid_o     = valid_o_enc;
            ready_o_enc = ready_o;
            data_o      = {do_enc[7:0],do_enc[15:8], do_enc[23:16], do_enc[31:24], do_enc[39:32], do_enc[47:40],do_enc[55:48], do_enc[63:56]};
            ctr_next    = (valid_o  && ready_o) ? ctr + 1 : ctr;
            nstate0      = (ctr == T1_LEN[11:3]-1 && valid_o && ready_o) ? KG_ENCODE_T0 : KG_ENCODE_T1;

            // Load T1 fifo -> Keccak (for tr computation)
            k_fsm = 1;
            case(sec_lvl)
            2: begin
                din_fsm       = keccak_fifo[159];
                src_ready_fsm = (keccak_valid[159] == 0) ? 1 : 0;
            end
            3: begin
                din_fsm       = keccak_fifo[239];
                src_ready_fsm = (keccak_valid[239] == 0) ? 1 : 0;
            end
            5: begin
                din_fsm       = keccak_fifo[319];
                src_ready_fsm = (keccak_valid[319] == 0) ? 1 : 0;
            end
            endcase
        end
        {2'd0,KG_ENCODE_T0}: begin
            // ENCODER
            mode_enc    = ENCODE_T0;
            addra_ram3  = ctr_t;
            valid_i_enc = enc_phase;
            di_enc      = {doa_ram3[24*3+:23],doa_ram3[24*2+:23],doa_ram3[24*1+:23],doa_ram3[24*0+:23]};
            
            // Unload T0 to encoder->AXI
            valid_o     = valid_o_enc;
            ready_o_enc = ready_o;
            data_o      = {do_enc[7:0],do_enc[15:8], do_enc[23:16], do_enc[31:24], do_enc[39:32], do_enc[47:40],do_enc[55:48], do_enc[63:56]};
            ctr_next    = (valid_o  && ready_o) ? ctr + 1 : ctr;
            nstate0      = (ctr == T0_LEN[11:3]-1 && valid_o && ready_o) ? KG_UNLOAD_TR : KG_ENCODE_T0;

            // Load T1 fifo -> Keccak  
            k_fsm = 1;
            case(sec_lvl)
            2: begin
                din_fsm       = keccak_fifo[159];
                src_ready_fsm = (keccak_valid[159] == 0) ? 1 : 0;   
            end
            3: begin
                din_fsm       = keccak_fifo[239];
                src_ready_fsm = (keccak_valid[239] == 0) ? 1 : 0;   
            end
            5: begin
                din_fsm       = keccak_fifo[319];
                src_ready_fsm = (keccak_valid[319] == 0) ? 1 : 0;   
            end
            endcase      
        end
        {2'd0,KG_UNLOAD_TR}: begin
            // Load T1 fifo -> Keccak     
            k_fsm = 1;   
            case(sec_lvl)
            2: begin
                din_fsm       = keccak_fifo[159];
                src_ready_fsm = (keccak_valid[159] == 0) ? 1 : 0;   
            end
            3: begin
                din_fsm       = keccak_fifo[239];
                src_ready_fsm = (keccak_valid[239] == 0) ? 1 : 0;   
            end
            5: begin
                din_fsm       = keccak_fifo[319];
                src_ready_fsm = (keccak_valid[319] == 0) ? 1 : 0;   
            end
            endcase  
        
            // Unload TR from SHAKE to AXI output
            dst_ready_fsm = !ready_o;
            valid_o  = dst_write[2];
            data_o    = dout[2];
            ctr_next    = (ctr == 7 && valid_o && ready_o) ? 0 
                        : (valid_o && ready_o) ? ctr + 1 : ctr; 
                        
            nstate0    = (ctr == 7 && valid_o && ready_o) ? KG_INIT : KG_UNLOAD_TR;
        end
        {2'd1,VY_INIT}: begin
            rst_enc   = (start) ? 0 : 1;
            rst_dec   = (start) ? 0 : 1;
            rst_k_fsm     = (start) ? 0 : 1;
            k_fsm = 1;
            rst_a     = (start) ? 0 : 1;
            rst_c     = (start) ? 0 : 1;
            rst_op[0] = (start) ? 0 : 1;
            rst_hint  =  (start) ? 0 : 1;
            start_hint = (start) ? 1 : 0;
            start_a    = (start) ? 1 : 0;
            start_c    = (start) ? 1 : 0;
            nstate0    = (start) ? VY_LOAD_RHO : VY_INIT;
            ctr_next = 0;
            ctr0_next = 0;

            naddr1_sel_op[0] = 0; 
            naddr2_sel_op[0] = 0; 
            naddr3_sel_op[0] = 0; 
        end
        {2'd1,VY_LOAD_RHO}: begin                      
            /* --- Datapath MUX --- */ 
            // AXI -> GenA         
            din_a     = data_i;
            valid_i_a = valid_i;
            ready_i_mux = 2;
            nstate0    = (ctr == 3 && ready_i_a && valid_i_a) ? VY_LOAD_C : VY_LOAD_RHO; 
            
            /* --- CTRL Logic --- */   
            if (ready_i_a && valid_i == 1) begin
                if (ctr == 3) begin
                    ctr_next = 0;
                end else begin
                    ctr_next = ctr + 1;
                end
            end else begin
                ctr_next = ctr;
            end 
        end
        {2'd1,VY_LOAD_C}: begin
            /* --- Datapath MUX --- */
            // AXI -> GenC
            din_c     = data_i;
            valid_i_c = valid_i;
            ready_i_mux = 3;
            nstate0   = (((ctr == 3 && sec_lvl == 2) || (ctr == 5 && sec_lvl == 3) || (ctr == 7 && sec_lvl == 5)) && ready_i_c && valid_i_c) ? VY_DECODE_Z : VY_LOAD_C; 
            
            k_fsm = 1;
            rst_k_fsm = rst_k_c;
            din_fsm = din_k_c;
            src_ready_fsm = src_ready_c;
            dst_ready_fsm = dst_ready_c;
            
            // GenA -> BRAM_A
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            /* --- CTRL Logic --- */
            ctr_next  = (((ctr == 3 && sec_lvl == 2) || (ctr == 5 && sec_lvl == 3) || (ctr == 7 && sec_lvl == 5)) && ready_i_c && valid_i_c) ? 0 
                      : (ready_i_c && valid_i_c) ? ctr + 1 : ctr;
            
        end
        {2'd1,VY_DECODE_Z}: begin        
            /* --- Datapath MUX --- */
            // AXI -> Decoder -> BRAM
            if (ctr < Z_LEN[12:3]) begin
                ready_i_mux = 4;
                valid_i_dec = valid_i;
                di_dec      = {data_i[0*8+:8],data_i[1*8+:8],data_i[2*8+:8],data_i[3*8+:8],
                               data_i[4*8+:8],data_i[5*8+:8],data_i[6*8+:8],data_i[7*8+:8]};
            end
            mode_dec    = ENCODE_Z;
            wea_ram1    = valid_o_dec;
            ready_o_dec = 1;
            addra_ram1  = ctr_dec;
            dia_ram1    = {1'd0, do_dec[3*23+:23], 1'd0, do_dec[2*23+:23], 1'd0, do_dec[1*23+:23], 1'd0, do_dec[0*23+:23]};
            
            // GenC -> BRAM_C    
            wea_ram3    = valid_o_c;
            addra_ram3  = ctr_c;
            dia_ram3    = {1'd0, samples_c[3*23+:23], 1'd0, samples_c[2*23+:23], 1'd0, samples_c[1*23+:23], 1'd0, samples_c[0*23+:23]};
            ready_o_c   = 1;
            
            k_fsm = 1;
            rst_k_fsm = (ctr0 == 0) ? rst_k_c : 0;
            din_fsm = din_k_c;
            src_ready_fsm = src_ready_c;
            dst_ready_fsm = dst_ready_c;
        
            // GenA -> BRAM_A
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            /* --- CTRL Logic --- */
            ctr_next  = (ctr_dec == {L, 6'd0}-1 && valid_o_dec && ready_o_dec) ? 0 
                        : (valid_i_dec && ready_i_dec) ? ctr + 1 : ctr;
                
            nstate0    = (ctr_dec == {L, 6'd0}-1 && valid_o_dec && ready_o_dec) ? VY_NTT_Z : VY_DECODE_Z;
            rst_dec   = (ctr_dec == {L, 6'd0}-1 && valid_o_dec && ready_o_dec) ? 1 : 0;

            // init and load RHO to keccak
            ctr0_next = (rst_dec) ? 0 : (done_c || (src_read[2] && ctr0 > 0)) ? ctr0 + 1 : ctr0;
            if (ctr0 == 1) begin
                src_ready_fsm = 0;
                din_fsm       = {4'hE, 28'd512, 32'd256+{T1_LEN, 3'd0}}; // tr = 64 bytes
            end else if (ctr0 > 1 && ctr0 < 6) begin
                // load rho
                src_ready_fsm = 0;
                din_fsm       = RHO[255:256-64];
            end else if (ctr0 >= 6) begin
                src_ready_fsm = 1;
            end
        end
        {2'd1,VY_NTT_Z}: begin
            /* --- Datapath MUX --- */
            // sampler a ctr
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+5'd1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            // NTT on Z
            addra_ram1 = {addr1_sel_op[0], addra1_op[0]};
            addrb_ram1 = {addr1_sel_op[0], addrb1_op[0]};
            web_ram1   = web1_op[0];
            dib_ram1   = dib1_op[0];
            doa1_op[0]  = doa_ram1;
            dob1_op[0]  = dob_ram1;
            
            // AXI -> Decode t1 & SHAKE
            k_fsm = 1;
            if (ctr < T1_LEN[12:3]) begin
                ready_i_mux = 1;
                src_ready_fsm   = ~(valid_i && ready_i_dec);
                valid_i_dec = src_read[2];
                di_dec      = {data_i[0*8+:8],data_i[1*8+:8],data_i[2*8+:8],data_i[3*8+:8],
                               data_i[4*8+:8],data_i[5*8+:8],data_i[6*8+:8],data_i[7*8+:8]};
                din_fsm         = data_i;
            end
            mode_dec    = ENCODE_T1;
            wea_ram2    = valid_o_dec;
            ready_o_dec = 1;
            addra_ram2  = ctr_dec;
            dia_ram2    = {1'd0, do_dec[3*23+:23], 1'd0, do_dec[2*23+:23], 1'd0, do_dec[1*23+:23], 1'd0, do_dec[0*23+:23]};
                        
            
            /* --- CTRL Logic --- */
            ctr_next  = (ntt_z_done && ctr >= T1_LEN[12:3] && ctr0 >= 8) ? 0
                        : (src_read[2]) ? ctr + 1 : ctr;

            ctr0_next = (ntt_z_done && ctr >= T1_LEN[12:3] && ctr0 >= 8) ? 0 : (dst_write[2]) ? ctr0 + 1 : ctr0;
            dst_ready_fsm = 0;

            nstate0      = (ntt_z_done && ctr >= T1_LEN[12:3] && ctr0 >= 8) ? VY_NTT_T1 : VY_NTT_Z;
            rst_op[0]   = (done_op[0] && !(ntt_z_done && ctr >= T1_LEN[12:3] && ctr0 >= 8)) ? 1 : 0;
            mode_op[0]  = FORWARD_NTT_MODE;
            naddr1_sel_op[0] = (ntt_z_done && ctr >= T1_LEN[12:3] && ctr0 >= 8) ? 0
                             : (done_op[0] && !ntt_z_done) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];

        end
        {2'd1,VY_NTT_T1}: begin
            /* --- Datapath MUX --- */
            // NTT on t1
            addra_ram2 = {addr1_sel_op[0], addra1_op[0]};
            addrb_ram2 = {addr1_sel_op[0], addrb1_op[0]};
            web_ram2   = web1_op[0];
            dib_ram2   = dib1_op[0];
            doa1_op[0]  = doa_ram2;
            dob1_op[0]  = dob_ram2;
        
            // sampler a ctr
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+5'd1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            /* --- CTRL Logic --- */
            nstate0      = ((ntt_verif_done && ({ctr0, 3'd0} >= mlen_PLUS144)))  ? VY_NTT_C : VY_NTT_T1;
            rst_op[0]   = (done_op[0] || ctr0 == 0) ? 1 : 0;
            mode_op[0]  = FORWARD_NTT_MODE;
            naddr1_sel_op[0] = (done_op[0] && addr1_sel_op[0] == K-1) ? 0 
                             : (done_op[0]) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];
                    
                             
            // load tr back into 
            ctr0_next = (ntt_verif_done && ({ctr0, 3'd0} >= mlen_PLUS144)) ?  0  //(((done_op[0] && addr1_sel_op[0] == K-1) && ({ctr0, 3'd0} >= mlen_PLUS144)) || ((addr1_sel_op[0] == 0) &&({ctr0, 3'd0} >= mlen_PLUS144)))
                        : (src_read[2] || dst_write[2]) ? ctr0 + 1 : ctr0;

            k_fsm = 1;
            if (ctr0 == 0) begin
                rst_k_fsm = 1;
                ctr0_next = ctr0 + 1;
            end else if (ctr0 == 1) begin
                src_ready_fsm = ~valid_i;
                // ready_i   = src_read[2];
                ready_i_mux = 1;
                din_fsm       = {4'hE, 28'd512, 32'd512+{data_i[15:0] + 16'd2, 3'd0} }; //padding
            end else if (ctr0 < 10) begin // 64 bytes
                // ready_i   = 0;
                ready_i_mux = 0;
                src_ready_fsm = 0;
                din_fsm     = TR[511:512-64];
            end else begin
                src_ready_fsm   = ({ctr0, 3'd0} < mlen_PLUS80) ? ~valid_i : 1; //mlen_PLUS48
                din_fsm         = data_i;
                ready_i_mux     = ({ctr0, 3'd0} < mlen_PLUS80) ? 1 : 0;
                
                dst_ready_fsm   = ({ctr0, 3'd0} <= mlen_PLUS144) ? 0 : 1; // 64byte OUTPUT HERE <=
            end
        end
        {2'd1,VY_NTT_C}: begin
            /* --- Datapath MUX --- */
            // NTT on t1
            addra_ram3 = addra1_op[0];
            addrb_ram3 = addrb1_op[0];
            web_ram3   = web1_op[0];
            dib_ram3   = dib1_op[0];
            doa1_op[0]  = doa_ram3;
            dob1_op[0]  = dob_ram3;
        
            // sampler a ctr
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+5'd1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            // AXI -> Hint
            ready_i_mux      = 5;
            valid_i_hint = valid_i;
            di_hint      = data_i;
            
            /* --- CTRL Logic --- */
            mode_op[0]  = FORWARD_NTT_MODE;
            
            nstate0      = ((done_op[0] && sec_lvl != 5) || (done_a && sec_lvl == 5)) ? VY_MULT_AZ : VY_NTT_C; //
            rst_op[0]   = ((done_op[0] && sec_lvl != 5) || (done_a && sec_lvl == 5)) ? 1 : 0;
            
        end
        {2'd1,VY_MULT_AZ}: begin
            /* --- Datapath MUX --- */
            // multa: z, multb: a, acc: t   
            addra_ram1 = {addr1_sel_op[0], addra1_op[0]};
            addra_ram0  = {addr2_sel_op[0], addra2_op[0]};
            addra_ram2  = {addr3_sel_op[0], addrb1_op[0]} | 512;
            // write
            addrb_ram2 = {addr3_sel_op[0], addrb2_op[0]} | 512;
            web_ram2   = web2_op[0];
            dib_ram2   = dib2_op[0];
            
            doa1_op[0]  = doa_ram1;
            doa2_op[0]  = doa_ram0;
            dob1_op[0]  = (addr1_sel_op[0] == 0) ? 0 : doa_ram2; // only acc on s1[x] : x != 0
            
            
            /* --- CTRL Logic --- */
            // s1: naddr1_sel_op, a: naddr2_sel_op, t: naddr3_sel_op 
            mode_op[0]        = MULT_MODE;
            encode_mode_op[0] = ENCODE_TRUE;
            
            if (done_op[0]) begin
                rst_op[0] = 1;
                naddr2_sel_op[0] = addr2_sel_op[0] + 1;
                if (naddr1_sel_op[0] == L - 1) begin
                    naddr1_sel_op[0] = 0;
                    if (naddr3_sel_op[0] == K - 1) begin
                        naddr3_sel_op[0] = 0;
                        naddr2_sel_op[0] = 0;
                        
                        // end of mult
                        nstate0 = VY_MULT_CT1;
                    end else begin
                        naddr3_sel_op[0] = addr3_sel_op[0] + 1;
                    end
                end else begin
                    naddr1_sel_op[0] = addr1_sel_op[0] + 1;
                end
            end
        end
        {2'd1,VY_MULT_CT1}: begin
            /* --- Datapath MUX --- */
            // multa: t1, multb: c, acc: none   
            addra_ram2  = {addr1_sel_op[0], addra1_op[0]};
            addra_ram3  = addra2_op[0];
            // write
            addrb_ram2 = {addr1_sel_op[0], addrb2_op[0]};
            web_ram2   = web2_op[0];
            dib_ram2   = dib2_op[0];
            
            doa1_op[0]  = doa_ram2;
            doa2_op[0]  = doa_ram3;
            
            /* --- CTRL Logic --- */
            mode_op[0]        = MULT_MODE;
            
            if (done_op[0]) begin
                rst_op[0] = 1;
                if (naddr1_sel_op[0] == K - 1) begin
                    naddr1_sel_op[0] = 0;
                    
                    // end of mult
                    nstate0 = VY_SUB_AZ_CT1;
                end else begin
                    naddr1_sel_op[0] = addr1_sel_op[0] + 1;
                end
            end
        end
        {2'd1,VY_SUB_AZ_CT1}: begin
            /* --- Datapath MUX --- */
            mode_op[0]  = (done_op[0] && addr1_sel_op[0] == K-1) ? INVERSE_NTT_MODE : SUB_MODE;
            // SUB Az and ct1
            addra_ram2 = {addr1_sel_op[0], addra1_op[0]} | 512;
            addrb_ram2 = {addr1_sel_op[0], addra1_op[0]};
            doa1_op[0]  = doa_ram2;
            doa2_op[0]  = dob_ram2;
            
            // write
            addrb_ram1 = {addr1_sel_op[0], addrb2_op[0]};
            web_ram1   = web2_op[0];
            dib_ram1   = dib2_op[0];

            /* --- CTRL Logic --- */
            rst_op[0]   = (done_op[0]) ? 1 : 0;
            naddr1_sel_op[0] = (done_op[0] && addr1_sel_op[0] == K-1) ? 0 
                             : (done_op[0] ) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];
            nstate0 = (done_op[0] && addr1_sel_op[0] == K-1) ? VY_INTT : VY_SUB_AZ_CT1;
        end
        {2'd1,VY_INTT}: begin
            /* --- Datapath MUX --- */
            // NTTI on Z (Az-ct1)
            addra_ram1 = {addr1_sel_op[0], addra1_op[0]};
            addrb_ram1 = {addr1_sel_op[0], addrb1_op[0]};
            web_ram1   = web1_op[0];
            dib_ram1   = dib1_op[0];
            doa1_op[0]  = doa_ram1;
            dob1_op[0]  = dob_ram1;
            
            /* --- CTRL Logic --- */
            naddr1_sel_op[0] = (done_op[0] && addr1_sel_op[0] == K-1) ? 0 
                             : (done_op[0] ) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];
            nstate0    = (done_op[0] && addr1_sel_op[0] == K-1) ? VY_GENW1 : VY_INTT;
            rst_op[0]  = (done_op[0]) ? 1 : 0;
            mode_op[0] =  INVERSE_NTT_MODE;
            encode_mode_op[0] = ENCODE_TRUE;
            
            
            // load tr back into 
            ctr0_next = (done_op[0] && addr1_sel_op[0] == K-1) ? 0 
                        : (src_read[2] || dst_write[2]) ? ctr0 + 1 : ctr0;
            k_fsm = 1;
            if (ctr0 == 0) begin
                rst_k_fsm = 1;
                ctr0_next = ctr0 + 1;
            end else if (ctr0 == 1) begin
                src_ready_fsm = 0;
                din_fsm       = {4'hE, ctilde_out_len[28 - 1 : 0], 32'd512+5'd8*W1_LEN};
            end else if (ctr0 < 10) begin
                src_ready_fsm = 0;
                din_fsm       = MU[511:512-64];
            end
        end
        {2'd1,VY_GENW1}: begin
            /* --- Datapath MUX --- */
            dst_ready_fsm = 0;
            di_decomp  = doa_ram1;
            addra_ram1 = ctr;
            valid_i_decomp = (ctr > 0 && ready_i_decomp) ? 1 : 0;

            // Feed useHint for ctr tracking (keeps hint_ctr synchronized)
            poly_valid_i_hint = valid_o_decomp;
            poly_di0_hint     = doa_decomp;
            poly_di1_hint     = dob_decomp;
            poly_ready_o_hint = ready_i_enc;

            // Inline hint adjustment: bypass useHint data path
            // Uses exposed hint_poly_data and hint_ctr from useHint
            mode_enc = ENCODE_W1;
            valid_i_enc = valid_o_decomp;
            begin : gen_w1_inline
                integer ih;
                reg [95:0] w1_adj;
                w1_adj = dob_decomp;
                for (ih = 0; ih < 4; ih = ih + 1) begin
                    if (hint_poly_data[hint_ctr + ih] == 1'b1) begin
                        if (doa_decomp[ih*24+:24] > 261888 || doa_decomp[ih*24+:24] == 0)
                            w1_adj[ih*24+:24] = (dob_decomp[ih*24+:24] == 0) ? 24'd15 : dob_decomp[ih*24+:24] - 24'd1;
                        else
                            w1_adj[ih*24+:24] = (dob_decomp[ih*24+:24] == 15) ? 24'd0 : dob_decomp[ih*24+:24] + 24'd1;
                    end
                end
                di_enc = {w1_adj[24*3+:23], w1_adj[24*2+:23], w1_adj[24*1+:23], w1_adj[24*0+:23]};
            end

            // Direct backpressure: encoder → decompressor
            ready_o_decomp = ready_i_enc;

            // encoder to SHAKE
            k_fsm = 1;
            din_fsm = {do_enc[8*0+:8], do_enc[8*1+:8],do_enc[8*2+:8],do_enc[8*3+:8],do_enc[8*4+:8],do_enc[8*5+:8],do_enc[8*6+:8],do_enc[8*7+:8]};
            src_ready_fsm = !valid_o_enc;
            ready_o_enc = src_read[2];

            /* --- CTRL Logic --- */
            nstate0     = (ctr == K*64) ? VY_COMPARE : VY_GENW1;
            ctr_next   = (ctr == K*64) ? 0
                       : (ready_i_decomp) ? ctr + 1
                       : ctr;
        end
        {2'd1,VY_COMPARE}: begin
            /* --- Datapath MUX --- */
            di_decomp  = doa_ram1;
            addra_ram1 = ctr;
            valid_i_decomp = 0;

            // Fix 9: encoder input directly from decompressor pipeline (bypass useHint)
            // useHint is in EXPAND_HINT state during VY_COMPARE and blocks data flow.
            // Maintaining the VY_GENW1 data path allows the encoder PISO to drain to Keccak.
            mode_enc = ENCODE_W1;
            valid_i_enc = valid_o_decomp;
            begin : vy_cmp_enc
                integer ih2;
                reg [95:0] w1_adj2;
                w1_adj2 = dob_decomp;
                for (ih2 = 0; ih2 < 4; ih2 = ih2 + 1) begin
                    if (hint_poly_data[hint_ctr + ih2] == 1'b1) begin
                        if (doa_decomp[ih2*24+:24] > 261888 || doa_decomp[ih2*24+:24] == 0)
                            w1_adj2[ih2*24+:24] = (dob_decomp[ih2*24+:24] == 0) ? 24'd15 : dob_decomp[ih2*24+:24] - 24'd1;
                        else
                            w1_adj2[ih2*24+:24] = (dob_decomp[ih2*24+:24] == 15) ? 24'd0 : dob_decomp[ih2*24+:24] + 24'd1;
                    end
                end
                di_enc = {w1_adj2[24*3+:23], w1_adj2[24*2+:23], w1_adj2[24*1+:23], w1_adj2[24*0+:23]};
            end
            ready_o_decomp = ready_i_enc;

            // encoder to SHAKE
            k_fsm = 1;
            din_fsm = {do_enc[8*0+:8], do_enc[8*1+:8],do_enc[8*2+:8],do_enc[8*3+:8],do_enc[8*4+:8],do_enc[8*5+:8],do_enc[8*6+:8],do_enc[8*7+:8]};
            src_ready_fsm = !valid_o_enc;
            ready_o_enc = src_read[2];

            // Block Keccak output after absorbing c~hat' to avoid interfering with diagnostic output
            dst_ready_fsm = ((ctr < 4 && sec_lvl == 2) || (ctr < 6 && sec_lvl == 3) || (ctr < 8 && sec_lvl == 5)) ? 0 : 1;

            /* --- CTRL Logic --- */
            // fix: reverted to baseline single-word fail output. The previous code
            // emitted 7 diagnostic words (TR, MU, hash, c, fail, rho, ntt_z_ctr0)
            // for sec_lvl=3, but the testbench (and any spec-compliant verify
            // consumer) reads ONE word: the fail bit (0=valid, 1=invalid). The
            // first word at ctr=6 was TR (0xe247931e1c7bdfd0 in KAT#0), not fail,
            // so the testbench saw "valid" when KAT expects "invalid".
            ctr_next = (dst_write[2]) ? ctr + 1 : ctr;
            valid_o = ((ctr == 4 && sec_lvl == 2) || (ctr == 6 && sec_lvl == 3) || (ctr == 8 && sec_lvl == 5)) ? 1 : 0;
            data_o  = ((ctr == 4 && sec_lvl == 2) || (ctr == 6 && sec_lvl == 3) || (ctr == 8 && sec_lvl == 5)) ? {63'd0, fail} : 0;
            nstate0  = (ready_o && valid_o) ? VY_INIT : VY_COMPARE;
        end
        {2'd2,FSM0_INIT}: begin
            rst_enc  = (start) ? 0 : 1;
            rst_dec    = (start) ? 0 : 1;
            rst_geny   = (start) ? 0 : 1;
            rst_a      = (start) ? 0 : 1;
            rst_c      = (start) ? 0 : 1;
            rst_op[0]  = (start) ? 0 : 1;
            rst_op[1]  = (start) ? 0 : 1;
            rst_mh     = (start) ? 0 : 1;
            start_a    = (start) ? 1 : 0;
            start_c    = (start) ? 1 : 0;
            
            naddr1_sel_op[0] = 0; 
            naddr2_sel_op[0] = 0; 
            naddr3_sel_op[0] = 0;
            naddr1_sel_op[1] = 0; 
            naddr2_sel_op[1] = 0; 
            naddr3_sel_op[1] = 0;
            
            ctr_next   = 0;
            ctr0_next  = 0;
            ctr1_next  = 0;
            
            nstate0     = (start) ? FSM0_LOAD_RHO : FSM0_INIT; 
        end
        {2'd2,FSM0_LOAD_RHO}: begin
            /* --- Datapath MUX --- */ 
            // AXI -> GenA         
            din_a     = data_i;
            valid_i_a = valid_i;
            ready_i_mux = 2;
            nstate0    = (ctr == 3 && ready_i_a && valid_i_a) ? FSM0_LOAD_MU : FSM0_LOAD_RHO; 
            
            /* --- CTRL Logic --- */   
            if (ready_i_a && valid_i == 1) begin
                if (ctr == 3) begin
                    ctr_next = 0;
                end else begin
                    ctr_next = ctr + 1;
                end
            end else begin
                ctr_next = ctr;
            end 
        end
        {2'd2,FSM0_LOAD_MU}: begin
            /* --- Datapath MUX --- */ 
            // AXI -> GenY
            if (ctr1 > 0) begin
                ready_i_mux = 6;
                valid_i_geny = valid_i;
                di_geny      = data_i;         
                ctr1_next  = (valid_i && ready_i) ? ctr1 + 1 : ctr1;
            end else begin
                ready_i_mux = 7;
                start_geny = (valid_i && ready_i) ? 1 : 0;
                ctr1_next  = (valid_i && ready_i) ? ctr1 + 1 : ctr1;
            end
            
            // GenA -> BRAM_A
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            /* --- CTRL Logic --- */ 
            if ({ctr1,3'd0} > mlen_PLUS128) begin // tr + K + rnd
                nstate0 = FSM0_DECODE_S1;
                ctr1_next = 0;
                nstart_fsm1 = 1;
            end
            
        end
        {2'd2,FSM0_DECODE_S1}: begin
            /* --- Datapath MUX --- */ 
            // AXI -> Decoder -> BRAM
            if (ctr < S1_LEN[12:3]) begin
                ready_i_mux = 4;
                valid_i_dec = valid_i;
                di_dec      = {data_i[0*8+:8],data_i[1*8+:8],data_i[2*8+:8],data_i[3*8+:8],
                               data_i[4*8+:8],data_i[5*8+:8],data_i[6*8+:8],data_i[7*8+:8]};
            end
            mode_dec    = ENCODE_S1;
            ready_o_dec = 1;
            wea_ram3    = valid_o_dec;
            addra_ram3  = ctr_dec;
            dia_ram3    = {1'd0, do_dec[3*23+:23], 1'd0, do_dec[2*23+:23], 1'd0, do_dec[1*23+:23], 1'd0, do_dec[0*23+:23]};
            
            // GenA -> BRAM_A
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            /* --- CTRL Logic --- */ 
            ctr_next  = (ctr_dec == {L,6'd0}-1) ? 0 
                        : (valid_i_dec && ready_i_dec) ? ctr + 1 : ctr;
                
            
            nstate0 = (ctr_dec == {L,6'd0}-1) ? FSM0_NTT_S1 : FSM0_DECODE_S1;
            rst_dec = (ctr_dec == {L,6'd0}-1) ? 1 : 0;
            
        end
        {2'd2,FSM0_NTT_S1}: begin
            /* --- Datapath MUX --- */ 
            // AXI -> Decoder -> BRAM
            if (ctr < S2_LEN[12:3]) begin
                ready_i_mux = 4;
                valid_i_dec = valid_i;
                di_dec      = {data_i[0*8+:8],data_i[1*8+:8],data_i[2*8+:8],data_i[3*8+:8],
                               data_i[4*8+:8],data_i[5*8+:8],data_i[6*8+:8],data_i[7*8+:8]};
            end
            mode_dec    = ENCODE_S2;
            ready_o_dec = 1;
            wea_ram5    = valid_o_dec;
            addra_ram5  = ctr_dec;
            dia_ram5    = {1'd0, do_dec[3*23+:23], 1'd0, do_dec[2*23+:23], 1'd0, do_dec[1*23+:23], 1'd0, do_dec[0*23+:23]};
            
            // GenA -> BRAM_A
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            // NTT S1
            addra_ram3 = {addr1_sel_op[1], addra1_op[1]};
            addrb_ram3 = {addr1_sel_op[1], addrb1_op[1]};
            web_ram3   = web1_op[1];
            dib_ram3   = dib1_op[1];
            doa1_op[1]  = doa_ram3;
            dob1_op[1]  = dob_ram3;
            
            /* --- CTRL Logic --- */
            // fix: reverted to baseline — prior code required ctr_dec==K*64-1 which is
            // impossible for S1 (only L*64-1 decoder outputs). Sign hung here. The
            // s1_ntt_all_done sticky stays declared for diagnostics but no longer gates
            // the transition; simple done_op[1] && addr1==L-1 is the original condition.
            ctr_next  = (done_op[1] && addr1_sel_op[1] == L-1) ? 0
                        : (valid_i_dec && ready_i_dec) ? ctr + 1 : ctr;

            nstate0    = (done_op[1] && addr1_sel_op[1] == L-1) ? FSM0_NTT_S2 : FSM0_NTT_S1;
            rst_dec   = (ctr_dec == {K, 6'd0}-1 && valid_o_dec && ready_o_dec) ? 1 : 0;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = FORWARD_NTT_MODE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == L-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
        end
        {2'd2,FSM0_NTT_S2}: begin
            /* --- Datapath MUX --- */ 
            // AXI -> Decoder -> BRAM
            if (ctr < T0_LEN[12:3]) begin
                ready_i_mux = 4;
                valid_i_dec = valid_i;
                di_dec      = {data_i[0*8+:8],data_i[1*8+:8],data_i[2*8+:8],data_i[3*8+:8],
                               data_i[4*8+:8],data_i[5*8+:8],data_i[6*8+:8],data_i[7*8+:8]};
            end
            mode_dec    = ENCODE_T0;
            ready_o_dec = 1;
            wea_ram3    = valid_o_dec;
            addra_ram3  = 512 | ctr_dec;
            dia_ram3    = {1'd0, do_dec[3*23+:23], 1'd0, do_dec[2*23+:23], 1'd0, do_dec[1*23+:23], 1'd0, do_dec[0*23+:23]};

            // fix: debug instrumentation (DECT0, DECDI) removed after T0 stall fix verified.
            
            // GenA -> BRAM_A
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
            
            // NTT S2
            addra_ram5 = {addr1_sel_op[1], addra1_op[1]};
            addrb_ram5 = {addr1_sel_op[1], addrb1_op[1]};
            web_ram5   = web1_op[1];
            dib_ram5   = dib1_op[1];
            doa1_op[1]  = doa_ram5;
            dob1_op[1]  = dob_ram5;
            
            /* --- CTRL Logic --- */
            // fix: reverted to baseline — same reason as FSM0_NTT_S1. The
            // s2_ntt_all_done sticky stays declared but no longer gates transition.
            ctr_next  = (done_op[1] && addr1_sel_op[1] == K-1) ? 0
                        : (valid_i_dec && ready_i_dec) ? ctr + 1 : ctr;

            nstate0    = (done_op[1] && addr1_sel_op[1] == K-1) ? FSM0_NTT_T0 : FSM0_NTT_S2;
            rst_dec   = (ctr_dec == {K, 6'd0}-1 && valid_o_dec && ready_o_dec) ? 1 : 0;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = FORWARD_NTT_MODE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == K-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
        end
        {2'd2,FSM0_NTT_T0}: begin
            /* --- Datapath MUX --- */ 
            // NTT S2
            addra_ram3 = 512 | {addr1_sel_op[1], addra1_op[1]};
            addrb_ram3 = 512 | {addr1_sel_op[1], addrb1_op[1]};
            web_ram3   = web1_op[1];
            dib_ram3   = dib1_op[1];
            doa1_op[1]  = doa_ram3;
            dob1_op[1]  = dob_ram3;
        
            // GenA -> BRAM_A
            wea_ram0   = valid_o_a[0];
            ready_o_a[0]  = 1;
            addra_ram0 = {sample_state, ctr_a1};
            dia_ram0   = {1'd0, samples_a[3*23+:23], 1'd0, samples_a[2*23+:23], 1'd0, samples_a[1*23+:23], 1'd0, samples_a[0*23+:23]};

            web_ram0   = valid_o_a[1];
            ready_o_a[1]  = 1;
            addrb_ram0 = {sample_state+1'b1, ctr_a2};
            dib_ram0   = {1'd0, samples_a[7*23+:23], 1'd0, samples_a[6*23+:23], 1'd0, samples_a[5*23+:23], 1'd0, samples_a[4*23+:23]};
        
            /* --- CTRL Logic --- */ 
            nstate0    = (done_op[1] && addr1_sel_op[1] == K-1) ? FSM0_STALL : FSM0_NTT_T0;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = FORWARD_NTT_MODE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == K-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
        end
        {2'd2,FSM0_STALL}: begin
            nstate0 = (cstart_fsm0) ? FSM0_UNLOAD_Z :  FSM0_STALL;
        end
        {2'd2,FSM0_UNLOAD_Z}: begin
            /* --- Datapath MUX --- */
            // MEM -> ENCODER -> AXI
            mode_enc    = ENCODE_Z;
            valid_i_enc = (ctr != 0 && ctr[0] == 0 && ctr < L*64*2+2) && !(valid_o_enc && !ready_o);
            di_enc      = {doa_ram6[24*3+:23], doa_ram6[24*2+:23],doa_ram6[24*1+:23],doa_ram6[24*0+:23]};
            // fix: hold addra_ram6 one address BEHIND during output stall.
            // dual_port_ram has 1-cycle registered read latency, so doa_ram6
            // reflects addra_ram6 from the PREVIOUS cycle. In no-stall operation
            // ctr increments every cycle, and di_enc at ctr=2K shows word K-1
            // (lag of 1). During stall, ctr holds at 2K and addra holds at K,
            // so doa_ram6 catches up to word K after 1 cycle — diverging from
            // the FSM's expectation. When stall ends, valid_i_enc=1 accepts
            // word K (not K-1), and 2 cycles later accepts word K AGAIN (RAM
            // lag still showing word K). Result: word K-1 missed, word K
            // duplicated — observable as +80-bit shift in the output stream.
            // Holding addra at (ctr>>1)-1 during stall keeps doa_ram6 at word
            // K-1 throughout, preserving the no-stall di_enc/ctr relationship.
            addra_ram6  = (valid_o_enc && !ready_o) ? ((ctr >> 1) - 1) : (ctr >> 1);

            ready_o_enc = ready_o;
            valid_o     = valid_o_enc;
            data_o      = {do_enc[8*0+:8], do_enc[8*1+:8],do_enc[8*2+:8],do_enc[8*3+:8],do_enc[8*4+:8],do_enc[8*5+:8],do_enc[8*6+:8],do_enc[8*7+:8]};


            /* --- CTRL Logic --- */
            // fix: hold ctr on output stall. With the addra_ram6 fix above,
            // the FSM/encoder/RAM stay aligned during stall — no duplicate
            // accepts when stall ends. The original encoder (ready_i=1
            // always) makes the ready_i_enc term a no-op; kept for safety.
            ctr_next = (valid_o_enc && !ready_o)            ? ctr :
                       (valid_i_enc && !ready_i_enc)        ? ctr :
                       ctr + 1;

            if (ctr >= L*64*2+4 && !valid_o_enc) begin
                nstate0  = FSM0_UNLOAD_H;
                ctr_next = 0;
                rst_enc  = 1;
            end
        end
        {2'd2,FSM0_UNLOAD_H}: begin
            /* --- Datapath MUX --- */ 
            // MAKEHINT -> AXI
            readyo_mh = ready_o;
            valid_o   = valido_mh;
            data_o    = {hint_o[8*0+:8], hint_o[8*1+:8],hint_o[8*2+:8],hint_o[8*3+:8],hint_o[8*4+:8],hint_o[8*5+:8],hint_o[8*6+:8],hint_o[8*7+:8]};
            
            /* --- CTRL Logic --- */ 
            ctr_next = (ready_o && valid_o) ? ctr + 1 : ctr;
            if (((ctr == 10 && sec_lvl != 3) || (ctr == 7 && sec_lvl == 3)) && ready_o && valid_o) begin
                nstate0  = FSM0_UNLOAD_C;
                ctr_next = 0;
            end
        end
        {2'd2,FSM0_UNLOAD_C}: begin
            /* --- Datapath MUX --- */
            // MAKEHINT -> GENC
            read_ch_c = ready_o;
            data_o    = ch_c;
            valid_o   = 1;
            ctr_next = (ready_o) ? ctr + 1 : ctr;
            /* --- CTRL Logic --- */
            if (((ctr == 3 && sec_lvl == 2) || (ctr == 5 && sec_lvl == 3) || (ctr == 7 && sec_lvl == 5))  && ready_o) begin
                nstate0  = FSM0_INIT;
                ctr_next = 0;
            end
        end
        endcase
            
        case(cstate1) 
        FSM1_STALL: begin
            // OP 0
            ctrfsm1_next = 0;
            nstate1 = (cstart_fsm1) ? FSM1_GENY : FSM1_STALL;
            start_geny = (cstart_fsm1 && cstate0 == FSM0_STALL) ? 1 : start_geny;
        end
        FSM1_GENY: begin
            addra_ram1   = {fsm1_even, 9'd0} | ctrfsm1;
            dia_ram1     = {1'b0,do_geny[23*3+:23],1'b0,do_geny[23*2+:23],1'b0,do_geny[23*1+:23],1'b0,do_geny[23*0+:23]};
            wea_ram1     = valid_o_geny;
            ready_o_geny = 1 && ((cstate2 >= 5'd5) || (cstate2 == 0));
            
            if (valid_o_geny && ready_o_geny) begin
                if (ctrfsm1 == {L, 6'd0}-1) begin
                    ctrfsm1_next = 0;
                    nstate1      = FSM1_WAIT;
                end else begin
                    ctrfsm1_next = ctrfsm1 + 1;
                end
            end
        end
        FSM1_WAIT: begin
            nstate1 = FSM1_NTT_Y;
            mode_op[0]  = FORWARD_NTT_MODE;
            rst_op[0]   = 1;
        end
        FSM1_NTT_Y: begin
            /* --- Datapath MUX --- */ 
            // NTT Y
            addra_ram1 = {fsm1_even, 9'd0} | {addr1_sel_op[0], addra1_op[0]};
            addrb_ram1 = {fsm1_even, 9'd0} | {addr1_sel_op[0], addrb1_op[0]};
            web_ram1   = web1_op[0];
            dib_ram1   = dib1_op[0];
            doa1_op[0]  = doa_ram1;
            dob1_op[0]  = dob_ram1;
            
            
        
            /* --- CTRL Logic --- */ 
            if (a_generated || cstate0 == 7) begin ////(sec_lvl == 2 || cstate0 == 7)   (a_generated || cstate0 == 7)
                nstate1    = (done_op[0] && addr1_sel_op[0] == L-1) ? FSM1_MULT_A_Y : FSM1_NTT_Y;
                rst_op[0]   = (done_op[0]) ? 1 : 0;
            end else begin
                // sampleA is bottleneck
                nstate1    = (a_generated_during && op_done_ntty) ? FSM1_MULT_A_Y : FSM1_NTT_Y;
                rst_op[0]   = ((done_op[0] && addr1_sel_op[0] != L-1) || (a_generated_during && op_done_ntty)) ? 1 : 0; // 
            end
            
            //rst_op[0]   = (done_op[0]) ? 1 : 0;
            
            
            mode_op[0]  = FORWARD_NTT_MODE;
            naddr1_sel_op[0] = (done_op[0] && addr1_sel_op[0] == L-1) ? 0 
                             : (done_op[0]) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];
        end
        FSM1_MULT_A_Y: begin
            
            // multa: y, multb: a, acc: w   
            addra_ram1 = {fsm1_even, 9'd0} | {addr1_sel_op[0], addra1_op[0]};
            addra_ram0  = {addr2_sel_op[0], addra2_op[0]};
            addra_ram2  = {addr3_sel_op[0], addrb1_op[0]};
            // write
            addrb_ram2 = {addr3_sel_op[0], addrb2_op[0]};
            web_ram2   = web2_op[0];
            dib_ram2   = dib2_op[0];
            
            doa1_op[0]  = doa_ram1;
            doa2_op[0]  = doa_ram0;
            dob1_op[0]  = (addr1_sel_op[0] == 0) ? 0 : doa_ram2; // only acc on s1[x] : x != 0
            
            // s1: naddr1_sel_op, a: naddr2_sel_op, t: naddr3_sel_op 
            mode_op[0]  = MULT_MODE;
            encode_mode_op[0] = ENCODE_TRUE;
            
            if (done_op[0]) begin
                rst_op[0] = 1;
                naddr2_sel_op[0] = addr2_sel_op[0] + 1;
                if (naddr1_sel_op[0] == L - 1) begin
                    naddr1_sel_op[0] = 0;
                    if (naddr3_sel_op[0] == K - 1) begin
                        naddr3_sel_op[0] = 0;
                        naddr2_sel_op[0] = 0;
                        
                        // end of mult
                        nstate1 = FSM1_NTTI_W;
                    end else begin
                        naddr3_sel_op[0] = addr3_sel_op[0] + 1;
                    end
                end else begin
                    naddr1_sel_op[0] = addr1_sel_op[0] + 1;
                end
            end
            
        end
        FSM1_NTTI_W: begin
            /* --- Datapath MUX --- */ 
            // NTTI W
            addra_ram2 = {addr1_sel_op[0], addra1_op[0]};
            addrb_ram2 = {addr1_sel_op[0], addrb1_op[0]};
            web_ram2   = web1_op[0];
            dib_ram2   = dib1_op[0];
            doa1_op[0]  = doa_ram2;
            dob1_op[0]  = dob_ram2;
        
            /* --- CTRL Logic --- */ 
            nstate1    = (done_op[0] && addr1_sel_op[0] == K-1) ? FSM1_STALL : FSM1_NTTI_W;
            nstart_fsm2 = (done_op[0] && addr1_sel_op[0] == K-1) ? 1 : 0;
            
            rst_op[0]   = (done_op[0]) ? 1 : 0;
            mode_op[0]  = INVERSE_NTT_MODE;
            encode_mode_op[0] = ENCODE_TRUE;
            naddr1_sel_op[0] = (done_op[0] && addr1_sel_op[0] == K-1) ? 0 
                             : (done_op[0]) ? addr1_sel_op[0] + 1 : addr1_sel_op[0];
        end
        endcase
        
        
        case(cstate2)
        FSM2_STALL: begin
            nstart_fsm1  = (cstate0 < 7 && mode == 2) ? 1 : 0;
            ctrfsm2_next = 0;
            ctr0fsm2_next = 0;
            
            nstate2 = (cstart_fsm2 && !cstart_fsm0) ? FSM2_DECOMP : FSM2_STALL;
            rst_mh  = (cstart_fsm2 && !cstart_fsm0) ? 1 : 0;
        end
        FSM2_DECOMP: begin
            /* --- Datapath MUX --- */
            di_decomp  = doa_ram2;
            addra_ram2 = ctrfsm2;
            valid_i_decomp =  (ctrfsm2 > 0 && ctrfsm2 <= K*64 && ready_i_decomp && ready_i_decomp_last) ? 1 : 0; //ready_i_enc
            ready_o_decomp = ready_i_enc;
            
            // decomp to encoder
            mode_enc    = ENCODE_W1;
            valid_i_enc = valid_o_decomp;
            di_enc = {dob_decomp[24*3+:23], dob_decomp[24*2+:23], dob_decomp[24*1+:23], dob_decomp[24*0+:23]};
            
            // encoder to SHAKE
            din_c = {do_enc[8*0+:8], do_enc[8*1+:8],do_enc[8*2+:8],do_enc[8*3+:8],do_enc[8*4+:8],do_enc[8*5+:8],do_enc[8*6+:8],do_enc[8*7+:8]}; 
            valid_i_c = valid_o_enc;
            ready_o_enc = ready_i_c;
            
            wea_ram4 = (valid_o_decomp && ready_i_enc) ? 1 : 0;
            web_ram4 = (valid_o_decomp && ready_i_enc) ? 1 : 0;
            addra_ram4 = ctr0fsm2 | 512;
            addrb_ram4 = ctr0fsm2;
            dia_ram4 = doa_decomp;
            dib_ram4 = dob_decomp;
            
            ctr0fsm2_next = (valid_o_decomp && ready_i_enc || (ctr0fsm2 >= K*64-1)) ? ctr0fsm2 + 1 : ctr0fsm2;
            
            
            /* --- CTRL Logic --- */
            rst_decomp = (ctr0fsm2 >= K*64-1 + 6) ? 1 : 0;
            rst_enc    = (ctr0fsm2 >= K*64-1 + 6) ? 1 : 0;
            nstate2    = (ctr0fsm2 >= K*64-1 + 6) ? FSM2_GEN_C : FSM2_DECOMP;
            ctrfsm2_next   = (ctr0fsm2 >= K*64-1 + 6)  ? 0 
                       : (ready_i_decomp) ? ctrfsm2 + 1
                       : (ready_i_decomp == 0 && ready_i_decomp_last == 1) ? ctrfsm2 - 1: ctrfsm2;
        end
        FSM2_GEN_C: begin
            addra_ram0 = 3584 | ctrfsm2;
            dia_ram0 = {1'b0,samples_c[23*3+:23],1'b0,samples_c[23*2+:23],1'b0,samples_c[23*1+:23],1'b0,samples_c[23*0+:23]};
            wea_ram0 = valid_o_c;
            ready_o_c = 1;
            
            nstate2     = (done_c) ? FSM2_NTT_C : FSM2_GEN_C;
            //nstart_fsm1  = (done_c) ? 1 : 0;
            rst_op[1]    = (done_c) ? 1 : 0;
            
            ctrfsm2_next = (done_c) ? 0 
                            : (valid_o_c) ? ctrfsm2 + 1 : ctrfsm2;
        end
        FSM2_NTT_C: begin
            /* --- Datapath MUX --- */ 
            // NTTI W
            addra_ram0 = 3584 | {addr1_sel_op[1], addra1_op[1]};
            addrb_ram0 = 3584 | {addr1_sel_op[1], addrb1_op[1]};
            web_ram0   = web1_op[1];
            dib_ram0   = dib1_op[1];
            doa1_op[1]  = doa_ram0;
            dob1_op[1]  = dob_ram0;
        
            /* --- CTRL Logic --- */ 
            nstate2     = (done_op[1]) ? FSM2_MULTACC : FSM2_NTT_C;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = FORWARD_NTT_MODE;
            naddr1_sel_op[1] = 0;
        end
        FSM2_MULTACC: begin
            // y+c*s1
            // multa: c, multb: s1, acc: y   
            addra_ram3 = {addr1_sel_op[1], addra1_op[1]};
            addra_ram0 = 3584 | addra2_op[1];
            addrb_ram1 = {!fsm1_even, 9'd0} | {addr1_sel_op[1], addrb1_op[1]};
            // write
            addrb_ram6 = {addr1_sel_op[1], addrb2_op[1]};
            web_ram6   = web2_op[1];
            dib_ram6   = dib2_op[1];
            
            doa1_op[1]  = doa_ram3;
            doa2_op[1]  = doa_ram0;
            dob1_op[1]  = dob_ram1;
            
            // s1: naddr1_sel_op, a: naddr2_sel_op, t: naddr3_sel_op 
            mode_op[1]  = MULT_MODE;
            
            if (done_op[1]) begin
                rst_op[1] = 1;
                naddr1_sel_op[1] = addr1_sel_op[1] + 1;
                if (addr1_sel_op[1] == L - 1) begin
                    naddr1_sel_op[1] = 0;
                    nstate2 = FSM2_MULT_CS2;
                    nstart_fsm1 = 1;
                end 
            end
        end
        FSM2_MULT_CS2: begin
            // multa: c, multb: s2, acc: 0   
            addra_ram5 = {addr1_sel_op[1], addra1_op[1]};
            addra_ram0 = 3584 | addra2_op[1];
            // write
            addrb_ram5 = 512 | {addr1_sel_op[1], addrb2_op[1]};
            web_ram5   = web2_op[1];
            dib_ram5   = dib2_op[1];
            
            doa1_op[1]  = doa_ram5;
            doa2_op[1]  = doa_ram0;
            dob1_op[1]  = 0; // only acc on s1[x] : x != 0
            
            // s1: naddr1_sel_op, a: naddr2_sel_op, t: naddr3_sel_op 
            mode_op[1]  = MULT_MODE;
            
            if (done_op[1]) begin
                rst_op[1] = 1;
                naddr1_sel_op[1] = addr1_sel_op[1] + 1;
                if (addr1_sel_op[1] == K - 1) begin
                    naddr1_sel_op[1] = 0;
                    nstate2 = FSM2_MULT_CT0;
                    //nstart_fsm1 = 1;
                end 
            end
        end
        FSM2_MULT_CT0: begin
            // multa: c, multb: t0, acc: 0
            addra_ram3 = 512 | {addr1_sel_op[1], addra1_op[1]};
            addrb_ram0 = 3584 | addra2_op[1];
            // write
            addrb_ram6 = 512 | {addr1_sel_op[1], addrb2_op[1]};
            web_ram6   = web2_op[1];
            dib_ram6   = dib2_op[1];

            doa1_op[1]  = doa_ram3;
            doa2_op[1]  = dob_ram0;
            dob1_op[1]  = 0; // only acc on s1[x] : x != 0

            // fix: debug instrumentation (MULT_CT0) removed after T0 stall fix verified.
            
            // s1: naddr1_sel_op, a: naddr2_sel_op, t: naddr3_sel_op 
            mode_op[1]  = MULT_MODE;
            
            if (done_op[1]) begin
                rst_op[1] = 1;
                naddr1_sel_op[1] = addr1_sel_op[1] + 1;
                if (addr1_sel_op[1] == K - 1) begin
                    naddr1_sel_op[1] = 0;
                    nstate2 = FSM2_NTTI_Z;
                    //nstart_fsm1 = 1;
                end 
            end
        end
        FSM2_NTTI_Z: begin
            /* --- Datapath MUX --- */ 
            // NTTI Z
            addra_ram6 = {addr1_sel_op[1], addra1_op[1]};
            addrb_ram6 = {addr1_sel_op[1], addrb1_op[1]};
            web_ram6   = web1_op[1];
            dib_ram6   = dib1_op[1];
            doa1_op[1]  = doa_ram6;
            dob1_op[1]  = dob_ram6;
        
            // check Norm
            mode_norm = G1_SUB_BETA ;
            validi_norm = (web1_op[1] && ctrfsm2 >= 192) ? 1 : 0;
            di_norm = dib1_op[1];
            ctrfsm2_next = (done_op[1]) ? 0 
                        : (web1_op[1]) ? ctrfsm2 + 1 : ctrfsm2;
        
            /* --- CTRL Logic --- */ 
            nstate2    = (done_op[1] && addr1_sel_op[1] == L-1) ? FSM2_NTTI_CS2 : FSM2_NTTI_Z;
            //nstart_fsm1  = (done_op[1] && addr1_sel_op[1] == L-1) ? 1 : 0;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = INVERSE_NTT_MODE;
            encode_mode_op[1] = ENCODE_TRUE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == L-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
        end
        FSM2_NTTI_CS2: begin
            /* --- Datapath MUX --- */ 
            // NTTI CS2
            
            addra_ram5 = 512 | {addr1_sel_op[1], addra1_op[1]};
            addrb_ram5 = 512 | {addr1_sel_op[1], addrb1_op[1]};
            web_ram5   = web1_op[1];
            dib_ram5   = dib1_op[1];
            doa1_op[1]  = doa_ram5;
            dob1_op[1]  = dob_ram5;
        
            /* --- CTRL Logic --- */ 
            nstate2    = (done_op[1] && addr1_sel_op[1] == K-1) ? FSM2_NTTI_CT0 : FSM2_NTTI_CS2;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = INVERSE_NTT_MODE;
            encode_mode_op[1] = ENCODE_TRUE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == K-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
        end
        FSM2_NTTI_CT0: begin
            /* --- Datapath MUX --- */
            // NTTI CT0
            addra_ram6 = 512 | {addr1_sel_op[1], addra1_op[1]};
            addrb_ram6 = 512 | {addr1_sel_op[1], addrb1_op[1]};
            web_ram6   = web1_op[1];
            dib_ram6   = dib1_op[1];
            doa1_op[1]  = doa_ram6;
            dob1_op[1]  = dob_ram6;

            // fix: debug instrumentation (NTTI_CT0) removed after T0 stall fix verified.
        
            
            // check norm
            mode_norm   = G2 ;
            validi_norm = (web1_op[1] && ctrfsm2 > 192) ? 1 : 0;
            di_norm = dib1_op[1];
            ctrfsm2_next = (done_op[1]) ? 0 
                        : (web1_op[1]) ? ctrfsm2 + 1 : ctrfsm2;
            
        
            /* --- CTRL Logic --- */ 
            nstate2    = (done_op[1] && addr1_sel_op[1] == K-1) ? FSM2_SUB_W0_CS2 : FSM2_NTTI_CT0;
            
            
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = INVERSE_NTT_MODE;
            encode_mode_op[1] = ENCODE_TRUE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == K-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
        end
        FSM2_SUB_W0_CS2: begin
            /* --- Datapath MUX --- */
            // W0 - CS2: addra1: W0, addra2: CS2, addrb2:w0-cs2
            addra_ram4 = 512 | {addr1_sel_op[1], addra1_op[1]};
            addra_ram5 = 512 | {addr1_sel_op[1], addra2_op[1]};

            doa1_op[1]  = doa_ram4;
            doa2_op[1]  = doa_ram5;

            addrb_ram5 = 512 | {addr1_sel_op[1], addrb2_op[1]};
            web_ram5   = web2_op[1];
            dib_ram5   = dib2_op[1];

            // fix: debug instrumentation (SUB) removed after T0 stall fix verified.
        
            // Check norm
            mode_norm   = G2_SUB_BETA ;
            validi_norm = web2_op[1];
            di_norm     = dib2_op[1];
            
            /* --- CTRL Logic --- */ 
            nstate2    = (done_op[1] && addr1_sel_op[1] == K-1) ? FSM2_MAKEHINT : FSM2_SUB_W0_CS2;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = SUB_MODE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == K-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
        end 
        FSM2_MAKEHINT: begin
            /* --- Datapath MUX --- */
            // W0 - CS2: addra1: W0, addra2: CS2, addrb2:w0-cs2
            addra_ram6 = 512 | {addr1_sel_op[1], addra1_op[1]};
            addra_ram5 = 512 | {addr1_sel_op[1], addra2_op[1]};

            doa1_op[1]  = doa_ram6;
            doa2_op[1]  = doa_ram5;

            // fix: debug instrumentation (MHIN) removed after T0 stall fix verified.
            
            addrb_ram5 = 512 | {addr1_sel_op[1], addrb2_op[1]};
            web_ram5   = web2_op[1];
            dib_ram5   = dib2_op[1];
            
            // OP -> MakeHint
            addra_ram4 = (web2_op[1]) ? {addr1_sel_op[1], addrb2_op[1]} + 1 : {addr1_sel_op[1], addrb2_op[1]};
            
            validi_mh = web2_op[1];
            polyi0_mh = dib2_op[1];
            polyi1_mh = doa_ram4;
        
            /* --- CTRL Logic --- */ 
            nstate2 = FSM2_MAKEHINT;
            
            rst_op[1]   = (done_op[1]) ? 1 : 0;
            mode_op[1]  = ADD_MODE;
            naddr1_sel_op[1] = (done_op[1] && addr1_sel_op[1] == K-1) ? 0 
                             : (done_op[1]) ? addr1_sel_op[1] + 1 : addr1_sel_op[1];
                             
            if ((done_op[1] && addr1_sel_op[1] == K-1 && sec_lvl != 5) || (sec_lvl == 5 && done_op[0] && addr1_sel_op[0] == K-1)) begin
                if (reject_mh || norm_rejected) begin
                    nstate2 = FSM2_DECOMP;
                    rst_mh  = 1;
                    start_c = 1;
                    ctr0fsm2_next = 0;
                    ctrfsm2_next  = 0;
                    //nstart_fsm1 = 1;
                end else begin
                    nstart_fsm0 = 1;
                    nstate2     = FSM2_STALL;
                end                
            end
        end
        endcase

    end
    
    integer i;
    
    reg a_generated;
    reg a_generated_during;
    reg op_done_ntty;
    
    always @(posedge clk) begin
        mlen_PLUS48  <= mlen + 48;
        mlen_PLUS64  <= mlen + 64;
        mlen_PLUS80 <= mlen + 80;
//        mlen_PLUS96  <= mlen + 96;
        mlen_PLUS112 <= mlen + 112;
        mlen_PLUS128 <= ((mlen + 7) & 32'hFFFFFFF8) + 128;
        mlen_PLUS144 <= mlen + 144;
        mlen_PLUS152 <= mlen + 152;

        start_op[0] <= 0;
        start_op[1] <= 0;
        
        addr1_sel_op[0] <= naddr1_sel_op[0]; 
        addr2_sel_op[0] <= naddr2_sel_op[0]; 
        addr3_sel_op[0] <= naddr3_sel_op[0]; 
    
        addr1_sel_op[1] <= naddr1_sel_op[1]; 
        addr2_sel_op[1] <= naddr2_sel_op[1]; 
        addr3_sel_op[1] <= naddr3_sel_op[1]; 
    
        ready_i_decomp_last <= ready_i_decomp;
    
        norm_rejected <= (rej_norm) ? 1 : norm_rejected;
        
        shake_verif_done <= shake_verif_done;
        ntt_verif_done <= ntt_verif_done;
        ntt_z_done <= ntt_z_done;
    
        if (rst) begin
            cstate0 <= FSM0_INIT;
            cstate1 <= FSM1_STALL;
            cstate2 <= FSM2_STALL;
            ctr    <= 0;
            ctr0   <= 0;
            ctr1   <= 0;
            
            curr_y_used <= 0;
            op_done_ntty <= 0;
            
            ctrfsm2 <= 0;
            ctrfsm1 <= 0;
            ctr0fsm2 <= 0;
            
            mlen <= 0;
            norm_rejected <= 0;
            shake_verif_done <= 0;
            ntt_verif_done <= 0;
            ntt_z_done <= 0;
            s1_ntt_all_done <= 0;
            s2_ntt_all_done <= 0;
            
            fsm1_even <= 0;
            
            cstart_fsm0 <= 0;
            cstart_fsm1 <= 0;
            cstart_fsm2 <= 0;
            a_generated <= 0;
            a_generated_during <= 0;
            out_word_total <= 0;
            sticky_entered_t0 <= 0;
            sticky_entered_tr <= 0;
            owt_hash <= 0;
            owt_s1 <= 0;
            owt_s2 <= 0;
            owt_t1 <= 0;
            owt_t0 <= 0;
            owt_tr <= 0;
            sticky_cstart_fsm1 <= 0;
            sticky_start_geny  <= 0;
            sticky_src_read2   <= 0;
            sticky_valid_geny  <= 0;
            sticky_ready_geny  <= 0;
            sticky_multacc_entered <= 0;
            sticky_web6_fired      <= 0;
            sticky_start_op1_mult  <= 0;
            sticky_dib6_nonzero_multacc <= 0;
            sticky_dib6_nonzero_anywhere <= 0;
            multacc_web_count       <= 0;
            nttiz_web_count         <= 0;
            first_multacc_dib_low   <= 0;
            first_multacc_captured  <= 0;
            first_nttiz_dib_low     <= 0;
            first_nttiz_captured    <= 0;
            unload_addr_max         <= 0;
            multacc_done_count      <= 0;
            nttiz_done_count        <= 0;
            multacc_addr1_max       <= 0;
            nttiz_addr1_max         <= 0;
            multacc_addr1_at_exit   <= 0;
            multacc_last_addrb      <= 0;
            keccak_word_cnt    <= 0;
        end else begin
            // Count every completed output transfer
            if (valid_o && ready_o) begin
                out_word_total <= out_word_total + 1;
                case (cstate0)
                    4'd1, 4'd2: owt_hash <= owt_hash + 1;
                    4'd3:       owt_s1 <= owt_s1 + 1;
                    4'd4:       owt_s2 <= owt_s2 + 1;
                    4'd10:      owt_t1 <= owt_t1 + 1;
                    4'd8:       owt_t0 <= owt_t0 + 1;
                    4'd9:       owt_tr <= owt_tr + 1;
                    default:    ;
                endcase
            end
            cstate0 <= nstate0;
            cstate1 <= nstate1;
            cstate2 <= nstate2;
            ctr    <= ctr_next;
            ctr0   <= ctr0_next;
            ctr1   <= ctr1_next;
            
            ctrfsm2 <= ctrfsm2_next;
            ctrfsm1 <= ctrfsm1_next;
            ctr0fsm2 <= ctr0fsm2_next;
            
            cstart_fsm0 <= nstart_fsm0;
            cstart_fsm1 <= nstart_fsm1;
            cstart_fsm2 <= nstart_fsm2;

            // Sticky diagnostic flags (latch on rising edge, cleared by rst)
            if (nstart_fsm1 && !cstart_fsm1)
                sticky_cstart_fsm1 <= 1;
            if (start_geny && !sticky_start_geny)
                sticky_start_geny <= 1;
            if (src_read[2] && !sticky_src_read2)
                sticky_src_read2 <= 1;
            if (src_read[2] && k_fsm)
                keccak_word_cnt <= keccak_word_cnt + 1;
            if (valid_i_geny && !sticky_valid_geny)
                sticky_valid_geny <= 1;
            if (ready_i_geny && !sticky_ready_geny)
                sticky_ready_geny <= 1;
            // Sticky MULTACC debug
            if (cstate2 == FSM2_MULTACC)
                sticky_multacc_entered <= 1;
            if (cstate2 == FSM2_MULTACC && web_ram6)
                sticky_web6_fired <= 1;
            if (cstate2 == FSM2_MULTACC && start_op[1])
                sticky_start_op1_mult <= 1;
            if (cstate2 == FSM2_MULTACC && web_ram6 && dib_ram6 != 0)
                sticky_dib6_nonzero_multacc <= 1;
            if (web_ram6 && dib_ram6 != 0)
                sticky_dib6_nonzero_anywhere <= 1;
            // Counters and first-data capture
            if (cstate2 == FSM2_MULTACC && web_ram6)
                multacc_web_count <= multacc_web_count + 1;
            if (cstate2 == FSM2_NTTI_Z && web_ram6)
                nttiz_web_count <= nttiz_web_count + 1;
            if (cstate2 == FSM2_MULTACC && web_ram6 && !first_multacc_captured) begin
                first_multacc_dib_low  <= dib_ram6[31:0];
                first_multacc_captured <= (dib_ram6[31:0] != 0);
            end
            if (cstate2 == FSM2_NTTI_Z && web_ram6 && !first_nttiz_captured) begin
                first_nttiz_dib_low  <= dib_ram6[31:0];
                first_nttiz_captured <= (dib_ram6[31:0] != 0);
            end
            if (cstate0 == FSM0_UNLOAD_Z && (addra_ram6 > unload_addr_max))
                unload_addr_max <= addra_ram6;
            // Track polynomial index progression
            if (cstate2 == FSM2_MULTACC && done_op[1])
                multacc_done_count <= multacc_done_count + 1;
            if (cstate2 == FSM2_NTTI_Z && done_op[1])
                nttiz_done_count <= nttiz_done_count + 1;
            if (cstate2 == FSM2_MULTACC && (addr1_sel_op[1] > multacc_addr1_max))
                multacc_addr1_max <= addr1_sel_op[1];
            if (cstate2 == FSM2_NTTI_Z && (addr1_sel_op[1] > nttiz_addr1_max))
                nttiz_addr1_max <= addr1_sel_op[1];
            if (cstate2 == FSM2_MULTACC && nstate2 == FSM2_MULT_CS2)
                multacc_addr1_at_exit <= addr1_sel_op[1];
            if (cstate2 == FSM2_MULTACC)
                multacc_last_addrb <= addrb_ram6;
            // Capture LAST dib values to compare against FIRST (detects constant vs varying data)
            if (cstate2 == FSM2_MULTACC && web_ram6) begin
                last_multacc_dib_low <= dib_ram6[31:0];
                or_multacc_dib_low   <= or_multacc_dib_low | dib_ram6[31:0];
                if (dib_ram6[31:0] != 0)
                    multacc_nonzero_count <= multacc_nonzero_count + 1;
            end
            if (cstate2 == FSM2_NTTI_Z && web_ram6) begin
                last_nttiz_dib_low <= dib_ram6[31:0];
                or_nttiz_dib_low   <= or_nttiz_dib_low | dib_ram6[31:0];
                if (dib_ram6[31:0] != 0)
                    nttiz_nonzero_count <= nttiz_nonzero_count + 1;
            end
            // Track addrb range in MULTACC and NTTI_Z (should span 0..63 per poly)
            if (cstate2 == FSM2_MULTACC && web_ram6) begin
                if (addrb_ram6 > multacc_addrb_max) multacc_addrb_max <= addrb_ram6;
                if (addrb_ram6 < multacc_addrb_min) multacc_addrb_min <= addrb_ram6;
            end
            if (cstate2 == FSM2_NTTI_Z && web_ram6) begin
                if (addrb_ram6 > nttiz_addrb_max) nttiz_addrb_max <= addrb_ram6;
            end
        end

        case({mode,cstate0})
            {2'd0,KG_INIT}: begin
                addr1_sel_op[0] <= 0;
                addr2_sel_op[0] <= 0;
                addr3_sel_op[0] <= 0;

                ctr_a1 <= 0;
                ctr_a2 <= 0;
                ctr_s1 <= 0;
                ctr_s2 <= 0;
                keccak_valid <= 0;

                ctr_t <= 0;
                s2_prereq_done <= 0;
                // Don't reset diagnostic counters here — preserve for post-run readout
            end
            {2'd0,KG_UNLOAD_HASH}: begin
                rho <= (valid_i_a && ready_i_a) ?  {rho[255-64:0], dout[2]} : rho;
            end
            {2'd0,KG_SAMPLE_S1}: begin
                ctr_s1 <= (valid_o_s && ready_o_s) ? ctr_s1 + 1 : ctr_s1;
                if (ctr == S1_LEN[10:3]-1 && valid_o && ready_o) begin
                    ctr_s1 <= 0;
                    ctr <= 0;
                end
            
                addr1_sel_op[0] <= 0; 
                start_op[0] <= (ctr == S1_LEN[10:3]-1 && valid_o && ready_o) ? 1 : 0;
            end
            {2'd0,KG_SAMPLE_S2}: begin
                ctr_s2 <= (valid_o_s && ready_o_s) ? ctr_s2 + 1 : ctr_s2;
                if (done_s) begin
                    ctr_s2 <= 0;
                end

                // Latch: require NTT completion (addr1==L-1) AND GenA completion (a_generated)
                // For sec_lvl==2 K==L so original condition is preserved via shortcut
                s2_prereq_done <= ((done_op[0] && addr1_sel_op[0] == L - 1) && (sec_lvl == 2 || a_generated)) ? 1 : s2_prereq_done;
                // Only reset ctr when the actual transition fires (last s2 word output)
                ctr <= (((ctr == S2_LEN[10:3]-1 && valid_o && ready_o) ||
                         (ctr >= S2_LEN[10:3])) &&
                        (s2_prereq_done || (done_op[0] && addr1_sel_op[0] == K - 1 && sec_lvl == 2) || (a_generated && sec_lvl != 2)))
                       ? 0 : ctr_next;
                addr1_sel_op[0] <= naddr1_sel_op[0];
                // Start next NTT when current one completes (but NOT the last one at L-1).
                // Also start MULT by pulsing start_op when the transition to KG_MULT_AS1 fires.
                start_op[0]     <= ((done_op[0] && addr1_sel_op[0] != L - 1) || (nstate0 == KG_MULT_AS1)) ? 1 : 0;
            end
            {2'd0,KG_MULT_AS1}: begin
                // fix: restored original addr3 condition — current code was pulsing
                // start_op[0] on the last MULT completion, causing op[0] to start a
                // spurious operation that corrupted downstream INTT/ADD timing.
                // Original: only pulse start for non-last MULT (addr3 != (K-1)*(L-1)).
                start_op[0] <= (addr3_sel_op[0] != (K-1)*(L-1) && done_op[0]) ? 1 : 0;

                addr1_sel_op[0] <= naddr1_sel_op[0];
                addr2_sel_op[0] <= naddr2_sel_op[0];
                addr3_sel_op[0] <= naddr3_sel_op[0];

                // Ensure ctr is 0 so KG_NTTI_T can properly initialize the
                // Keccak for tr computation (it expects ctr 0→5 for rho loading).
                ctr <= 0;
            end
            {2'd0,KG_NTTI_T}: begin
                addr1_sel_op[0] <= naddr1_sel_op[0]; 
                start_op[0]     <= (done_op[0]) ? 1 : 0;
                
                rho <= (src_read[2] && ~src_ready_fsm && ctr > 0) ?  {rho[255-64:0], 64'd0} : rho;
                ctr <= (done_op[0] && addr1_sel_op[0] == K-1) ? 0 : ctr_next;
            end
            {2'd0,KG_ADD_T_S2}: begin
                addr1_sel_op[0] <= naddr1_sel_op[0];
                start_op[0]     <= (addr1_sel_op[0] != K-1 && done_op[0]) ? 1 : 0;
                ctr       <= 0;
                ctr_t     <= 0;
                enc_phase <= 0;
            end
            {2'd0,KG_ENCODE_T1}: begin
                // Backpressure-safe RAM read state machine:
                //   enc_phase=0 (READ): address presented to RAM, wait 1 cycle
                //   enc_phase=1 (HOLD): data available, wait for encoder acceptance
                //   After K*64 inputs: stop reading, wait for encoder to drain
                if (ctr_t >= K*64) begin
                    enc_phase <= 0;
                end else if (!enc_phase) begin
                    enc_phase <= 1;
                end else if (ready_i_enc) begin
                    ctr_t     <= ctr_t + 1;
                    enc_phase <= 0;
                end
                // Use AXI output counter (ctr) for transition timing — matches TB consumption
                ctr <= (ctr == T1_LEN[11:3]-1 && valid_o && ready_o) ? 0 : ctr_next;
                if (ctr == T1_LEN[11:3]-1 && valid_o && ready_o) begin
                    ctr_t     <= 0;
                    enc_phase <= 0;
                end

                // load fifo (T1 output for tr hash)
                if (valid_o && ready_o) begin
                    keccak_valid <= {keccak_valid[318:0], 1'b1};
                    keccak_fifo[0] <= {do_enc[7:0],do_enc[15:8], do_enc[23:16], do_enc[31:24], do_enc[39:32], do_enc[47:40],do_enc[55:48], do_enc[63:56]};
                    for (i = 0; i < 319; i = i + 1)
                        keccak_fifo[i+1] <= keccak_fifo[i];
                end
            end
            {2'd0,KG_ENCODE_T0}: begin
                // Backpressure-safe RAM read (same pattern as KG_ENCODE_T1)
                // After K*64 inputs: stop reading, wait for encoder to drain
                sticky_entered_t0 <= 1;
                if (ctr_t >= K*64) begin
                    enc_phase <= 0;
                end else if (!enc_phase) begin
                    enc_phase <= 1;
                end else if (ready_i_enc) begin
                    ctr_t     <= ctr_t + 1;
                    enc_phase <= 0;
                end
                // Use AXI output counter (ctr) for transition timing — matches TB consumption
                ctr <= (ctr == T0_LEN[11:3]-1 && valid_o && ready_o) ? 0 : ctr_next;
                if (ctr == T0_LEN[11:3]-1 && valid_o && ready_o) begin
                    ctr_t     <= 0;
                    enc_phase <= 0;
                end

                // unload fifo
                if (src_read[2]  && ~src_ready_fsm) begin
                    keccak_valid <= {keccak_valid[318:0], 1'b0};
                    keccak_fifo[0] <= 0;
                    for (i = 0; i < 319; i = i + 1)
                        keccak_fifo[i+1] <= keccak_fifo[i];
                end

            end
            {2'd0,KG_UNLOAD_TR}: begin
                sticky_entered_tr <= 1;
                // unload fifo
                if (src_read[2]  && ~src_ready_fsm) begin
                    keccak_valid <= {keccak_valid[318:0], 1'b0};
                    keccak_fifo[0] <= 0;
                    for (i = 0; i < 319; i = i + 1)
                        keccak_fifo[i+1] <= keccak_fifo[i];
                end
            end
            {2'd1,VY_INIT}: begin
                mlen <= 0;
                ctr  <= 0;
                fail <= 0;
                COMP_FAIL    <= 0;
                ctr_dec <= 0;
                ctr_c   <= 0;

                
                addr1_sel_op[0] <= 0; 
                addr2_sel_op[0] <= 0; 
                addr3_sel_op[0] <= 0; 
            end 
            {2'd1,VY_LOAD_RHO}: begin
                RHO <= (valid_i && ready_i) ?  {RHO[255-64:0], data_i} : RHO;
                ctr <= ctr_next;
            end
            {2'd1,VY_LOAD_C}: begin
                case(sec_lvl)
                2: begin
                    C <= (valid_i && ready_i) ?  {256'd0, C[255-64 : 0], data_i} : C;
                end
                3: begin
                    C <= (valid_i && ready_i) ?  {128'd0, C[383-64 : 0], data_i} : C;
                end 
                5: begin 
                    C <= (valid_i && ready_i) ?  {C[511-64 : 0], data_i} : C;
                end
                endcase
                
            end
            {2'd1,VY_DECODE_Z}: begin
                ctr_dec <= (ctr_dec == {L, 6'd0}-1 && valid_o_dec && ready_o_dec) ? 0
                             : (valid_o_dec) ? ctr_dec + 1 : ctr_dec;
                ctr_c   <= (valid_o_c)   ? ctr_c   + 1 : ctr_c;

                start_op[0] <= (ctr_dec == {L, 6'd0}-1 && valid_o_dec && ready_o_dec)  ? 1 :0;

                RHO <= (src_read[2] && ctr0 > 1) ?  {RHO[255-64:0], 64'd0} : RHO;
                if (src_read[2] && ctr0 == 2) rho_verify_diag <= RHO[255:192];
            end
            {2'd1,VY_NTT_Z}: begin
                ctr_dec <= (valid_o_dec) ? ctr_dec + 1 : ctr_dec;
                addr1_sel_op[0] <= naddr1_sel_op[0];
                start_op[0]     <= (done_op[0] && addr1_sel_op[0] != L-1) ? 1 : 0;
                ntt_z_done      <= (done_op[0] && addr1_sel_op[0] == L-1) ? 1 : ntt_z_done;

                TR <= (dst_write[2] && ctr0 < 8) ? {TR[511-64:0], dout[2]} : TR;
                if (nstate0 == VY_NTT_T1) begin
                    tr_verify_diag <= TR[511:448];
                    tr_low_diag <= TR[63:0];
                    ntt_z_ctr0_diag <= {57'd0, ctr0[6:0]};
                end
            end
            {2'd1,VY_NTT_T1}: begin
                TR <= (src_read[2] && ctr0 > 1) ? {TR[511-64:0], 64'd0} : TR;
                MU <= (dst_write[2]) ? {MU[511-64:0], dout[2]} : MU;

                mlen <= (ready_i && valid_i && ctr0 == 1) ? data_i[31:0] + 16'd2 : mlen;
                addr1_sel_op[0] <= naddr1_sel_op[0];
                start_op[0]     <= ((ctr0 == 0) || (done_op[0] && (addr1_sel_op[0] != K-1)) || ((nstate0 == VY_NTT_C))) ? 1 : 0;

                shake_verif_done <= ({ctr0, 3'd0} >= mlen_PLUS144) ? 1 : 0;
                ntt_verif_done <= (done_op[0] &&  (addr1_sel_op[0] == K-1)) ? 1 : ntt_verif_done;
                if (nstate0 == VY_NTT_C) mu_verify_diag <= MU[511:448];
            end
            {2'd1,VY_NTT_C}: begin
                shake_verif_done <= 0;
                ntt_verif_done <= 0;
                start_op[0]     <= ((done_op[0] && sec_lvl != 5) || (done_a && sec_lvl == 5)) ? 1 : 0;
            end
            {2'd1,VY_MULT_AZ}: begin
                start_op[0]     <= (done_op[0]) ? 1 : 0; 
            
                addr1_sel_op[0] <= naddr1_sel_op[0]; 
                addr2_sel_op[0] <= naddr2_sel_op[0];
                addr3_sel_op[0] <= naddr3_sel_op[0];
            end
            {2'd1,VY_MULT_CT1}: begin
                start_op[0]     <= (done_op[0]) ? 1 : 0;
            
                addr1_sel_op[0] <= naddr1_sel_op[0]; 
                addr2_sel_op[0] <= naddr2_sel_op[0];
                addr3_sel_op[0] <= naddr3_sel_op[0];
            end
            {2'd1,VY_SUB_AZ_CT1}: begin
                addr1_sel_op[0] <= naddr1_sel_op[0]; 
                start_op[0]     <= (done_op[0]) ? 1 : 0; 
            end
            {2'd1,VY_INTT}: begin
                addr1_sel_op[0] <= naddr1_sel_op[0];
                start_op[0]     <= (done_op[0] && addr1_sel_op[0] != K-1) ? 1 : 0;

                // Reset keccak_word_cnt at VY_INTT start to count only this Keccak operation
                if (ctr0 == 0)
                    keccak_word_cnt <= 0;
                MU <= (src_read[2] && ctr0 > 1) ? {MU[511-64:0], 64'd0} : MU;
            end
            {2'd1,VY_COMPARE}: begin
                if (dst_write[2]) begin
                    // Capture first comparison for diagnostics
                    if (ctr == 0) begin
                        dout_compare_diag <= dout[2];
                        c_compare_diag <= C[383:320];
                    end
                    case(sec_lvl)
                    2: begin
                        C <= {256'd0, C[255-64:0], 64'd0};
                        if (dout[2] != C[255:256-64]) begin
                            fail <= 1;
                        end
                    end
                    3: begin
                        C <= {128'd0, C[383-64:0], 64'd0};
                        if (dout[2] != C[383:384-64]) begin
                            fail <= 1;
                        end
                    end
                    5: begin
                        C <= {C[511-64:0], 64'd0};
                        if (dout[2] != C[511:512-64]) begin
                            fail <= 1;
                        end
                    end
                    endcase

                end
            end
            {2'd2,FSM0_LOAD_MU}: begin
                mlen <= (ready_i && valid_i && ctr1 == 0) ? data_i[31:0] + 16'd2 : mlen;
                // Capture GenY state at LOAD_MU exit
                if ({ctr1_next,3'd0} > mlen_PLUS128)
                    geny_cstate_at_mu_exit <= geny_cstate;
            end
            {2'd2,FSM0_DECODE_S1}: begin
                if (valid_o_dec && ready_o_dec) begin
                    if (ctr_dec == {L, 6'd0}-1) begin
                        ctr_dec     <= 0;
                        start_op[1] <= 1;  
                    end else begin
                        ctr_dec <= ctr_dec + 1;
                    end
                end              
            end
            {2'd2,FSM0_NTT_S1}: begin
                ctr_dec <= (ctr_dec == {K, 6'd0}-1 && valid_o_dec && ready_o_dec) ? 0
                             : (valid_o_dec) ? ctr_dec + 1 : ctr_dec;

                start_op[1] <= ((rst_op[1] && addr1_sel_op[1] != L-1) || ((nstate0 == FSM0_NTT_S2)))  ? 1 : 0;

                // Latch when all L S1 NTTs complete; clear on transition to NTT_S2
                if (done_op[1] && addr1_sel_op[1] == L-1) s1_ntt_all_done <= 1;
                if (nstate0 == FSM0_NTT_S2) s1_ntt_all_done <= 0;
            end
            {2'd2,FSM0_NTT_S2}: begin
                ctr_dec <= (ctr_dec == {K, 6'd0}-1 && valid_o_dec && ready_o_dec) ? 0
                             : (valid_o_dec) ? ctr_dec + 1 : ctr_dec;

                start_op[1] <= ((rst_op[1] && addr1_sel_op[1] != K-1) || (nstate0 == FSM0_NTT_T0)) ? 1 : 0;

                // Latch when all K S2 NTTs complete; clear on transition to NTT_T0
                if (done_op[1] && addr1_sel_op[1] == K-1) s2_ntt_all_done <= 1;
                if (nstate0 == FSM0_NTT_T0) s2_ntt_all_done <= 0;
            end
            {2'd2,FSM0_NTT_T0}: begin
                start_op[1] <= (rst_op[1] && addr1_sel_op[1] != K-1) ? 1 : 0; 
            end
            //{2'd2,UNLOAD_}: begin
            //    curr_y_used  <= 1;
            //end
        endcase

        case(cstate1) 
        //FSM1_GENY: begin
            //curr_y_used <= 1;
        //end
        FSM1_WAIT: begin
            start_op[0] <= 1;
        end
        FSM1_NTT_Y: begin
            start_op[0] <= (rst_op[0]) ? 1 : 0; 
            op_done_ntty <= (done_op[0] && addr1_sel_op[0] == L-1) ? 1 : op_done_ntty;
            a_generated_during <= (done_a) ? 1 : a_generated_during;
        end
        FSM1_MULT_A_Y: begin
            start_op[0] <= (rst_op[0]) ? 1 : 0; 
        end
        FSM1_NTTI_W: begin
            start_op[0] <= (rst_op[0] && addr1_sel_op[0] != K-1) ? 1 : 0; 
            fsm1_even <= (rst_op[0] && addr1_sel_op[0] == K-1) ? ~fsm1_even : fsm1_even;
        end
        endcase
        
        
        case(cstate2)
        FSM2_GEN_C: begin
            start_op[1] <= (done_c) ? 1 : 0;
        end
        FSM2_NTT_C: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
        end
        FSM2_MULTACC: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
        end
        FSM2_MULT_CS2: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
        end
        FSM2_MULT_CT0: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
        end
        FSM2_NTTI_Z: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
        end
        FSM2_NTTI_CS2: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
            //
        end
        FSM2_NTTI_CT0: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
        end
        FSM2_SUB_W0_CS2: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
        end
        FSM2_MAKEHINT: begin
            start_op[1] <= (rst_op[1]) ? 1 : 0;
            
            if ((done_op[1] && addr1_sel_op[1] == K-1 && sec_lvl != 5) || (sec_lvl == 5 && done_op[0] && addr1_sel_op[0] == K-1)) begin
                norm_rejected <= 0; 
                //curr_y_used <= 1;
            end
        end
        endcase

        
        
        ctr_a1 <= (valid_o_a[0]) ? ctr_a1 + 1 : ctr_a1;
        ctr_a2 <= (valid_o_a[1]) ? ctr_a2 + 1 : ctr_a2;
        
        if (done_a) begin
            a_generated <= (cstate1 == FSM1_NTT_Y) ? 0 : 1;
            
            ctr_a1 <= 0;
            ctr_a2 <= 0;
        end
    end

    // -----------------------------------------------------------------------
    // Diagnostic output packing (63 bits)
    // -----------------------------------------------------------------------
    // Bits  [7:0]   padding
    // Bit   [8]     geny_ctr[8]
    // Bits [13:9]   cstate0[4:0]
    // Bits [18:14]  cstate1[4:0] (Sign) | out_word_total[4:0] (KeyGen)
    // Bits [23:19]  cstate2[4:0] (Sign) | out_word_total[9:5] (KeyGen)
    // Bits [30:24]  owt_t1[6:0]
    // Bits [33:31]  geny_cstate[2:0]
    // Bits [37:34]  geny_ctr[3:0] (dup)
    // Bits [41:38]  ctr1[3:0]
    // Bits [49:42]  geny_ctr[7:0]
    // Bit  [50]     enc_phase
    // Bit  [51]     ready_i_enc
    // Bit  [52]     valid_o
    // Bit  [53]     done_op[0]
    // Bit  [54]     s2_prereq_done
    // Bit  [55]     sticky_entered_t0
    // Bit  [56]     sticky_entered_tr
    // Bit  [57]     s1_ntt_all_done (Sign mode)
    // Bit  [58]     s2_ntt_all_done (Sign mode)
    // Bit  [59]     done_op[1]
    // Bit  [60]     sticky_start_geny
    // Bit  [61]     sticky_cstart_fsm1
    // Bit  [62]     geny_cstate[3] (MSB)
    // Bits [49:42]  geny_ctr[7:0] (GenY internal word counter)
    // Bits [41:38]  ctr1[3:0] (FSM0 LOAD_MU word counter low bits)
    // Bits [37:34]  handshake sticky flags: src_read2, valid_geny, ready_geny, src_ready_y
    // Bits [33:31]  geny_cstate[2:0]
    // Bits [30:27]  geny_cstate_at_mu_exit[3:0]
    // Bits [26:24]  owt_t1[2:0]
    // Bits [23:19]  cstate2[4:0]
    // Bits [18:14]  cstate1[4:0]
    // Bits [13:9]   cstate0[4:0]
    // Bits [8:0]    geny_ctr[8] + padding
    assign diag = {
        nttiz_nonzero_count[15:0],      // [63:48] # non-zero dib writes in NTTI_Z (expect ~320 if working)
        multacc_nonzero_count[15:0],    // [47:32] # non-zero dib writes in MULTACC
        or_nttiz_dib_low[15:0],         // [31:16] OR of all NTTI_Z dib[15:0] writes (0=all zeros)
        or_multacc_dib_low[15:0]        // [15:0]  OR of all MULTACC dib[15:0] writes
    };

endmodule
