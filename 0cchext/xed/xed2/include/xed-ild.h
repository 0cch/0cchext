/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2015 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/// @file xed-ild.h
/// instruction length decoder

#if !defined(_XED_ILD_H_)
# define _XED_ILD_H_
#include "xed-common-hdrs.h"
#include "xed-common-defs.h"
#include "xed-portability.h"
#include "xed-types.h"
#include "xed-decoded-inst.h"

#include "xed-operand-accessors.h"


/// This function just does instruction length decoding.
/// It does not return a fully decoded instruction.
///  @param xedd  the decoded instruction of type #xed_decoded_inst_t .
///               Mode/state sent in via xedd; See the #xed_state_t .
///  @param itext the pointer to the array of instruction text bytes
///  @param bytes the length of the itext input array.
///              1 to 15 bytes, anything more is ignored.
/// @return #xed_error_enum_t indiciating success (#XED_ERROR_NONE) or
///       failure.
/// Only two failure codes are valid for this function:
///  #XED_ERROR_BUFFER_TOO_SHORT and #XED_ERROR_GENERAL_ERROR.
/// In general this function cannot tell if the instruction is valid or
/// not. For valid instructions, XED can figure out if enough bytes were
/// provided to decode the instruction. If not enough were provided,
/// XED returns #XED_ERROR_BUFFER_TOO_SHORT.
/// From this function, the #XED_ERROR_GENERAL_ERROR is an indication
/// that XED could not decode the instruction's length because  the
/// instruction was so invalid that even its length
/// may across implmentations.
///
/// @ingroup DEC
XED_DLL_EXPORT xed_error_enum_t
xed_ild_decode(xed_decoded_inst_t* xedd,
               const xed_uint8_t* itext,
               const unsigned int bytes);


#endif

