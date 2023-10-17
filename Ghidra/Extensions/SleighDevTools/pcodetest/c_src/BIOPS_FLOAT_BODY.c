/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "pcode_test.h"

#ifdef HAS_FLOAT

PCODE_COMPARE_LOGIC(f4)

PCODE_GREATERTHAN_FLOAT(f4)

PCODE_GREATERTHANEQUALS_FLOAT(f4)

PCODE_LESSTHAN_FLOAT(f4)

PCODE_LESSTHANEQUALS_FLOAT(f4)

PCODE_EQUALS_FLOAT(f4)

PCODE_NOTEQUALS_FLOAT(f4)

PCODE_LOGICAL_AND_FLOAT(f4)

PCODE_LOGICAL_OR_FLOAT(f4)

PCODE_LOGICAL_NOT_FLOAT(f4)

PCODE_UNARY_PLUS_FLOAT(f4)

PCODE_UNARY_MINUS_FLOAT(f4)

PCODE_ADDITION_FLOAT(f4)

PCODE_SUBTRACT_FLOAT(f4)

#ifdef HAS_MULTIPLY

PCODE_MUL_FLOAT(f4)

#endif /* #ifdef HAS_MULTIPLY */
#ifdef HAS_DIVIDE

PCODE_DIV_FLOAT(f4)

#endif /* #ifdef HAS_DIVIDE */
#endif /* #ifdef HAS_FLOAT */
