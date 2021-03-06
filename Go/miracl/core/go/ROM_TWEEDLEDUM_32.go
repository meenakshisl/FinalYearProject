/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Fixed Data in ROM - Field and Curve parameters */

package TWEEDLEDUM

// Base  bits= 29
var Modulus = [...]Chunk{0x1, 0xA032710, 0xFD66E68, 0x15424ED8, 0x38, 0x0, 0x0, 0x0, 0x400000}
var R2modp = [...]Chunk{0x3FF4, 0x1B622B40, 0x1166FB28, 0x5BEEDDF, 0x16646668, 0x321298C, 0xDD7B28E, 0x3E66507, 0x22B644}
var ROI = [...]Chunk{0x188837CE, 0x1EF4F98D, 0x1AA67594, 0xDD1E7E7, 0x2D57FF4, 0x197557C6, 0xBF3D893, 0x2F121DC, 0x2AE451}
var SQRTm3 = [...]Chunk{0x17DE6C70, 0x10786BD5, 0x1DC95B25, 0xD55C069, 0x184CB128, 0x16EB9107, 0x1B5B20A1, 0x95285A0, 0x15EF7D}

const MConst Chunk = 0x1FFFFFFF

//*** rom curve parameters *****
const CURVE_Cof_I int = 1

var CURVE_Cof = [...]Chunk{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

const CURVE_B_I int = 5

var CURVE_B = [...]Chunk{0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CURVE_Order = [...]Chunk{0x1, 0x1657EA0, 0x18A1B261, 0x15424ED2, 0x38, 0x0, 0x0, 0x0, 0x400000}
var CURVE_Gx = [...]Chunk{0x0, 0xA032710, 0xFD66E68, 0x15424ED8, 0x38, 0x0, 0x0, 0x0, 0x400000}
var CURVE_Gy = [...]Chunk{0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
var CURVE_HTPC = [...]Chunk{0x1381795, 0x16B3AA9A, 0xF3EF0D9, 0x15DD7A0, 0xBAA53E1, 0xC45B655, 0xFD3BC53, 0x1E66E041, 0x3AB46C}
