/**
* Copyright 2017 The Open Source Research Group,
*                University of Erlangen-Nürnberg
*
* Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     https://www.gnu.org/licenses/gpl.html
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef __TVBUFF_H
#define __TVBUFF_H

#include <glib.h>

#define ENC_LITTLE_ENDIAN 0
#define ENC_BIG_ENDIAN 1

typedef struct tvbuff {
    guint8 *buffer;
    guint length;
} tvbuff_t;


extern guint
tvb_reported_length(tvbuff_t *tvb);

extern guint8
tvb_get_guint8(tvbuff_t *tvb, const gint offset);

/*
extern guint32
tvb_get_bits(tvbuff_t *, guint bit_offset, const gint no_of_bits, const guint encoding);
*/

extern guint8
tvb_get_bits8(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits);

extern guint16
tvb_get_bits16(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint enc);

extern guint32
tvb_get_bits32(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint enc);

extern guint64
tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint enc);

#endif /* __TVBUFF_H */




