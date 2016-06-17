
#ifndef __TVBUFF_H
#define __TVBUFF_H

#include <glib.h>

#define ENC_LITTLE_ENDIAN 0
#define ENC_BIG_ENDIAN 1

typedef struct tvbuff {
    guint8 *buffer;
    guint length;
} tvbuff_t;

extern guint8
tvb_get_guint8(tvbuff_t *tvb, const gint offset);

extern guint8
tvb_get_bits8(tvbuff_t *tvb, guint offset, const gint no_of_bits);

extern guint
tvb_reported_length(tvbuff_t *tvb);

extern guint8
tvb_get_bits(tvbuff_t *, guint offset, const gint len);

extern guint16
tvb_get_bits16(tvbuff_t *tvb, guint offset, const gint no_of_bits, const guint enc);


extern guint32
tvb_get_bits32(tvbuff_t *tvb, guint offset, const gint no_of_bits, const guint enc);

extern guint64
tvb_get_bits64(tvbuff_t *tvb, guint offset, const gint no_of_bits, const guint enc);

#endif /* __TVBUFF_H */




