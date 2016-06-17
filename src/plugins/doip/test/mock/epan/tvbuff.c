
#include "tvbuff.h"

guint
tvb_reported_length(tvbuff_t *tvb)
{
    return tvb->length;
}

guint8
tvb_get_guint8(tvbuff_t *tvb, const gint offset)
{
    return tvb_get_bits(tvb, offset, 8);
}

guint8
tvb_get_bits8(tvbuff_t *tvb, guint offset, const gint no_of_bits)
{
    return tvb_get_bits(tvb, offset, no_of_bits);
}

guint8
tvb_get_bits(tvbuff_t *tvb, guint offset, const gint no_of_bits)
{
    guint8 bits;
    guint8 byte;

    guint8 *buffer;

    buffer = tvb->buffer;
    byte = buffer[offset];

    bits = byte >> (8 - no_of_bits);

    return bits;
}

guint16
tvb_get_bits16(tvbuff_t *tvb, guint offset, const gint no_of_bits, const guint enc)
{
    /* ignore the encoding */
    /* also ignore no_of_bits */
    /* I don't even want to bother with endianess */
    guint8 bytes[2] = {0, 0};
    guint16 requested;

    bytes[0] = tvb_get_bits(tvb, offset, 8);
    bytes[1] = tvb_get_bits(tvb, offset +1, 8);

    requested = ((guint16)bytes[0]) << 8;
    requested ^= bytes[1];

    return requested;
}

guint32
tvb_get_bits32(tvbuff_t *tvb, guint offset, const gint no_of_bits, const guint enc)
{
    guint32 requested;
    guint16 parts[2];

    parts[0] = tvb_get_bits16(tvb, offset, 16, enc);
    parts[1] = tvb_get_bits16(tvb, offset +2, 16, enc);

    requested = ((guint32) parts[0]) << 16;
    requested ^= parts[1];

    return requested;
}


guint64
tvb_get_bits64(tvbuff_t *tvb, guint offset, const gint no_of_bits, const guint enc)
{
    guint32 parts[2];
    guint64 requested;

    parts[0] = tvb_get_bits32(tvb, offset, 32, enc);
    parts[1] = tvb_get_bits32(tvb, offset +4, 32, enc);

    requested = ((guint64) parts[0]) << 32;
    requested ^= parts[1];

    return requested; 
}





