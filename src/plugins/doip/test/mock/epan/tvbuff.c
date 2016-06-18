
#include "tvbuff.h"

guint
tvb_reported_length(tvbuff_t *tvb)
{
    return tvb->length;
}

guint8
tvb_get_guint8(tvbuff_t *tvb, const gint offset)
{
    gint bit_offset = offset * 8;
    return tvb_get_bits8(tvb, bit_offset, 8);
}

/*
guint32
tvb_get_bits(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint encoding)
{
    guint8 bits;
    guint8 byte;

    guint8 *buffer;

    buffer = tvb->buffer;
    byte = buffer[offset];

    bits = byte >> (8 - no_of_bits);

    return bits;
}
*/

guint8
tvb_get_bits8(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits)
{
    const gint WORD_LENGTH = 8;

    guint byte_offset;
    guint8 bits;
    gint shift;


    shift = WORD_LENGTH - no_of_bits;

    byte_offset = bit_offset / WORD_LENGTH;

    bits = tvb->buffer[byte_offset];

    if(shift)
    {
        bits = (bits << shift) >> (shift);
    }

    return bits;
}

guint16
tvb_get_bits16(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint enc)
{
    /* ignore the encoding */
    /* also ignore no_of_bits */
    /* I don't even want to bother with endianess */
    const gint WORD_LENGTH = 16;

    guint8 bytes[2] = {0, 0};
    gint shift;
    guint16 requested;

    shift = WORD_LENGTH - no_of_bits;

    bytes[0] = tvb_get_bits8(tvb, bit_offset, 8);
    bytes[1] = tvb_get_bits8(tvb, bit_offset +8, 8);

    requested = ((guint16)bytes[0]) << 8;
    requested ^= bytes[1];

    requested = (requested << shift) >> shift;

    return requested;
}

guint32
tvb_get_bits32(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint enc)
{
    const gint WORD_LENGTH = 32;
    guint32 requested;
    gint shift = WORD_LENGTH - no_of_bits;
    guint16 parts[2];


    parts[0] = tvb_get_bits16(tvb, bit_offset, 16, enc);
    parts[1] = tvb_get_bits16(tvb, bit_offset +16, 16, enc);

    requested = ((guint32) parts[0]) << 16;
    requested ^= parts[1];

    requested = (requested << shift) >> shift;

    return requested;
}


guint64
tvb_get_bits64(tvbuff_t *tvb, guint bit_offset, const gint no_of_bits, const guint enc)
{
    const gint WORD_LENGTH = 64;
    guint32 parts[2];
    gint shift = WORD_LENGTH - no_of_bits;
    guint64 requested;

    parts[0] = tvb_get_bits32(tvb, bit_offset, 32, enc);
    parts[1] = tvb_get_bits32(tvb, bit_offset +32, 32, enc);

    requested = ((guint64) parts[0]) << 32;
    requested ^= parts[1];

    requested = (requested << shift) >> shift;

    return requested; 
}



