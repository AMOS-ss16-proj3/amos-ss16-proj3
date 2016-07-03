/**
* Copyright 2016 The Open Source Research Group,
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

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>

#include "doip-header.h"



/* helper methods */


/* According to ISO 13400-2:2012(E) a doip-header
 * takes 8 bytes of space
*/
const gint DOIP_HEADER_LENGTH = 8;



/* converts a byte-offset into a bit-offset
 *
 * @param[in] offset
 * @param[in,out] *i, pointer to variable in
 *   which the result will be written
 * @return TRUE, if everything went fine,
 *  FALSE if an overflow or any other error occured
 */
static inline gboolean
message_byte_offset_to_tvb_bit_offset(gint , gint *);



/* converts a doip_header message offset 
 * into a tvb_offset which can be used in
 * methods provided by epan/tvbuff.h
 *
 * @param[in] offset
 * @param[in,out] *i, pointer to variable in
 *   which the result will be written
 * @return TRUE, if everything went fine,
 *  FALSE if an overflow or any other error occured
 */ 
static inline gboolean
message_byte_offset_to_tvb_byte_offset(gint msg_offset, gint *tvb_byte_offset);

/* reads proto_version from tvbuff_t and 
 * writes it into doip_header
 */
static gboolean
insert_proto_version(doip_header *, tvbuff_t *);

/* reads inverse_proto_version from tvbuff_t and 
 * writes it into doip_header
 */
static inline gboolean
insert_inverse_proto_version(doip_header *, tvbuff_t *);

/* reads payload type from tvbuff_t and 
 * writes it into doip_header
 */
static inline gboolean
insert_payload_type(doip_header *, tvbuff_t *);

/* reads payload length from tvbuff_t and 
 * writes it into doip_header
 */
static inline gboolean
insert_payload_length(doip_header *, tvbuff_t *);

/* writes data necessary for reading doip-message
 * parts into a doip_header
 * these information will be used by 
 * get_guint8_from_message(), etc.
 */
static inline gboolean
insert_payload_message(doip_header *, tvbuff_t *);

/* checks whether a doip_header is valid or not
 */
static gboolean
validate_doip_header(doip_header *);

/* checks whether a doip_header version matches its inverse
 */
static inline gboolean
validate_doip_version(guint8 version, guint8 inverse_version);

int 
get_header_length(void)
{
	return DOIP_HEADER_LENGTH;
}

doip_header *
create_doip_header(tvbuff_t *tvb)
{
    gboolean success = FALSE;
    doip_header *header = NULL;

    header = (doip_header *) malloc(sizeof(doip_header));

    if(header)
    {
        success = fill_doip_header(header, tvb);
        if(!success)
        {
            free(header);
            header = NULL;
        }
    }
    return header;
}

gboolean
fill_doip_header(doip_header *header, tvbuff_t *tvb)
{
    gboolean valid = TRUE;
    if(tvb && header)
    {
        valid &= insert_proto_version(header, tvb)
            && insert_inverse_proto_version(header, tvb)
            && insert_payload_type(header, tvb)
            && insert_payload_length(header, tvb)
            && insert_payload_message(header, tvb)
            && validate_doip_header(header)
        ;
    }
    else
    {
        valid = FALSE;
    }

    return valid;
}

void
destroy_doip_header(doip_header *header)
{
    if(header)
    {
        free(header);
    }
}

void
print_doip_header(FILE *stream, doip_header *header)
{
    fprintf(
        stream,
        "doip-header:\n\tversion: %d\n\tpayload type: 0x%x\n\tpayload length: %d\n",
        header->proto_version,
        header->payload.type,
        header->payload.length
    );
}

tvbuff_t *
retrieve_tvbuff(doip_header *header)
{
    return header ? header->payload.tvb : NULL;
}

gint
get_total_doip_package_length(doip_header *header)
{
    gint payload_length;

    payload_length = (gint) header->payload.length;

    return DOIP_HEADER_LENGTH + payload_length;
}

gint
payload_offset_to_abs_offset(gint payload_offset)
{
    return DOIP_HEADER_LENGTH + payload_offset;
}

gboolean
get_guint8_from_message(const doip_header *header, guint8 *i, gint offset)
{
    const gint NUMBER_OF_BITS = 8;

    if(message_byte_offset_to_tvb_bit_offset(offset, &offset))
    {
        *i = tvb_get_bits8(
            header->payload.tvb,
            offset,
            NUMBER_OF_BITS
        );
        return TRUE;
    }
    return FALSE;
}


gboolean
get_guint16_from_message(const doip_header *header, guint16 *i, gint offset)
{
    const gint NUMBER_OF_BITS = 16;

    if(message_byte_offset_to_tvb_bit_offset(offset, &offset))
    {
        *i = tvb_get_bits16(
            header->payload.tvb,
            offset,
            NUMBER_OF_BITS,
            ENC_LITTLE_ENDIAN
        );
        return TRUE;
    }
    return FALSE;
}




gboolean
get_guint32_from_message(const doip_header *header, guint32 *i, gint offset)
{
    const gint NUMBER_OF_BITS = 32;

    if(message_byte_offset_to_tvb_bit_offset(offset, &offset))
    {
        *i = tvb_get_bits32(
            header->payload.tvb,
            offset,
            NUMBER_OF_BITS,
            ENC_LITTLE_ENDIAN
        );
        return TRUE;
    }
    return FALSE;
}
gboolean
get_guint64_from_message(const doip_header *header, guint64 *i, gint offset)
{
    const gint NUMBER_OF_BITS = 64;

    if(message_byte_offset_to_tvb_bit_offset(offset, &offset))
    {
        *i = tvb_get_bits64(
            header->payload.tvb,
            offset,
            NUMBER_OF_BITS,
            ENC_LITTLE_ENDIAN
        );
        return TRUE;
    }
    return FALSE;
}












static inline gboolean
message_byte_offset_to_tvb_bit_offset(gint msg_offset, gint *tvb_bit_offset)
{
    /* three left shifts are equivalent to multiplication by eight */
    guint BIT_SHIFTER = 3;
    gint tvb_byte_offset;
    gint bit_offset;
    gboolean overflow;

    if(message_byte_offset_to_tvb_byte_offset(msg_offset, &tvb_byte_offset))
    {
        /** will overflow if at least one of the first
        *   three most significant 
        *   bits is set
        */
        bit_offset = tvb_byte_offset << BIT_SHIFTER;

        overflow = bit_offset >> BIT_SHIFTER != tvb_byte_offset;

        if(!overflow)
        {
            *tvb_bit_offset = bit_offset;
            return TRUE;
        }
    }

    return FALSE;
}

gboolean
message_byte_offset_to_tvb_byte_offset(gint msg_offset, gint *tvb_byte_offset)
{
    gboolean overflow;
    gint offset;

    offset = msg_offset + DOIP_HEADER_LENGTH;
    overflow = offset < msg_offset;

    *tvb_byte_offset = offset;

    return !overflow;    
}




static inline gboolean
insert_proto_version(doip_header *header, tvbuff_t *tvb)
{
    const gint OFFSET = 0;
    const gint LENGTH = 1; 
    guint tvb_length = tvb_reported_length(tvb);
    gboolean version_available = header && tvb_length >= OFFSET + LENGTH;

    if(version_available)
    {
        header->proto_version = tvb_get_guint8(tvb, OFFSET);
    }
    return version_available;
}

static inline gboolean
insert_inverse_proto_version(doip_header *header, tvbuff_t *tvb)
{
    const gint OFFSET = 1;
    const gint LENGTH = 1;
    guint tvb_length = tvb_reported_length(tvb);
    gboolean iversion_available = header && tvb_length >= OFFSET + LENGTH;

    if(iversion_available)
    {
        header->inverse_proto_version = tvb_get_guint8(tvb, OFFSET);
    }
    return iversion_available;
}


static inline gboolean
insert_payload_type(doip_header *header, tvbuff_t *tvb)
{
    const gint BYTE_OFFSET = 2;
    const gint BYTE_LENGTH = 2;
    const gint BIT_OFFSET = BYTE_OFFSET * 8;
    const gint WORD_LENGTH = BYTE_LENGTH * 8;
    gint payload_type = 0;
    guint tvb_length = tvb_reported_length(tvb);
    gboolean type_available = header && tvb_length >= BYTE_OFFSET + BYTE_LENGTH;
    
    if(type_available)
    {
        /*
        payload_type = ((guint16)tvb_get_guint8(tvb, offset + byte_offset++)) << 8;
        payload_type ^= (guint16) tvb_get_guint8(tvb, offset + byte_offset++);
        */

        payload_type = tvb_get_bits16(
            tvb,
            BIT_OFFSET,
            WORD_LENGTH,
            ENC_LITTLE_ENDIAN
        );

        header->payload.type = payload_type;
    }
    return type_available;
}

static inline gboolean
insert_payload_length(doip_header *header, tvbuff_t *tvb)
{
    const gint BYTE_OFFSET = 4;
    const gint BYTE_LENGTH = 4;
    const gint BIT_OFFSET = BYTE_OFFSET * 8;
    const gint WORD_LENGTH = BYTE_LENGTH * 8;
    guint32 payload_length;
    guint tvb_length = tvb_reported_length(tvb);
    gboolean length_available = tvb_length >= BYTE_OFFSET + BYTE_LENGTH;

    if(length_available)
    {
        payload_length = tvb_get_bits32(
            tvb,
            BIT_OFFSET,
            WORD_LENGTH,
            ENC_LITTLE_ENDIAN
        );
        
        header->payload.length = payload_length;
    }
    return length_available;
}

static inline gboolean
insert_payload_message(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = DOIP_HEADER_LENGTH;
    gboolean payload_msg_available = header && tvb;

    if(payload_msg_available)
    {
        header->payload.tvb = tvb;
        header->payload.tvb_offset = offset;
    }
    return payload_msg_available;
}

static inline gboolean
validate_doip_header(doip_header *header)
{
    gboolean valid_version = FALSE;
    
    if(header)
    {
        valid_version = validate_doip_version(
            header->proto_version,
            header->inverse_proto_version
        );
    }

    return valid_version;
}

static inline gboolean
validate_doip_version(guint8 version, guint8 inverse_version)
{
    const guint8 inverter = 0xff;
    return inverter == (version ^ inverse_version);
}

