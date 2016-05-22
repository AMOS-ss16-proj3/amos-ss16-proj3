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

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>

#include "doip-header.h"



/* helper methods */




/* converts a byte-offset into a bit-offset
 *
 * @param[in] offset
 * @param[in,out] *i, pointer to variable in
 *   which the result will be written
 * @return TRUE, if everything went fine,
 *  FALSE if an overflow or any other error occured
 */
static inline gboolean
message_byte_offset_to_tvb_bit_offset(guint , guint *);

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
message_byte_offset_to_tvb_byte_offset(guint , guint *);

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
    if(tvb && header)
    {
        insert_proto_version(header, tvb);

        insert_inverse_proto_version(header, tvb);

        insert_payload_type(header, tvb);

        insert_payload_length(header, tvb);

        insert_payload_message(header, tvb);
    }

    return validate_doip_header(header);
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

gint
get_total_doip_package_length(doip_header *header)
{
    const gint HEADER_LENGTH = 8; /* as taken from ISO 13400-2 */
    gint payload_length;

    payload_length = (gint) header->payload.length;

    return HEADER_LENGTH + payload_length;
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
message_byte_offset_to_tvb_bit_offset(guint msg_offset, guint *tvb_bit_offset)
{
    /* three left shifts are equivalent to multiplication by eight */
    guint BIT_SHIFTER = 3;
    guint tvb_byte_offset;
    guint bit_offset;
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

static inline gboolean
message_byte_offset_to_tvb_byte_offset(guint msg_offset, guint *tvb_byte_offset)
{
    const guint TVB_MSG_BYTE_OFFSET = 8;
   
    gboolean overflow;
    guint offset;

    offset = msg_offset + TVB_MSG_BYTE_OFFSET;
    overflow = offset < msg_offset;

    *tvb_byte_offset = offset;

    return !overflow;    
}




static inline gboolean
insert_proto_version(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 0;
    if(header)
    {
        header->proto_version = tvb_get_guint8(tvb, offset);
    }
    return header != NULL;
}

static inline gboolean
insert_inverse_proto_version(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 1;
    if(header)
    {
        header->inverse_proto_version = tvb_get_guint8(tvb, offset);
    }
    return header != NULL;
}


static inline gboolean
insert_payload_type(doip_header *header, tvbuff_t *tvb)
{
    const gint BIT_OFFSET = 2 * 8;
    const gint WORD_LENGTH = 16;
    gint payload_type = 0;
    
    if(header)
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
    return header != NULL;
}

static inline gboolean
insert_payload_length(doip_header *header, tvbuff_t *tvb)
{
    const gint BIT_OFFSET = 4 * 8;
    const gint WORD_LENGTH = 32;
    guint32 payload_length;
    if(header)
    {
        payload_length = tvb_get_bits32(
            tvb,
            BIT_OFFSET,
            WORD_LENGTH,
            ENC_LITTLE_ENDIAN
        );
        
        /*
        payload_length = ((guint32)tvb_get_guint8(tvb, offset + byte_offset++)) << 24;
        payload_length ^= ((guint32)tvb_get_guint8(tvb, offset + byte_offset++)) << 16;
        payload_length ^= ((guint32)tvb_get_guint8(tvb, offset + byte_offset++)) << 8;
        payload_length ^= ((guint32)tvb_get_guint8(tvb, offset));
        */

        header->payload.length = payload_length;
    }
    return header != NULL;
}

static inline gboolean
insert_payload_message(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 8;

    if(header && header->payload.length)
    {
        header->payload.tvb = tvb;
        header->payload.tvb_offset = offset;
    }
    return FALSE;
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

