

#include "config.h"
#include <stdlib.h>
#include <epan/packet.h>
#include <epan/tvbuff.h>

#include "doip-header.h"

doip_header *
create_doip_header(tvbuff_t *tvb)
{

    doip_header *header;

    header = (doip_header *) malloc(sizeof(doip_header));

    if(header)
    {

        insert_proto_version(header, tvb);

        insert_inverse_proto_version(header, tvb);

        insert_payload_type(header, tvb);

        insert_payload_length(header, tvb);

        insert_payload_content(header, tvb);


        if(!validate_doip_header(header))
        {
            destroy_doip_header(header);
            header = NULL;
        }
    }

    return header;
}

void
destroy_doip_header(doip_header *header)
{
    if(header)
    {
        if(header->payload_length > 0)
        {
            free(header->payload_content);
        }
        free(header);
    }
}

inline gboolean
insert_proto_version(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 0;
    if(header)
    {
        header->proto_version = tvb_get_guint8(tvb, offset);
    }
    return header != NULL;
}

inline gboolean
insert_inverse_proto_version(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 1;
    if(header)
    {
        header->inverse_proto_version = tvb_get_guint8(tvb, offset);
    }
    return header != NULL;
}


inline gboolean
insert_payload_type(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 3;
    gint payload_type = 0;
    gint byte_offset = 0;
    
    if(header)
    {
        payload_type = ((guint16)tvb_get_guint8(tvb, offset + byte_offset++)) << 8;
        payload_type ^= (guint16) tvb_get_guint8(tvb, offset + byte_offset++);

        header->payload_type = payload_type;
    }
    return header != NULL;


}

inline gboolean
insert_payload_length(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 5;
    guint32 payload_length = 0;
    gint byte_offset = 0;
    if(header)
    {
        
        payload_length = ((guint32)tvb_get_guint8(tvb, offset + byte_offset++)) << 24;
        payload_length ^= ((guint32)tvb_get_guint8(tvb, offset + byte_offset++)) << 16;
        payload_length ^= ((guint32)tvb_get_guint8(tvb, offset + byte_offset++)) << 8;
        payload_length ^= ((guint32)tvb_get_guint8(tvb, offset));

        header->payload_length = payload_length;
    }
    return header != NULL;
}

inline gboolean
insert_payload_content(doip_header *header, tvbuff_t *tvb)
{
    const gint offset = 9;
    if(header)
    {

        header->payload_content = (guint8 **) malloc(sizeof(guint8) * header->payload_length);

        tvb_memcpy(tvb, *(header->payload_content), offset, header->payload_length);
    }
    return header != NULL;
}

inline gboolean
validate_doip_header(doip_header *header)
{
    gboolean valid_version;

    valid_version = validate_doip_version(header->proto_version, header->inverse_proto_version);

    /* TODO:
        - more checks
    */

    return valid_version;
}

inline gboolean
validate_doip_version(guint8 version, guint8 inverse_version)
{
    const gint8 inverter = 0xff;
    return (version == (inverse_version ^ inverter));
}

