

#ifndef __DOIP_HEADER_H
#define __DOIP_HEADER_H

#include "config.h"
#include <epan/packet.h>
#include <epan/tvbuff.h>


typedef struct doip_header 
{
    guint8 proto_version;
    guint8 inverse_proto_version;

    guint16 payload_type;
    guint32 payload_length;
    guint8 **payload_content;
} doip_header;

doip_header *
create_doip_header(tvbuff_t *);

void
destroy_doip_header(doip_header *);

inline gboolean
insert_proto_version(doip_header *, tvbuff_t *);

inline gboolean
insert_inverse_proto_version(doip_header *, tvbuff_t *);

inline gboolean
insert_payload_type(doip_header *, tvbuff_t *);

inline gboolean
insert_payload_length(doip_header *, tvbuff_t *);

inline gboolean
insert_payload_content(doip_header *, tvbuff_t *);

gboolean
validate_doip_header(doip_header *);

inline gboolean
validate_doip_version(guint8 version, guint8 inverse_version);

#endif /* __DOIP_HEADER_H */



