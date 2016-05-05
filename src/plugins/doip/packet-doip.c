
#include "config.h"

#include <epan/packet.h>

static const char *DOIP_FULL_NAME = "Diagnostic over IP";
static const char *DOIP_SHORTNAME = "DoIP";
static const char *DOIP_ABBREV = "doip";

static const guint32 TCP_DATA_PORT = 13400;
static const guint32 UDP_DISCOVERY_PORT = 13400;
static const guint32 UDP_TEST_EQUIPMENT = 13400;

static int proto_doip = -1;

static void
dissect_doip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* suppress warning for unused variables */
    if(tvb) {
        tvb = NULL;
    }
    if(tree) {
        tree = NULL;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, DOIP_SHORTNAME);
    col_clear(pinfo->cinfo, COL_INFO);
}


void
proto_register_doip(void)
{
    proto_doip = proto_register_protocol (
        DOIP_FULLNAME,
        DOIP_SHORTNAME,
        DOIP_ABBREV
    );
}

void
proto_reg_handoff_doip(void)
{
    static dissector_handle_t doip_handle;

    doip_handle = create_dissector_handle(dissect_doip, proto_doip);
    dissector_add_uint("tcp.port", TCP_DATA_PORT, doip_handle);
    dissector_add_uint("udp.port", UDP_DISCOVERY_PORT, doip_handle);
}


