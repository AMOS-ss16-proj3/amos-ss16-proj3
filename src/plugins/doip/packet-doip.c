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


#include <epan/tvbuff.h>
#include <stdio.h>
#include <stdlib.h>

#include "doip-header.h"
#include "doip-payload-handler.h"
#include "visualize-doip-header.h"
#include "packet-doip.h"
#include <epan/dissectors/packet-tcp.h>


/* debug variables */
#define DEBUG_OUTPUT stdout
/* end debug variables */


static const char *DOIP_FULLNAME = "Diagnostic over IP";
static const char *DOIP_SHORTNAME = "DoIP";
static const char *DOIP_ABBREV = "doip";

static const guint32 TCP_DATA_PORT = 13400;
static const guint32 UDP_DISCOVERY_PORT = 13400;
static const guint32 UDP_TEST_EQUIPMENT = 13400;


static gint proto_doip = -1;


/* function declaration */
static int
dissect_doip(tvbuff_t *, packet_info *, proto_tree *, void *);

static void
dissect_doip_udp(tvbuff_t *, packet_info *, proto_tree *);

static int
dissect_doip_tcp(tvbuff_t *, packet_info *, proto_tree *, void *);

static void
register_udp_test_equipment_messages(packet_info *);

static guint
get_doip_message_len(packet_info *, tvbuff_t *, int);


/* function implementation is now called from tcp_dissect_pdus */
static int
dissect_doip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    doip_header header;
    payload_handler handler;


    proto_item *ti;
    /*proto_tree *doip_tree;*/

#ifndef NDEBUG
    printf("tvb: %p\t pinfo: %p\t tree: %p\n", tvb, pinfo, tree);
#endif /* NDEBUG */

    if (pinfo)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, DOIP_SHORTNAME);
    }

    if (tvb && tree)
    {
        if (fill_doip_header(&header, tvb))
        {
#ifndef NDEBUG
            print_doip_header(DEBUG_OUTPUT, &header);
#endif /* NDEBUG */


            /* Create sub-tree which can be used for inserting proto-items */
            ti = proto_tree_add_item(tree, proto_doip, tvb, 0, -1, ENC_NA);

#ifndef NDEBUG
            printf("before visualize doip header\n");
#endif /* NDEBUG */
            /* append all doip-header infos to proto-item */
            visualize_doip_header(&header, ti);

            /* find a handler suited for the given doip-type (header->payload.type) */
#ifndef NDEBUG
            printf("before find matching payload handler\n");
#endif /* NDEBUG */
            handler = find_matching_payload_handler(&header);

#ifndef NDEBUG
            printf("payload handler: %p\n", handler);
#endif /* NDEBUG */
            if (handler)
            {
                handler(&header, ti, pinfo);
            }
        }
    }
    return tvb_captured_length(tvb);
}

/* determine Protocol Data Unit (PDU) length of protocol doip */
static guint get_doip_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset) 
{
    guint header_length;
    guint payload_length;
    doip_header header;

    header_length = (guint)get_header_length();
    tvb = tvb_new_subset_length(tvb, (gint) offset, (gint) header_length);

    fill_doip_header(&header, tvb);

    payload_length = (guint) header.payload.length;

    return header_length + payload_length;
}

static int
dissect_doip_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) 
{
    gint header_length = get_header_length();
    /*Reassembling TCP Fragments with the first three paramters handed over and additional parameters
    as described in Wireshark Developers Guide on page 66 */
    tcp_dissect_pdus(
        tvb,
        pinfo,
        tree,
        TRUE,
        header_length,
        get_doip_message_len,
        dissect_doip, data
    );
    return tvb_captured_length(tvb);
}

static void
dissect_doip_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    register_udp_test_equipment_messages(pinfo);

    dissect_doip(tvb, pinfo, tree, NULL);
}

static void
register_udp_test_equipment_messages(packet_info *pinfo)
{
    /* According to ISO 13400-2:2012(E) page 1, Figure 5
     * a situation may occur where there is doip-communication 
     * using non-specified ports. In order to fetch these messages
     * as well, we have to find these cases and instruct wireshark
     * to call our dissector.
     *
     * None-specified ports-communication may occure, when external
     * test equipment makes an UDP-request with src-port
     * UDP_TEST_EQUIPMENT (dynamically assigned,
     * ISO 13400-2:2012(E) page 12 table 8) and dst-port UDP_DISCOVERY
     * (specified as port 13400 at page 12, table 8).
     * The request can be answered by a DoIP entity using a dynamically
     * assigned src-port and using the request's src-port as response's 
     * dst-port.
    */
    guint32 srcport;
    guint32 dstport;
    gboolean dynamic_port_is_possible =  FALSE;

    dissector_handle_t doip_dyn_udp_handle;

    if (pinfo)
    {
#ifndef NDEBUG
        printf("udp on srcport: %d, destport: %d\n", pinfo->srcport, pinfo->destport);
#endif /* NDEBUG */
        srcport = pinfo->srcport;
        dstport = pinfo->destport;

        dynamic_port_is_possible = srcport != 13400 && dstport == 13400;
    }

    if(dynamic_port_is_possible)
    {
        doip_dyn_udp_handle = create_dissector_handle(dissect_doip_udp, proto_doip);
        dissector_add_uint("udp.port", srcport, doip_dyn_udp_handle);
    }
}

void
proto_register_doip(void)
{
    proto_doip = proto_register_protocol(
        DOIP_FULLNAME,
        DOIP_SHORTNAME,
        DOIP_ABBREV
        );

    register_proto_doip_payload(proto_doip);
}

void
proto_reg_handoff_doip(void)
{
    static dissector_handle_t doip_tcp_handle;
    static dissector_handle_t doip_udp_handle;

#if VERSION_MAJOR == 1
    doip_tcp_handle = new_create_dissector_handle(dissect_doip_tcp, proto_doip);
#else 
    doip_tcp_handle = create_dissector_handle(dissect_doip_tcp, proto_doip);
#endif /* VERSION_MAJOR == 1 */

    doip_udp_handle = create_dissector_handle(dissect_doip_udp, proto_doip);

    dissector_add_uint("tcp.port", TCP_DATA_PORT, doip_tcp_handle);
    dissector_add_uint("udp.port", UDP_DISCOVERY_PORT, doip_udp_handle);
}


