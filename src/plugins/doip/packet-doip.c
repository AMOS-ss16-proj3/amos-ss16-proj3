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

/** Ports are defined in ISO 13400-2:2012(E)
 * page 25, table 15
*/
static const guint32 TCP_DATA_PORT = 13400;
static const guint32 UDP_DISCOVERY_PORT = 13400;
static const guint32 UDP_TEST_EQUIPMENT = 13400;

/** Protocol identifier
 * This must be set only once in proto_register_doip()!
*/
static gint proto_doip = -1;


/* function declaration */

/** Actual implementation of dissect-function.
 * It will be called either from dissect_doip_tcp() or dissect_doip_udp()
*/
static int
dissect_doip(tvbuff_t *, packet_info *, proto_tree *, void *);

/** Will be called by Wireshark if there is any UDP-communication
 * via ports specified in proto_reg_handoff_doip()
 * After a few checks it will call dissect_doip() for further dissecting
*/
static void
dissect_doip_udp(tvbuff_t *, packet_info *, proto_tree *);

/** Will be called by Wireshark if there is any TCP-communication
 * via ports specified in proto_reg_handoff_doip()
 * It may occure, that multiple doip-messages are within a single TCP
 * segment or that a doip-msg is split upon multiple TCP segments.
 * If one of these cases occures, this function will take care of re-assembling
 * or splitting and call dissect_doip() with tvbuff_t which consist of a single
 * doip-message.
 * Otherwise dissect_doip() will be called normally.
*/
static int
dissect_doip_tcp(tvbuff_t *, packet_info *, proto_tree *, void *);

/** In rare cases it may occure that there is DoIP-communication via ports
 * other than 13400. This function will analyze wheter there is an indicator
 * for such behaviour and takes all required  measures.
 * Further details are given in the functions body.
*/
static void
register_udp_test_equipment_messages(packet_info *);

#if VERSION_MAJOR == 1
/** If-Endif-ing this function declaration to avoid the compiler complaining
 * about an unused function
*/

/** Determine length of actual a doip-message
 * @param[in] packet_info *;
 * @param[in] tvbuff_t *;
 * @param[in] int; tvb-offset.
 *            After x bytes the actual doip-msg is expected to start
*/
static guint
get_doip_msg_len_w1(packet_info *, tvbuff_t *, int);
#endif

/** Determine length of actual a doip-message
 * @param[in] packet_info *;
 * @param[in] tvbuff_t *;
 * @param[in] int; tvb-offset.
 *            After x bytes the actual doip-msg is expected to start
*/
static guint
get_doip_msg_len_w2(packet_info *, tvbuff_t *, int, void *);


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
        /** Set wireshark's info-column */
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
                /** further dissect payload */
                handler(&header, ti, pinfo);
            }
        }
    }
    return tvb_captured_length(tvb);
}

#if VERSION_MAJOR == 1
/** If-Endif-ing this function declaration to avoid the compiler complaining
 * about an unused function
*/
static guint
get_doip_msg_len_w1(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
    /** Unfortunately there was an API-change between Wireshark versions 1 and 2.
     * tcp_dissect_pdus() from "epan/dissectors/packet-tcp.h" unfortunately changed
     * as well. We need this function to assemble split DoIP-messages.
     * tcp_dissect_pdus() requires a function-pointer which indicates a messages length.
     * The arguments passed to this function, however, changed. Therefore we
     * have to introduce two different functions both for version 1 + 2.
    */
    return get_doip_msg_len_w2(pinfo, tvb, offset, NULL);
}
#endif

static guint
get_doip_msg_len_w2(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *dissector_data _U_)
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
#if VERSION_MAJOR == 1
        get_doip_msg_len_w1,
#else
        get_doip_msg_len_w2,
#endif
        dissect_doip,
        data
    );
    return tvb_captured_length(tvb);
}

static void
dissect_doip_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /** If there is a possibility to have communication
     * over non-specified ports, identify it and take appropriate measures.
    */
    register_udp_test_equipment_messages(pinfo);

    /** start actual dissecting of tvb. */
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


/** This function will be called by wireshark during start-up.
 * It registers our DoIP-dissector.
*/
void
proto_register_doip(void)
{
    proto_doip = proto_register_protocol(
        DOIP_FULLNAME,
        DOIP_SHORTNAME,
        DOIP_ABBREV
        );
    /* register dissector */
    register_proto_doip_payload(proto_doip);
}

/** This function will be called by wireshark during start-up.
 * At this point we specify which kind of network traffic will be passed to our
 * dissector for further dissecting.
 * For details see function-body below or ISO 13400-2:2012(E)
*/
void
proto_reg_handoff_doip(void)
{
    static dissector_handle_t doip_tcp_handle;
    static dissector_handle_t doip_udp_handle;

    /** Create callback which enable wireshark to call our dissector.
     * Unfortunately there are some API-changes which cause wireshark's
     * datatypes and functions from version 1 to differ from version 2.
    */
#if VERSION_MAJOR == 1
    doip_tcp_handle = new_create_dissector_handle(dissect_doip_tcp, proto_doip);
#elif VERSION_MINOR == 0
    doip_tcp_handle = new_create_dissector_handle((new_dissector_t)dissect_doip_tcp, proto_doip);
#else
    doip_tcp_handle = create_dissector_handle(dissect_doip_tcp, proto_doip);
#endif /* VERSION_MAJOR == 1 */

    doip_udp_handle = create_dissector_handle(dissect_doip_udp, proto_doip);

    /** According to ISO 13400-2:2012(E) page 25 table 15 DoIP messages
     * will be sent either via UDP or TCP from or to port 13400.
     * There is, however, an exception wich will be discussed at function 
     * register_udp_test_equipment_messages().
    */
    dissector_add_uint("tcp.port", TCP_DATA_PORT, doip_tcp_handle);
    dissector_add_uint("udp.port", UDP_DISCOVERY_PORT, doip_udp_handle);
}


