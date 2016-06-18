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

#ifndef __DOIP_HEADER_H
#define __DOIP_HEADER_H

#include "config.h"
/*
#include <epan/packet.h>
*/
#include <epan/tvbuff.h>
#include <stdio.h>

typedef struct doip_header 
{
    guint8 proto_version;
    guint8 inverse_proto_version;

    struct doip_payload
    {
        guint16 type;
        guint32 length;

		/* buffer for doip-payload */
        tvbuff_t *tvb;  

		/* Offset for the Header */
        guint32 tvb_offset; 

    } payload;

} doip_header;


/* Allocates and fills a doip_header
 * returned doip_header must be destroyed calling 'destroy_doip_header()'
 */
doip_header *
create_doip_header(tvbuff_t *);

/* Fills a given doip_header with data
 * read from a passed tvbuff_t
 */
gboolean
fill_doip_header(doip_header *, tvbuff_t *);

/* Frees memory allocated by a doip_header created
 * by 'create_doip_header()'
 */
void
destroy_doip_header(doip_header *);

/* Prints basic information about a 
 * doip_header on a given stream
 * Useful for debugging purposes
 */
void
print_doip_header(FILE *, doip_header *);

/* Returns a tvbuff_t * instancel associated
 * with this header
 */
tvbuff_t *
retrieve_tvbuff(doip_header *);


/* Calculates the total length of a doip-message
 * in bytes
 */
gint
get_total_doip_package_length(doip_header *);


/* Calculates the total offset of
 * a byte in the payload section
 * by adding the number of header bytes
 */
gint
payload_offset_to_abs_offset(gint payload_offset);

/* Retrieves eight bits of data from a
 * doip_header's message section
 * @param[in,out] *i, will be used to hold message-part
 * @param[in] offset, byte-offset. 0 marks the message's first byte
 * @return TRUE on success, otherwise FALSE
 */
gboolean
get_guint8_from_message(const doip_header *, guint8 *i, const gint offset);

/* Retrieves 16 bits of data from a
 * doip_header's message section
 * @param[in,out] *i, will be used to hold message-part
 * @param[in] offset, byte-offset. 0 marks the message's first byte
 * @return TRUE on success, otherwise FALSE
 */
gboolean
get_guint16_from_message(const doip_header *, guint16 *i, const gint offset);

/* Retrieves 32 bits of data from a
 * doip_header's message section
 * @param[in,out] *i, will be used to hold message-part
 * @param[in] offset, byte-offset. 0 marks the message's first byte
 * @return TRUE on success, otherwise FALSE
 */
gboolean
get_guint32_from_message(const doip_header *, guint32 *i, const gint offset);

/* Retrieves 64 bits of data from a
 * doip_header's message section
 * @param[in,out] *i, will be used to hold message-part
 * @param[in] offset, byte-offset. 0 marks the message's first byte
 * @return TRUE on success, otherwise FALSE
 */
gboolean
get_guint64_from_message(const doip_header *, guint64 *i, const gint offset);

#endif /* __DOIP_HEADER_H */



