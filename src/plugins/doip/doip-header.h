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
#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <stdio.h>


typedef struct doip_header 
{
    guint8 proto_version;
    guint8 inverse_proto_version;

    guint16 payload_type;
    guint32 payload_length;
    guint8 *payload_content;
} doip_header;

doip_header *
create_doip_header(tvbuff_t *);

void
destroy_doip_header(doip_header *);

void
print_doip_header(FILE *, doip_header *);

#endif /* __DOIP_HEADER_H */



