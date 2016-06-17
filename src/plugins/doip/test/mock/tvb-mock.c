
#include <stdlib.h>
#include <epan/tvbuff.h>

#include "tvb-mock.h"

tvbuff_t *
create_tvb_mock(guint8 buffer[], guint len)
{
    tvbuff_t *tvb;

    if((tvb = (tvbuff_t *) malloc(sizeof(tvbuff_t))))
    {
        tvb->buffer = buffer;
        tvb->length = len;
    }

    return tvb;
}

void
destroy_tvb_mock(tvbuff_t *tvb)
{
    if(tvb)
    {
        free(tvb);
    }
}
