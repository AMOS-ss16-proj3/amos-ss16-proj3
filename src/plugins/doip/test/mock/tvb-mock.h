
#ifndef __TVB_MOCK_H
#define __TVB_MOCK_H

#include <epan/tvbuff.h>

extern tvbuff_t *
create_tvb_mock(guint8 buffer[], guint len);

extern void
destroy_tvb_mock(tvbuff_t *tvb);

#endif /* __TVB_MOCK_H */


