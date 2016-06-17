
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <epan/tvbuff.h>
#include "tvb-mock.h"

#include "doip-header.h"

int
test()
{
    tvbuff_t *tvb;
    guint8 buffer[] = {1,2,3,0xFF, 0x00};
    int i;
    
    tvb = create_tvb_mock(buffer, sizeof(buffer));
    if(tvb)
    {
        for(i = 0; i < sizeof(buffer); i += 1)
        {
            printf("%d\n", tvb_get_bits(tvb, i, 8));
        }

        printf("%d\n", tvb_get_bits16(tvb, 0, 0, 0));
    } 
    else
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;;
}


int
main()
{
    guint8 doip_buffer[] = {0x02, 0xFD, 0x00, 0x01, 0x00};
    tvbuff_t *tvb;
    doip_header header;

    tvb = create_tvb_mock(doip_buffer, sizeof(doip_buffer));
    if(tvb)
    {
        fill_doip_header(&header, tvb);

        print_doip_header(stdout, &header);
    }

    return EXIT_SUCCESS;
}

