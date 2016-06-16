
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <epan/tvbuff.h>

int
main()
{
    int r = 0;
    tvbuff_t *tvb = NULL;

    r = tvb_reported_length(tvb);
    printf("%d\n", r);

    return EXIT_SUCCESS;;
}



