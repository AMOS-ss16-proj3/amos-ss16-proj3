
# Multiple DoIP-Messages within a single UDP-Segment

Contrary to our initial believe ISO 13400-2:2012(E) forbids implementations which try to send multiple DoIP-messages within a single UDP-segment.
This is mentioned in a "Note 1" at page 20.

> For UDP datagram-based messages, this implies that the generic header is located in the first bytes of the payload.
> (p.20, ISO 13400-2:2012(E))


