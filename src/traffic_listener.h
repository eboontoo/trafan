/**/

#ifndef TRAFAN_TRAFFIC_LISTENER_H
#define TRAFAN_TRAFFIC_LISTENER_H

#include "types.h"

enum traffic_listener

struct traffic_listener__frame {
        uint8 dst[6];
        uint8 src[6];
        uint16 type; 
};

typedef void (* traffic_listener__handler_func)();

struct traffic_listener {
};



#endif
