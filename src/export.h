#ifndef TRAFAN_EXPORT_H
#define TRAFAN_EXPORT_H

enum trafan__errc	trafan__init_instance(struct trafan__instance **instance);
enum trafan__errc	trafan__free_instance(struct trafan__instance *instance);

#endif
