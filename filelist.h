#ifndef FILELIST_H
#define FILELIST_H

#include "app.h"

void filelist_add(const char *path);
void filelist_add_dir(const char *dirpath);
void filelist_remove(const char *path);
void filelist_clear(void);
void filelist_refresh_view(void);

#endif /* FILELIST_H */