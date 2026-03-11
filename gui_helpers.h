#ifndef GUI_HELPERS_H
#define GUI_HELPERS_H

#include "app.h"

void gui_post_log(int target, const char *fmt, ...);
void gui_post_progress(int target, double fraction);
void gui_post_address(int target, const char *address);
void gui_post_downloads(int count);
void gui_post_fileid(const char *file_id);
void gui_post_uploads(int count);


#endif /* GUI_HELPERS_H */