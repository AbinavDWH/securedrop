#ifndef CLIENT_H
#define CLIENT_H

#include "app.h"

/* Upload file to server with password protection */
void client_upload_file(const char *filepath,
                        const char *server_addr,
                        const char *password);

/* Download file from server using file ID + password */
void client_download_file(const char *server_addr,
                          const char *file_id,
                          const char *password);

#endif /* CLIENT_H */