#pragma once

int dmap_from_file(const char* filename, void* kern_ptr, int* status, unsigned short magic);
int dmap_from_file_ex(const char* filename, const char* proxy_filename, int* status, unsigned short magic);
