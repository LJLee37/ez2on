#pragma once

int mixx_init(void);
int mixx_copy_mem(void* dest, void* src, unsigned int size);
int mixx_zero_mem(void* buf, unsigned int size);
void* mixx_get_text_section(void);
void* mixx_get_data_section(void);
int mixx_stdcall(void* entry, int* status);
int mixx_fastcall(void* entry, int* status);
int mixx_call_driver_entry(void* entry, int* status);
