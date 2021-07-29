#pragma once

/*
  shared data
*/

#include <Windows.h>

#define SHARED_DATA_MAX_PROC 1000
#define SHARED_DATA_XOR_KEY 0xbe

typedef union shared_data_params {
  // note: key_down, key_up, key_press
  struct {
    USHORT make_code;
  } keybd;
  // note: mouse_move, mouse_down, mouse_up, mouse_press
  struct {
    int dummy;
  } mouse;
  // note: enum_proc
  struct {
    ULONG len;
    struct {
      ULONG_PTR pid;
      CHAR image_file_name[16];
    } procs[SHARED_DATA_MAX_PROC];
  } enum_proc;
} shared_data_params;

typedef struct shared_data {
  shared_data_params params;
  struct {
    struct {
      ULONG_PTR down;
      ULONG_PTR up;
      ULONG_PTR press;
    } keybd;
    struct {
      ULONG_PTR dummy;
    } mouse;
    struct {
      ULONG_PTR fn;
    } enum_proc;
  } funcs;
} shared_data;
