
/*
  neo
*/

#define ENABLE_KEYBD 1

// note: windows
#include <Windows.h>
#include <process.h>

// note: clib
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// note: headers
#include "mixx.h"
#include "pmem.h"
#include "keybd.h"
#include "econ.h"
#include "sbuf.h"
#include "random.h"
#include "win.h"
#include "rt.h"

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#define EZ2ON "2ON"
#define GAME L"meAss"

#define ECON_OFFSET 0x10000

// note: module
static uint64_t game = 0;
// note: memory controller
static struct pmem mem;
// note: keyboard controller
static struct keybd_ctx keybd;
// note: external controller
static struct econ_ctx econ;

#define pread(dest, src, size) \
  pmem_read_eq(&mem, (void*)(dest), (void*)(src), (size))
#define pread_t(dest, src) \
  pread(&(dest), src, sizeof(dest))
#define pwrite(dest, src, size) \
  pmem_write_eq(&mem, (void*)(dest), (void*)(src), (size))
#define pwrite_t(dest, src) \
  pwrite(dest, &(src), sizeof(src))

#define pread_i8(addr) pmem_read_fast8(&mem, (void*)(addr))
#define pread_i16(addr) pmem_read_fast16(&mem, (void*)(addr))
#define pread_i32(addr) pmem_read_fast32(&mem, (void*)(addr))
#define pread_i64(addr) pmem_read_fast64(&mem, (void*)(addr))
#define pread_u8(addr) pmem_read_fast_u8(&mem, (void*)(addr))
#define pread_u16(addr) pmem_read_fast_u16(&mem, (void*)(addr))
#define pread_u32(addr) pmem_read_fast_u32(&mem, (void*)(addr))
#define pread_u64(addr) pmem_read_fast_u64(&mem, (void*)(addr))
#define pread_f32(addr) pmem_read_fast_f32(&mem, (void*)(addr))
#define pread_f64(addr) pmem_read_fast_f64(&mem, (void*)(addr))

static uint64_t pread_chain(uintptr_t addr) {
  return pread_u64(pread_u64(addr));
}

/*
  pid
*/

#define MAX_PID 100

typedef ULONG_PTR pid_list_t[MAX_PID];

static int get_pids(const char* proc_name, pid_list_t pids) {
  LIST_ENTRY proc_links;
  ULONG_PTR eproc = mem.cur_eproc, unique_pid;
  int len = 0;
  do {
    char file_name[15] = { 0, };
    if (!pread(file_name, eproc + ImageFileName, 15)) {
      break;
    }
    if (strstr(file_name, proc_name) != NULL) {
      if (len >= MAX_PID) {
        break;
      }
      if (pread_t(unique_pid, eproc + UniqueProcessId)) {
        pids[len++] = unique_pid;
      }
    }
    if (!pread_t(proc_links, eproc + ActiveProcessLinks)) {
      break;
    }
    eproc = (ULONG_PTR)
      proc_links.Flink - ActiveProcessLinks;
  } while (eproc != mem.cur_eproc);
  return len;
}

/*
  patch
*/

#define PATCH_CHECK 0x1F8AE27
#define PATCH_OFFSET 0x136C51B
#define PATCH_SPACE 21
#define PATCH_POCKET 0x2225F40

// note: KeyGameController__?(this, float, ...)
static int patch(void) {
  /*
    if (!byte_*) {
      ...
      byte_* = 1;
    }
  */
  if (!pread_u8(game + PATCH_CHECK)) {
    return 0;
  }
  /*
    note:
      mov qword ptr [rip + ?], rbx
      movaps xmmword ptr [rip + ?], xmm6
  */
  uint8_t patch_code[PATCH_SPACE] = {
    0x48, 0x89, 0x1d, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x29, 0x35, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
  };
  *(uint32_t*)(patch_code + 3) =
    (uint32_t)((PATCH_POCKET + 0) - (PATCH_OFFSET + 7));
  *(uint32_t*)(patch_code + 10) =
    (uint32_t)((PATCH_POCKET + 16) - (PATCH_OFFSET + 14));
  pwrite(game + PATCH_OFFSET, patch_code, PATCH_SPACE);
  return 1;
}

/*
  key
*/

#define MIN_KEY_SEC 3
#define MAX_KEY_SEC (10 + 1)

#define KEY_SEC_FLAG_PRESSED 0x1
#define KEY_SEC_FLAG_MODIFIED 0x2

struct key_sec_data {
  float time, len;
  int flags;
  // note: long note
  uint64_t cur_long_note;
};

#define DEFAULT_KEY 6

static int cur_key = DEFAULT_KEY;

static uint32_t key_sec_to_vkey(int key_sec) {
  switch (cur_key) {
  case 4: {
    switch (key_sec) {
    case 3: return 'D';
    case 4: return 'F';
    case 5: return VK_NUMPAD4;
    case 6: return VK_NUMPAD5;
    }
    break;
  }
  case 5: {
    switch (key_sec) {
    case 3: return 'D';
    case 4: return 'F';
    case 5: return VK_SPACE;
    case 6: return VK_NUMPAD4;
    case 7: return VK_NUMPAD5;
    }
    break;
  }
  case 6: {
    switch (key_sec) {
    case 3: return 'S';
    case 4: return 'D';
    case 5: return 'F';
    case 6: return VK_NUMPAD4;
    case 7: return VK_NUMPAD5;
    case 8: return VK_NUMPAD6;
    }
    break;
  }
  case 8: {
    switch (key_sec) {
    case 3: return 'A';
    case 4: return 'S';
    case 5: return 'D';
    case 6: return 'F';
    case 7: return VK_NUMPAD4;
    case 8: return VK_NUMPAD5;
    case 9: return VK_NUMPAD6;
    case 10: return VK_ADD;
    }
    break;
  }
  }
  return 0;
}

/*
  hid emulator
*/

struct delayed_keybd_up {
  float begin, last_press;
  float time;
  uint32_t vkey;
  // note: long note
  struct {
    float last_check, len;
    uint64_t cur_ptr;
  } long_note;
};

struct keybd_status {
  int press;
  float last_time;
};

struct hid_ctx {
  struct sbuf req_keybd_up;
  struct keybd_status keybd_status[0xff + 1];
};

static void hit_reset_keybd_status(struct hid_ctx* ctx, int reset_state) {
  if (reset_state) {
    uint32_t vkey = 1;
    for (; vkey <= 0xff; vkey++) {
      if (ctx->keybd_status[vkey].press) {
#if ENABLE_KEYBD
        keybd_up(&keybd, vkey);
#else
        printf("[keybd][up] %x\n", vkey);
#endif
      }
    }
  }
  memset(ctx->keybd_status, 0,
    sizeof(ctx->keybd_status));
}

static void hid_init(struct hid_ctx* ctx) {
  sbuf_init(&ctx->req_keybd_up,
    sizeof(struct delayed_keybd_up) * 0x20);
  hit_reset_keybd_status(ctx, 0);
}

static void hid_free(struct hid_ctx* ctx) {
  sbuf_free(&ctx->req_keybd_up);
}

static struct delayed_keybd_up* new_delayed_key_up(struct hid_ctx* ctx) {
  struct delayed_keybd_up* delayed_key_up;
  size_t iter = sbuf_used(&ctx->req_keybd_up);
  while (iter) {
    delayed_key_up = sbuf_ptr(&ctx->req_keybd_up,
      iter -= sizeof(struct delayed_keybd_up));
    if (!delayed_key_up->time) {
      return delayed_key_up;
    }
  }
  delayed_key_up = sbuf_alloc(&ctx->req_keybd_up,
    sizeof(struct delayed_keybd_up));
  if (delayed_key_up == NULL) {
    abort();
  }
  return delayed_key_up;
}

#define HID_INPUT_REPEAT_BEGIN 0.6f
#define HID_INPUT_REPEAT_PREQ 0.2f

// note: long note
#define HID_LONG_CHECK_MIN 0.0444f
#define HID_LONG_CHECK_MAX 0.0555f

#define LONG_DELAY_MIN 0.090f
#define LONG_DELAY_MAX 100.0f

static void hid_update(struct hid_ctx* ctx, float cur_time) {
  size_t begin = 0, end = sbuf_used(&ctx->req_keybd_up);
  for (; begin < end; begin += sizeof(struct delayed_keybd_up)) {
    struct delayed_keybd_up* delayed_key_up =
      sbuf_ptr(&ctx->req_keybd_up, begin);
    float time = delayed_key_up->time;
    if (time) {
      int done = 0;
      if (delayed_key_up->long_note.cur_ptr) {
        float delta_time = cur_time - delayed_key_up->begin;
        float note_min = MAX(delayed_key_up->long_note.len, LONG_DELAY_MIN);
        if (delta_time >= note_min) {
          if (delayed_key_up->long_note.last_check <= cur_time) {
            if (pread_u64(delayed_key_up->long_note.cur_ptr)) {
              delayed_key_up->long_note.last_check = cur_time +
                randomf2(HID_LONG_CHECK_MIN, HID_LONG_CHECK_MAX);
            }
            else {
              done = 1;
            }
          }
        }
      }
      if (done || time <= cur_time) {
        uint32_t vkey = delayed_key_up->vkey;
        if (ctx->keybd_status[vkey].press) {
#if ENABLE_KEYBD
          keybd_up(&keybd, vkey);
#else
          printf("[keybd][up] %x\n", vkey);
#endif
        }
        delayed_key_up->begin = 0;
        delayed_key_up->last_press = 0;
        delayed_key_up->time = 0;
        delayed_key_up->vkey = 0;
        // note: long note
        delayed_key_up->long_note.last_check = 0;
        delayed_key_up->long_note.len = 0;
        delayed_key_up->long_note.cur_ptr = 0;
        ctx->keybd_status[vkey].press = 0;
        ctx->keybd_status[vkey].last_time = 0;
      }
      else {
        if (delayed_key_up->begin + HID_INPUT_REPEAT_BEGIN <= cur_time) {
          if (delayed_key_up->last_press + HID_INPUT_REPEAT_PREQ <= cur_time) {
            uint32_t vkey = delayed_key_up->vkey;
            if (ctx->keybd_status[vkey].press) {
#if ENABLE_KEYBD
              keybd_down(&keybd, vkey);
#else
              printf("[keybd][down] %x\n", vkey);
#endif
              ctx->keybd_status[vkey].last_time = cur_time;
            }
            delayed_key_up->last_press = cur_time + HID_INPUT_REPEAT_PREQ;
          }
        }
      }
    }
  }
}

static struct key_sec_data* get_seq_key(struct sbuf key_sec_datas[], struct key_sec_data* key, int key_sec) {
  struct sbuf* data_buf = &key_sec_datas[key_sec];
  size_t begin = 0, end = sbuf_used(data_buf);
  for (; begin < end; begin += sizeof(struct key_sec_data)) {
    struct key_sec_data* data = sbuf_ptr(data_buf, begin);
    if (data == key) {
      continue;
    }
    if (!(data->flags & KEY_SEC_FLAG_PRESSED) && data->time > key->time) {
      return data;
    }
  }
  return NULL;
}

#define DELAY_MIN 0.02f
#define DELAY_RND_MIN 0.059f
#define DELAY_RND_MAX 0.099f
#define DELAY_MUL_MIN 0.555f
#define DELAY_MUL_MAX 0.666f

static float get_delayed_time(struct sbuf key_sec_datas[], struct key_sec_data* key, int key_sec) {
  float delay;
  struct key_sec_data* seq_key = get_seq_key(key_sec_datas, key, key_sec);
  if (seq_key == NULL) {
    delay = randomf2(DELAY_RND_MIN, DELAY_RND_MAX);
  }
  else {
    float delta_time = seq_key->time - key->time;
    if (delta_time > DELAY_RND_MAX) {
      delay = randomf2(DELAY_RND_MIN, DELAY_RND_MAX);
    }
    else {
      delay = delta_time * randomf2(DELAY_MUL_MIN, DELAY_MUL_MAX);
    }
    if (delay < DELAY_MIN) {
      delay = DELAY_MIN;
    }
  }
  return key->time + delay;
}

static float get_long_delayed_time(struct sbuf key_sec_datas[], struct key_sec_data* key, int key_sec) {
  struct key_sec_data* seq_key = get_seq_key(key_sec_datas, key, key_sec);
  float delay = LONG_DELAY_MAX;
  if (seq_key != NULL) {
    float delta_time = seq_key->time - key->time;
    if (delta_time > delay) {
      delta_time -= delay;
      if (delta_time < DELAY_MIN) {
        if (delay < DELAY_MIN) {
          delay = DELAY_MIN;
        }
        else {
          delay -= DELAY_MIN;
        }
      }
    }
    else {
      delay = delta_time;
      if (delay > DELAY_MIN) {
        delay -= DELAY_MIN;
      }
    }
  }
  if (delay < LONG_DELAY_MIN) {
    delay = LONG_DELAY_MIN;
  }
  return key->time + delay;
}

static int hid_keybd_press(struct hid_ctx* ctx, struct sbuf key_sec_datas[], struct key_sec_data* key, int key_sec, float cur_time) {
  struct delayed_keybd_up* delayed_key_up;
  uint32_t vkey = key_sec_to_vkey(key_sec);
  if (!vkey) {
    return 0;
  }
  if (ctx->keybd_status[vkey].press) {
    return 0;
    /*
      // note: almost miss
  #if ENABLE_KEYBD
      keybd_up(&keybd, vkey);
  #else
      printf("[keybd][up] %x\n", vkey);
  #endif
    */
  }
#if ENABLE_KEYBD
  keybd_down(&keybd, vkey);
#else
  printf("[keybd][down] %x\n", vkey);
#endif
  delayed_key_up = new_delayed_key_up(ctx);
  delayed_key_up->begin = cur_time;
  delayed_key_up->last_press = cur_time;
  if (key->len) {
    delayed_key_up->time = get_long_delayed_time(key_sec_datas, key, key_sec);
    // note: long note
    delayed_key_up->long_note.last_check = cur_time +
      randomf2(HID_LONG_CHECK_MIN, HID_LONG_CHECK_MAX);
    delayed_key_up->long_note.len = key->len;
    delayed_key_up->long_note.cur_ptr = key->cur_long_note;
  }
  else {
    delayed_key_up->time = get_delayed_time(key_sec_datas, key, key_sec);
    // note: long note
    delayed_key_up->long_note.last_check = 0;
    delayed_key_up->long_note.len = 0;
    delayed_key_up->long_note.cur_ptr = 0;
  }
  delayed_key_up->vkey = vkey;
  ctx->keybd_status[vkey].press = 1;
  ctx->keybd_status[vkey].last_time = cur_time;
  return 1;
}

/*
  game
*/

#define COOL_DELAY_MIN 0.024f
#define COOL_DELAY_MAX 0.028f

#define GOOD_DELAY_MIN 0.044f
#define GOOD_DELAY_MAX 0.048f

static volatile LONG
  jud_perfect[2] = { 0, 0 },
  jud_cool[2] = { 0, 0 },
  jud_good[2] = { 0, 0 },
  jud_miss[2] = { 0, 0 },
  jud_fail[2] = { 0, 0 };  // todo

static int game_pause = 0;

static void init_game(void) {
  uint64_t song_data = pread_u64(game + PATCH_POCKET);
  if (song_data) {
    song_data = 0;
    pwrite_t(game + (PATCH_POCKET + 0), song_data);
    pwrite_t(game + (PATCH_POCKET + 16), song_data);
  }
}

#define MAX_TIME 360.0f

static void set_cur_time(float cur_time) {
  pwrite_t(game + (PATCH_POCKET + 16), cur_time);
}

static float get_cur_time(float prev_time) {
  float cur_time = pread_f32(game + (PATCH_POCKET + 16));
  if (cur_time < prev_time || cur_time > MAX_TIME) {
    return 0;
  }
  return cur_time;
}

#define HIT_TEST 0.015f

static int hit_test(float hit_time, float press_time) {
  if (hit_time == press_time) {
    return 1;
  }
  if (hit_time < 0.0f || press_time < 0.0f || press_time > MAX_TIME) {
    return 0;
  }
  if (press_time < HIT_TEST) {
    if (hit_time < HIT_TEST) {
      return 1;
    }
  }
  else {
    if (
      hit_time >= press_time - HIT_TEST &&
      hit_time <= press_time + HIT_TEST) {
      return 1;
    }
  }
  return 0;
}

// note: slow
static void inc_key_time(struct sbuf key_data_bufs[], struct key_sec_data* key, float value) {
  int key_sec = MIN_KEY_SEC;
  for (; key_sec < MAX_KEY_SEC; key_sec++) {
    struct sbuf* sec_data = &key_data_bufs[key_sec];
    size_t begin = 0, end = sbuf_used(sec_data);
    for (; begin < end; begin += sizeof(struct key_sec_data)) {
      struct key_sec_data* data = sbuf_ptr(sec_data, begin);
      if (!(data->flags & (KEY_SEC_FLAG_PRESSED | KEY_SEC_FLAG_MODIFIED))) {
        if (hit_test(data->time, key->time)) {
          size_t next_iter = begin + sizeof(struct key_sec_data);
          if (next_iter < end) {
            struct key_sec_data* next_data = sbuf_ptr(sec_data, next_iter);
            if (
              next_data->time > DELAY_MIN &&
              next_data->time - DELAY_MIN <= data->time + value) {
              data->flags |= KEY_SEC_FLAG_MODIFIED;
              break;
            }
          }
          data->time += value;
          data->flags |= KEY_SEC_FLAG_MODIFIED;
          break;
        }
      }
    }
  }
}

// note: fast (unstable)
static void dec_key_time(struct sbuf key_data_bufs[], struct key_sec_data* key, float value) {
  int key_sec = MIN_KEY_SEC;
  for (; key_sec < MAX_KEY_SEC; key_sec++) {
    struct sbuf* sec_data = &key_data_bufs[key_sec];
    size_t begin = 0, end = sbuf_used(sec_data);
    for (; begin < end; begin += sizeof(struct key_sec_data)) {
      struct key_sec_data* data = sbuf_ptr(sec_data, begin);
      if (!(data->flags & (KEY_SEC_FLAG_PRESSED | KEY_SEC_FLAG_MODIFIED))) {
        if (hit_test(data->time, key->time)) {
          if (data->time >= value) {
            if (begin) {
              struct key_sec_data* prev_data = sbuf_ptr(sec_data,
                begin - sizeof(struct key_sec_data));
              // note: unstable
              if (prev_data->time + (DELAY_MIN * 2.0f) >= data->time - value) {
                data->flags |= KEY_SEC_FLAG_MODIFIED;
                break;
              }
            }
            data->time -= value;
          }
          data->flags |= KEY_SEC_FLAG_MODIFIED;
          break;
        }
      }
    }
  }
}

static void rnd_key_time(struct sbuf key_data_bufs[], struct key_sec_data* key, float value) {
  // note: 1 / 5
  if (random(6)) {
    inc_key_time(key_data_bufs, key, value);
  }
  else {
    dec_key_time(key_data_bufs, key, value);
  }
}

static struct key_sec_data* get_nearest_key(struct sbuf key_data_bufs[]) {
  struct key_sec_data* nearest_key = NULL;
  int key_sec = MIN_KEY_SEC;
  for (; key_sec < MAX_KEY_SEC; key_sec++) {
    struct sbuf* sec_data = &key_data_bufs[key_sec];
    size_t begin = 0, end = sbuf_used(sec_data);
    for (; begin < end; begin += sizeof(struct key_sec_data)) {
      struct key_sec_data* data = sbuf_ptr(sec_data, begin);
      if (!(data->flags & (KEY_SEC_FLAG_PRESSED | KEY_SEC_FLAG_MODIFIED))) {
        if (nearest_key == NULL || nearest_key->time > data->time) {
          nearest_key = data;
        }
        break;
      }
    }
  }
  return nearest_key;
}

#define KEY_LIFETIME 2.0f

static void play_game(struct hid_ctx* hid, struct sbuf key_data_bufs[]) {
  float cur_time = 0;
  int key_sec = MIN_KEY_SEC;
  for (; key_sec < MAX_KEY_SEC; key_sec++) {
    struct sbuf* sec_data = &key_data_bufs[key_sec];
    size_t begin = 0, end = sbuf_used(sec_data);
    for (; begin < end; begin += sizeof(struct key_sec_data)) {
      struct key_sec_data* data = sbuf_ptr(sec_data, begin);
      if (!(data->flags & KEY_SEC_FLAG_PRESSED)) {
        float delta_time;
        hid_update(hid,
          cur_time = get_cur_time(cur_time));
        if (data->time > cur_time) {
          if (!(data->flags & KEY_SEC_FLAG_MODIFIED)) {
            if (jud_cool[0] > 0) {
              struct key_sec_data* nearest_key = get_nearest_key(key_data_bufs);
              if (nearest_key != NULL) {
                rnd_key_time(key_data_bufs, nearest_key,
                  randomf2(COOL_DELAY_MIN, COOL_DELAY_MAX));
              }
              InterlockedDecrement(&jud_cool[0]);
            }
            else if (jud_good[0] > 0) {
              struct key_sec_data* nearest_key = get_nearest_key(key_data_bufs);
              if (nearest_key != NULL) {
                rnd_key_time(key_data_bufs, nearest_key,
                  randomf2(GOOD_DELAY_MIN, GOOD_DELAY_MAX));
              }
              InterlockedDecrement(&jud_good[0]);
            }
          }
          break;
        }
        delta_time = cur_time - data->time;
        if (delta_time <= KEY_LIFETIME) {
          if (jud_miss[0] > 0) {
            InterlockedDecrement(&jud_miss[0]);
          }
          else if (!game_pause) {
            hid_keybd_press(hid, key_data_bufs, data, key_sec, cur_time);
          }
        }
        data->flags |= KEY_SEC_FLAG_PRESSED;
        hid_update(hid,
          cur_time = get_cur_time(cur_time));
      }
    }
  }
  hid_update(hid,
    cur_time = get_cur_time(cur_time));
}

#define MIN_INPUT_DELAY 0.006f
#define MAX_INPUT_DELAY 0.009f

#define MIN_NOTE 30
#define MIN_NOTE_TIME 0.1f
#define MAX_NOTE_TIME MAX_TIME
#define MAX_NOTE_PER_SEC 1000

static int fetch_keys(struct sbuf key_data_bufs[], uint64_t music_track_arr, uint64_t cur_long_notes) {
  uint64_t music_track_vec[MAX_KEY_SEC] = { 0, };
  // note: note_max_len = pread_u64(music_track_arr + 24);
  int i = MIN_KEY_SEC;
  for (; i < MAX_KEY_SEC; i++) {
    sbuf_clear(&key_data_bufs[i]);
  }
  if (pread(music_track_vec, music_track_arr + 32, MAX_KEY_SEC * 8)) {
    int note_cnt = 0;
    int key_sec = MIN_KEY_SEC;
    for (; key_sec < MAX_KEY_SEC; key_sec++) {
      uint64_t music_track = music_track_vec[key_sec];
      uint32_t track_type = pread_u32(music_track + 16);
      // note: player
      if (track_type == 1) {
        // note: offset = pread_u32(music_track + 24);
        uint64_t note_list = pread_u64(music_track + 32);
        uint64_t note_arr = pread_u64(note_list + 16);
        uint64_t note_max_len = pread_u64(note_arr + 24);
        uint64_t note_idx = 0;
        float prev_time = 0.0f;
        if (note_max_len > MAX_NOTE_PER_SEC) {
          note_max_len = 0;
        }
        for (; note_idx < note_max_len; note_idx++) {
          uint64_t note = pread_u64((note_arr + 32) + note_idx * 8);
          if (note) {
            float note_time = pread_f32(note + 20);
            uint32_t note_type = pread_u32(note + 40);
            if (
              note_type == 1 &&
              note_time > prev_time &&
              note_time >= MIN_NOTE_TIME &&
              note_time <= MAX_NOTE_TIME) {
              float delay;
              struct key_sec_data* data = sbuf_alloc(&key_data_bufs[key_sec],
                sizeof(struct key_sec_data));
              if (data == NULL) {
                abort();
              }
              data->time = note_time;
              data->len = (float)pread_f64(note + 32);
              data->flags = 0;
              if (data->len < 0.0f) {
                return 0;
              }
              if (data->len) {
                data->cur_long_note = (cur_long_notes + 32) +
                  (key_sec - MIN_KEY_SEC) * 8;
              }
              else {
                data->cur_long_note = 0;
              }
              if (jud_perfect[0]) {
                InterlockedDecrement(&jud_perfect[0]);
              }
              else {
                delay = randomf2(MIN_INPUT_DELAY, MAX_INPUT_DELAY);
                if (random(2)) {
                  data->time += delay;
                }
                else if (data->time >= delay) {
                  data->time -= delay;
                }
              }
              prev_time = note_time;
              note_cnt++;
            }
          }
        }
      }
    }
    if (note_cnt < MIN_NOTE) {
      note_cnt = 0;
    }
    return note_cnt;
  }
  return 0;
}

static int get_cur_key(uint64_t key_game_con) {
  uint32_t game_mode = pread_u32(key_game_con + 24);
  switch (game_mode) {
  case 1: return 4;
  case 2: return 5;
  case 3: return 6;
  case 4: return 8;
  }
  return 0;
}

/*
  worker
*/

static volatile int
  exit_req = 0,
  reset_req = 0;

static unsigned int worker_thread(void* param) {
  struct hid_ctx hid;
  struct sbuf key_sec_datas[MAX_KEY_SEC];
  int i, loaded = 0;
  hid_init(&hid);
  for (i = MIN_KEY_SEC; i < MAX_KEY_SEC; i++) {
    sbuf_init(&key_sec_datas[i],
      sizeof(struct key_sec_data) * 32);
  }
  while (!exit_req) {
    uint64_t key_game_con = pread_u64(game + PATCH_POCKET);
    if (key_game_con) {
      uint64_t music_player = pread_u64(key_game_con + 64),
        music_sheet = pread_u64(music_player + 32),
        music_track_arr = pread_u64(music_sheet + 24);
      if (music_track_arr) {
        if (reset_req) {
          reset_req = 0, loaded = 0;
        }
        if (loaded) {
          play_game(&hid, key_sec_datas);
        }
        else {
          // note: in-game
          if (get_cur_time(0)) {
            uint64_t cur_long_notes = pread_u64(key_game_con + 0xd0);
            if (cur_long_notes) {
              int note_cnt = fetch_keys(key_sec_datas, music_track_arr, cur_long_notes);
              if (note_cnt) {
                hit_reset_keybd_status(&hid, 1);
                cur_key = get_cur_key(key_game_con);
                if (!cur_key) {
                  cur_key = DEFAULT_KEY;
                }
                jud_perfect[0] = 0,
                  jud_perfect[1] = 0,
                  jud_cool[0] = 0,
                  jud_cool[1] = 0,
                  jud_good[0] = 0,
                  jud_good[1] = 0,
                  jud_miss[0] = 0,
                  jud_miss[1] = 0,
                  jud_fail[0] = 0,
                  jud_fail[1] = 0;
                set_cur_time(0.0f);
                printf("loaded %d, %d\n", cur_key, note_cnt);
                loaded = 1;
              }
            }
          }
        }
      }
      else if (loaded) {
        hit_reset_keybd_status(&hid, 1);
        set_cur_time(0.0f);
        printf("unloaded\n");
        loaded = 0;
      }
    }
  }
  for (i = MIN_KEY_SEC; i < MAX_KEY_SEC; i++) {
    sbuf_free(&key_sec_datas[i]);
  }
  hid_free(&hid);
  return 0;
}

static unsigned int input_thread(void* param) {
  while (!exit_req) {
    int cmd = econ_get(&econ);
    if (cmd) {
      switch (cmd) {
      // note: /
      case 1: {
        InterlockedIncrement(&jud_cool[0]);
        printf("cool [%d]\n",
          ++jud_cool[1]);
        break;
      }
      // note: *
      case 2: {
        InterlockedIncrement(&jud_good[0]);
        printf("good [%d]\n",
          ++jud_good[1]);
        break;
      }
      // note: -
      case 3: {
        InterlockedIncrement(&jud_miss[0]);
        printf("miss [%d]\n",
          ++jud_miss[1]);
        break;
      }
      // note: num .
      case 4: {
        jud_cool[0] = 0;
        printf("cool 0 [%d]\n",
          jud_cool[1]);
        break;
      }
      // note: home
      case 10: {
        if (game_pause) {
          game_pause = 0;
          printf("play\n");
        }
        else {
          game_pause = 1;
          printf("pause\n");
        }
        /*
          printf("reset\n");
          reset_req = 1;
        */
        break;
      }
      // 5 = [
      // 6 = ]
      // note: num1
      case 7: {
        InterlockedIncrement(&jud_perfect[0]);
        printf("perfect [%d]\n",
          ++jud_perfect[1]);
        break;
      }
      // note: num2
      case 8: {
        InterlockedAdd(&jud_cool[0], 2);
        printf("cool 2 [%d]\n",
          jud_cool[1] += 2);
        break;
      }
      // note: num3
      case 9: {
        InterlockedAdd(&jud_cool[0], 3);
        printf("cool 3 [%d]\n",
          jud_cool[1] += 3);
        break;
      }
      }
    }
    Sleep(60);
  }
  return 0;
}

/*
  thread
*/

#ifdef __MINGW32__
typedef unsigned (__stdcall *_beginthreadex_proc_type)(void*);
#endif

static HANDLE create_thread(_beginthreadex_proc_type proc, void* param, int high_prio) {
  HANDLE handle = (HANDLE)
    _beginthreadex(NULL, 0, proc, param, 0, NULL);
  if (handle == NULL) {
    return NULL;
  }
  if (high_prio) {
    SetThreadPriority(handle,
      THREAD_PRIORITY_HIGHEST);
  }
  return handle;
}

static void close_thread(HANDLE handle, int wait) {
  if (handle != NULL) {
    if (wait) {
      WaitForSingleObject(handle, INFINITE);
    }
    CloseHandle(handle);
  }
}

/*
  main
*/

static void get_line(char* buf, int len) {
  for (;;) {
    if (fgets(buf, len, stdin) != NULL) {
      if (*buf != '\n') {
        int i = 0;
        for (; i < len; i++) {
          if (buf[i] == '\n') {
            buf[i] = '\0';
            break;
          }
        }
        break;
      }
    }
  }
}

static int loop(void) {
  int last_patch = 0;
  char buf[32], c;
  HANDLE worker, input;
  init_game();
  worker = create_thread(worker_thread, NULL, 1),
    input = create_thread(input_thread, NULL, 1);
  if (worker == NULL || input == NULL) {
    exit_req = 1;
    close_thread(worker, 1);
    close_thread(input, 1);
    return 1;
  }
  while (!exit_req) {
    system("cls");
    printf(
      "patch: %d\n"
      "status: %s\n"
      "[p]atch\n"
      "[r]eset\n"
      "[e]xit\n",
      last_patch, game_pause ? "pause" : "play"
    );
    get_line(buf, 32);
    c = buf[0];
    switch (tolower(c)) {
    case 'p': {
      last_patch = patch();
      break;
    }
    case 'r': {
      reset_req = 1;
      break;
    }
    case 'e': {
      exit_req = 1;
      break;
    }
    }
  }
  close_thread(worker, 1);
  close_thread(input, 1);
  return 0;
}

static int run(void) {
  pid_list_t pids;
  int i = 0, len = get_pids(EZ2ON, pids);
  for (; i < len; i++) {
    ULONG_PTR pid = pids[i];
    if (pmem_attach_to_pid(&mem, pid)) {
      game = get_mod_base(pid, GAME);
      if (game) {
        break;
      }
    }
  }
  if (!game) {
    return 1;
  }
  loop();
  pmem_detach(&mem);
  return 0;
}

int main(int argc, char* argv[]) {
  int exit_code = 0;
  random_init(0);
  if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
    return 1;
  }
  if (!mixx_init()) {
    return 1;
  }
  if (!pmem_init(&mem)) {
    return 1;
  }
  if (keybd_init_ex(&keybd, "maxx") && econ_init(&econ, ECON_OFFSET)) {
    econ_get(&econ);
    exit_code = run();
  }
  return exit_code;
}
