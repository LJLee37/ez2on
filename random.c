#include "random.h"

#include <time.h>
#include <stdlib.h>

void random_init(unsigned int seed) {
  if (!seed) {
    seed = (unsigned int)time(NULL);
  }
  srand(seed);
}

float randomf(void) {
  return (float)rand() / RAND_MAX;
}

float randomf2(float min, float max) {
  return min + randomf() * (max - min);
}

int random(int val) {
  return (int)(randomf() * val);
}

int random2(int min, int max) {
  return (int)(randomf() * (float)(max - min + 1)) + min;
}
