#ifndef CODECS_BENCH_H
#define CODECS_BENCH_H

#include "AmArg.h"

#define DEFAULT_BECH_FILE_PATH "/usr/lib/sems/audio/codecs_bench.wav"

int load_testing_source(string path,unsigned char *&buf);
void get_codec_cost(int payload_id,unsigned char *buf, int size, AmArg &cost);

#endif // CODECS_BENCH_H
