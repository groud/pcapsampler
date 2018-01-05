#include <argp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

enum mode {
  COUNT_SYS,
  COUNT_RAND_KN,
  COUNT_RAND_UNIFORM,
  TIME_SYS,
  TIME_RAND_POISSON
};

const char *argp_program_version = "pcapsampler 1.0";
const char *argp_program_bug_address = "";
static char doc[] = "pcapsampler";
static char args_doc[] = "INPUT_FILE OUTPUT_FILE";

static struct argp_option options[] = {
  {"mode", 'm', "MODE", 0, "Sampling mode (COUNT_SYS, COUNT_RAND_UNIFORM, COUNT_RAND_KN, TIME_SYS, TIME_RAND_POISSON", 0},
  {"rate", 'r', "RATE", 0, "Samples a packet every RATE packet or packets/seconds", 0},
  { 0 }
};

struct arguments {
  char * input;
  char * output;
  float sampling_rate;
  enum mode mode;
};

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
    case 'r':
      arguments->sampling_rate = atof(arg);
      break;

    case 'm':
      if(!strcmp(arg, "COUNT_SYS")) {
        arguments->mode = COUNT_SYS;
      } else if(!strcmp(arg, "COUNT_RAND_KN")) {
        arguments->mode = COUNT_RAND_KN;
      } else if(!strcmp(arg, "COUNT_RAND_UNIFORM")) {
        arguments->mode = COUNT_RAND_UNIFORM;
      } else if(!strcmp(arg, "TIME_SYS")) {
        arguments->mode = TIME_SYS;
      }else if(!strcmp(arg, "TIME_RAND_POISSON")) {
        arguments->mode = TIME_RAND_POISSON;
      } else {
        return ARGP_ERR_UNKNOWN;
      }
      break;

    case ARGP_KEY_NO_ARGS:
      argp_usage (state);
      break;

    case ARGP_KEY_ARG:
      if(state->arg_num == 0) arguments->input = arg;
      if(state->arg_num == 1) arguments->output = arg;
      break;

    case ARGP_KEY_END:
      if (state->arg_num < 2)
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0};

// ----------------------------------------------
// ---------------- PACKET BASED ----------------
// ----------------------------------------------

/* Systematic sampling by packet */
void process_systematic_count(pcap_t * input, pcap_dumper_t * output, int rate) {
  const u_char * packet;
  struct pcap_pkthdr header;

  int i=0;
  while((packet = pcap_next(input, &header)) != NULL) {
    if((i % rate)==0) {
      pcap_dump((u_char *)output, &header, packet);
    }
    i++;
  }
}

int cmpfunc (const void * a, const void * b) {
   return ( *(unsigned int*)a - *(unsigned int*)b );
}
void choose_k_out_of_N(unsigned int n, unsigned int N, unsigned int * indexes) {
  unsigned int chosen = 0;
  while (chosen < n) {
    unsigned int rand_index = rand()%N;

    // We check if the index was already chosen
    bool already_there = false;
    for(unsigned int i=0; i<chosen; i++) {
      if(indexes[i] == rand_index) {
        already_there = true;
      }
    }

    //Add the index
    if(!already_there) {
      indexes[chosen] = rand_index;
      chosen++;
    }
  }

  //Sorting
  qsort(indexes, n, sizeof(unsigned int), cmpfunc);
}

/* Random sampling by packet - n out of N */
void process_random_k_out_of_N(pcap_t * input, pcap_dumper_t * output, unsigned int nb_samples, unsigned int nb_picked_samples) {
  const u_char * packet;
  struct pcap_pkthdr header;

  unsigned int * indexes = malloc (nb_picked_samples * sizeof(int));

  unsigned int i=0;
  int passed=0;
  while((packet = pcap_next(input, &header)) != NULL) {
    if((i % nb_samples)==0) {
      // We select nb_picked_samples out of nb_samples
      choose_k_out_of_N (nb_picked_samples, nb_samples, indexes);
      passed=0;
    }
    if ((i % nb_samples)==indexes[passed]) {
      pcap_dump((u_char *)output, &header, packet);
      passed++;
    }

    i++;
  }
}

/* Random sampling by packet - uniform */
void process_random_uniform(pcap_t * input, pcap_dumper_t * output, double probability) {
  const u_char * packet;
  struct pcap_pkthdr header;

  probability = 1 / probability;
  while((packet = pcap_next(input, &header)) != NULL) {
    if(((double) rand() / RAND_MAX) < probability) {
      pcap_dump((u_char *)output, &header, packet);
    }
  }
}

// ----------------------------------------------
// ---------------- TIME BASED ------------------
// ----------------------------------------------

/* Systematic sampling by time */
void process_systematic_time(pcap_t * input, pcap_dumper_t * output, double rate) {
  const u_char * packet;
  struct pcap_pkthdr header;

  struct timeval delta = {rate, (rate-floor(rate)) * 1000000};

  struct timeval tmp;
  struct timeval last;

  bool first = true;

  while((packet = pcap_next(input, &header)) != NULL) {
    if(first) {
      memcpy(&last, &(header.ts), sizeof(struct timeval));
      first = false;
    }

    timersub(&(header.ts), &last, &tmp);

    int nb = 0;
    while (timercmp(&tmp, &delta, >=)) {
      timersub(&tmp, &delta, &tmp);
      nb++;
    }
    for (int i = 0; i < nb; i++) {
      pcap_dump((u_char *)output, &header, packet);
      memcpy(&last, &(header.ts), sizeof(struct timeval));
    }
  }
}

/* Random smapling by time - poisson */
void process_random_poisson(pcap_t * input, pcap_dumper_t * output, double rate) {
  const u_char * packet;
  struct pcap_pkthdr header;

  double time_delta;
  double limit = rate * 100;

  struct timeval delta;
  struct timeval next;

  bool first = true;

  while((packet = pcap_next(input, &header)) != NULL) {
    if(first) {
      memcpy(&next, &(header.ts), sizeof(struct timeval));
      time_delta = 0.0 - rate * log(1.0 - ((double) rand() / (double) RAND_MAX));
      time_delta = MIN(limit, time_delta);
      delta.tv_sec  = time_delta;
      delta.tv_usec = (time_delta-floor(time_delta)) * 1000000;
      timeradd(&next, &delta, &next);
      first = false;
    }

    if (timercmp(&header.ts, &next, >=)) {
      pcap_dump((u_char *)output, &header, packet);

      time_delta = 0.0 - rate * log(((double) rand() / (double) RAND_MAX));
      time_delta = MIN(limit, time_delta);
      delta.tv_sec  = time_delta;
      delta.tv_usec = (time_delta-floor(time_delta)) * 1000000;
      timeradd(&next, &delta, &next);
    }
  }
}

// ----------------------------------------------
// ---------------- MAIN ------------------------
// ----------------------------------------------

int main (int argc, char **argv) {
  char errbuf[1000];

  srand(time(NULL));

  // Sampling rate
  struct arguments arguments;
  arguments.mode = COUNT_SYS;
  arguments.sampling_rate = 1000;
  arguments.input = NULL;
  arguments.output = NULL;

  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  // Open input file
  pcap_t * pcap_input = pcap_open_offline(arguments.input, errbuf);
  if(!pcap_input) {
    printf("%s\n",errbuf);
    return errno;
  }

  pcap_dumper_t * pcap_output = pcap_dump_open(pcap_input, arguments.output);
  if(!pcap_output) {
    printf("%s\n",errbuf);
    return errno;
  }

  // Always dump the first packet
  const u_char * packet;
  struct pcap_pkthdr header;
  if((packet = pcap_next(pcap_input, &header)) != NULL) {
    pcap_dump((u_char *)pcap_output, &header, packet);
  }

  // Process
  switch(arguments.mode) {
    case COUNT_SYS:
      process_systematic_count(pcap_input, pcap_output, (int) arguments.sampling_rate);
      break;
    case COUNT_RAND_KN:
      process_random_k_out_of_N(pcap_input, pcap_output, arguments.sampling_rate, 1);
      break;
    case COUNT_RAND_UNIFORM:
      process_random_uniform(pcap_input, pcap_output, arguments.sampling_rate);
      break;
    case TIME_SYS:
      process_systematic_time(pcap_input, pcap_output, arguments.sampling_rate);
      break;
    case TIME_RAND_POISSON:
      process_random_poisson(pcap_input, pcap_output, arguments.sampling_rate);
      break;
    default:
      break;
  }

  // Close
  pcap_dump_close(pcap_output);
  pcap_close(pcap_input);
}
