# PCAPsampler

PCAPsampler is a simple program that selects a set of packets from a PCAP file
and write it to another one. It features five algorithms with a configurable
sampling rate.

## Sampling algorithms:

- **Systematic count-based:** systematically selects a packet every `RATE` packet.
- **Random probabilistic count-based:** produces a random number for each packet, and selects it with a probability of 1/`RATE`
- **1-out-of-N:** every `RATE` (=N) packets, chooses an integer between 0 and `RATE` and uses it as the index of the next packet to sample.
- **Systematic time-BASED:** selects a packet every 1/`RATE` second.
- **Random time-based:** generate a random waiting time (exponential distribution) between each selection. The average sampling rate is 1/`RATE` per second.  

## Usage:

```
Usage: pcapsampler [OPTION...] INPUT_FILE OUTPUT_FILE
pcapsampler

  -m, --mode=MODE            Sampling mode (COUNT_SYS, COUNT_RAND_UNIFORM,
                             COUNT_RAND_KN, TIME_SYS, TIME_RAND_POISSON
  -r, --rate=RATE            Samples a packet every RATE packet or
                             packets/seconds
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```
