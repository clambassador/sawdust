# Sawdust

Process lumen/haystack packet logs for interesting results.

TODO: describe data file format

## Installation

1. Install git, scons, ccache and clang++ (apt-get install git scons ccache clang++)
2. Get libib: git clone https://github.com/clambassador/ib.git
3. Compile libib: cd ib; scons
4. Set sawdust's PATH_TO_IB in SConstruct to point to where you cloned
ib (i.e., parent directory)
5. Compile sawdust: scons
6. Set up the config file: sawdust.cfg

## Running

./sawdust

Outputs the usage instructions: packetprocessor filename device hwid processor
args

filename: log file from monkey run
device: corresponding device file name
hwid: the hwid to identify which runs correspond to the same physical device
processor: the processor to use to analyze packets (see below)
args: optional args for processor if available.

The program analyses the packets in the log file and the output for each
processor is different. All data is written to stdout and can be saved to a file
with redirection.

## Processors

### bigdata

outputs a list of packets that went to a particular domain.

### id_search
Outputs a list of pii that matches from packets. The format is as follows:

time, app, version, dns, sni, ip, port, tls, data type, packet sha1 hash

This is post-processed into database format using id_search.py

### keymap

Output a map of key-values based on the packet data with json objections and http requests

### null

do nothing, test the other parts of the system such as packet loading and
parsing

## Batch Running

To simplify matters, run.sh runs on every log/device file pair in a directory.
Its usage is:

sh run.sh path processor args

For example,
    sh run.sh ~/monkey-runs id_search

It prints the current file being processed to stderr, allowing the output of the
processor to be redirected.

