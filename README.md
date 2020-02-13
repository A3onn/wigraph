# WiGraph

#### A simple to use program to visualise what's happening in a PCAP containing IEEE802.11 frames.

### Dependencies

To use this program, you'll need to install some libraries:
- `dpkt` to parse frames
- `networkx` to represent the graph in memory and outputing it to a file

You can install theses dependencies automatically by using the `requirements.txt` file :

`pip install -r requirements.txt`

## Usage

To create a graph:

`./main.py -p <pcap file> -o <output name w/o extension>`

This will generate a PNG file containing the graph. If you want another format, you can use the `-f` argument followed by the format :
- jpg
- gif
- svg
- svgz
- pdf
- dot (source file for GraphViz)
- ps
- png

### Splitting graph

If your pcap file contains a lot of traffic, the image will be really big and will take a long time to generate. To avoid this, you can split the graph into multiple images. To do this, you can use the `-s` argument:

`./main.py -p <pcap file> -o <output name w/o extension> -s`

This will generate each subgraphs __AND__ an image containing all nodes without edges, if you don't want it, you can use the `-a` parameter.

Even if you split the graph, images can be really big. You can choose to not draw probe request with the `-e` argument, the program will be able to split a bit more graphs. If you want to ignore all probe requests totally, you may use the `-i` argument.

By default the program tries to do an OUI lookup. This may takes some memory and some time so you can disable it by using the `-k` argument.

The default [GraphViz](https://graphviz.org/) program is _sfdp_. You can choose another program by using the `-g` argument followed by the name of the program :
- dot
- neato
- twopi
- circo
- fdp
- sfdp

### Filter

You can filter frames by either their MAC addresses (works with the source and destination) with the `-m` argument followed by one or multiple MAC addresses seperated by spaces. You can filter by BSSID as well with the `-b` argument followed by one or multiple BSSIDs seperated by spaces too.

## Disclamer

Sometime a node will be marked as a repeater. This means that the station has sent frames typically sent by an AP and some sent by a client. Most of the time it will be a repeater but sometimes false positif can occur, for exemple if a smartphone acts as a client (= sends probe requests, auth frames etc...) and later becomes an AP (= sends beacon frames).
