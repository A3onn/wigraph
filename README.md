# WiGraph

![Wigraph logo](Wigraph.png)

#### A simple to use program to visualise what's happening in a PCAP containing IEEE802.11 frames.

### Dependencies

WiGraph required some dependencies:
- `dpkt` to parse frames
- `networkx` to represent the graph in memory and drawing it to a file

You can install theses dependencies automatically by using the `requirements.txt` file :

`pip install -r requirements.txt`

## Usage

To create a graph:

`./wigraph.py -p <pcap file> -o <output name w/o extension>`

This is the base command, you can other parameters as well.

#### Format

This will generate a PNG file containing the graph. If you want another format, you can use the `-f` argument followed by the format :
- jpg
- gif
- svg
- svgz
- pdf
- dot (source file for GraphViz)
- ps
- png

#### Optimization

If your pcap file contains a lot of traffic, the image will be really big and will take a long time to generate. To avoid this, you can split the graph into multiple images. To do this, you can use the `-s` argument:

`./main.py -p <pcap file> -o <output name w/o extension> -s`

This will generate each subgraphs __AND__ an image containing all nodes without edges, if you don't want it, you can use the `-a` parameter.

Even if you split the graph, images can be really big. You can choose to not draw probe responses with the `-e` argument, this will let the program able to split a bit more graphs. If you want to ignore all probe responses totally, you may use the `-i` argument.

WiGraph uses [GraphViz](https://graphviz.org/) to generate images. The default used program is _sfdp_. You can choose another program by using the `-g` argument followed by the name of the program :
- dot
- neato
- twopi
- circo
- fdp
- sfdp

By default the program tries to do an OUI lookup. This may takes some memory and some time so you can disable it by using the `-k` argument.

#### Filter

You can filter frames by either their MAC addresses (works with the source and destination) with the `-m` argument followed by one or multiple MAC addresses seperated by space.
You can filter by BSSID as well with the `-b` argument followed by one or multiple BSSIDs seperated by spaces too.

## Disclamer

Sometime a node will be marked as a repeater (green node). This means that the station has sent frames typically sent by an AP and some sent by a client. Most of the time it will be a repeater but sometimes false positive can occur, for exemple if a smartphone acts as a client (= sends probe requests, auth frames etc...) and later becomes an AP (= sends beacon frames).

## Note

WiGraph is 100% passive, this means it doesn't send __ANY__ frame or packet.
Furthermore this program can easely be used in a script because it doesn't require any manual intervention once it is run.
