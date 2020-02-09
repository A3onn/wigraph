# WiGraph

#### Simple program to graph what's happening in a PCAP containing IEEE802.11 frames.

## Table of contents

- [Presentation](#Presentation)
- [Usage](#Usage)
- [Disclamer](#Disclamer)

## Presentation

### Dependencies

To use this program, you'll need to install some libraries:
- `dpkt` to parse frames
- `networkx` to represent the graph in memory and outputing it to a file

You can install theses dependencies automatically by using the `requirements.txt` file :

`pip install -r requirements.txt`

## Usage

To create a graph, you just have to execute the program with `-p` and `-o` as arguments :

`./main.py -p <pcap file> -o <output name w/o extension>`

This will generate a PNG file containing the graph. If you want another format, you can use the `-f` argument followed by the format :
- png
- jpg
- gif
- json
- imap
- cmapx
- svg
- svgz
- pdf
- dot (source file for GraphViz)
- ps
- fig

Keep in mind that the output file generated was meant to be used with GraphViz to generate images, so for exemple, in the JSON format there is the color of each nodes.

### Splitting graph

If your pcap file contains a lot of traffic, the output will be really big and will take a long time to generate. To avoid this, you can split the graph into subgraphs and generate a file for each subgraphs. To do this, you can use the `-s` argument:

`./main.py -p <pcap file> -o <output name w/o extension> -s`

This will generate each subgraphs __AND__ a file containing all nodes without edges : `<output name w/o extension>_alone_nodes.<format>`.

If you don't want this file, you can add the `-a` argument.

### Output content

If you don't want, for some reason, to parse _probe requests_, you can use the `-i` to ignore them.
But if you just don't want them to be included in the output file, you can use the `-e` argument. They will be parsed but not included.

By default the program tries to do an OUI lookup which takes some memory and some time, you can deactivate it by using the `-k` argument.


This program uses GraphViz, and it uses by default _sfdp_. You can change it with `-g` argument followed by the name of the program :
- dot
- neato
- twopi
- circo
- fdp
- sfdp

### Filter

You can filter frames by either their MAC addresses (works with the source and destination) with `-m` argument followed by one or multiple MAC addresses, or by their BSSID (works only with management frames) with the `-b` argument followed by one or multiple BSSIDs.

## Disclamer
