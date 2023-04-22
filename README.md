# Routology

routology is a command-line tool written in Python that mimics the functionality of the traceroute command, but sends UDP, TCP SYN, and ICMP probes each time. It has the same options as traceroute and is designed to help you diagnose network problems by showing the path that packets take from your computer to a destination host, and the latency or loss rate at each hop.
Installation

To use routology, you need to have Python 3 installed on your system, or use the provided executable. You can then install routology using pip:

```bash
pip install routology
```

## Usage

To use routology, simply open a terminal window and type:

```bash
routology [options] <file_with_destination_hosts>
```

Replace <file_with_destination_hosts> with the path to a file that contains the IP addresses or domain names of the hosts that you want to trace the route to, one per line.

You can customize the behavior of Routology using the same options as traceroute. For example, you can specify the maximum number of hops to try with the -m option, or specify the initial time-to-live (TTL) value with the -f option. See the help message for a full list of options:

```bash
routology --help
```

By default, routology sends UDP packets starting from port 33434, TCP packets to port 80, and ICMP packets each with a TTL of 1, and increments the TTL by 1 for each subsequent probe until it reaches the destination or a maximum TTL value of 64. You can customize the probe type, port, initial TTL, and maximum TTL using command-line options.

## How it works

Routology is built around an asynchronous architecture to allow receiving and sending a massive number of packets at the same time.
It uses the asyncio module to create a pool of tasks that send packets and receive responses, and a queue to store the packets that are waiting to be sent.
The main loop of the program is responsible for printing the results of the packets that have been received and creating the graph of the route.

The main components of the program are:

* **Scheduler**: The scheduler is responsible for sending probes while keeping only hosts which are not receiving responses. It creates a batch of packets tasks according
to the set number of simultaneous packets to send, and reports the number it has sent to a callback function which the main loop uses to print the progress.

* **Collector**: The collector is responsible for receiving packets and storing them in a manner that allows the main loop to print the results and draw the graph.

* **Dispatcher**: The dispatcher is responsible for sending responses to the scheduler and collector.

## Options

* **-m, --max-hops**: The maximum number of hops to try before giving up. Defaults to 30.
* **-f, --first-ttl**: The initial time-to-live (TTL) value. Defaults to 1.
* **-U, --udp-port**: The port to send probes to. Defaults to 33434.
* **-T, --tcp-port**: The port to send probes to. Defaults to 80.
* **-N, --sim-queries**: The number of simultaneous queries to send. Defaults to 16.
* **-n, --no-dns**: Do not resolve hostnames.
* **-w, --wait-time**: The number of seconds to wait for a response. Defaults to 3.
* **-q, --queries**: The number of series to send to each host. Defaults to 1.
* **--output-text-file**: The path to the file where the results will be saved in text format.
* **--output-image-file**: The path to the file where the results will be saved in graph image.

## License

routology is licensed under the MIT License. See the LICENSE file for details.
