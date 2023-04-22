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

## License

routology is licensed under the MIT License. See the LICENSE file for details.
