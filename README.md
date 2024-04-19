# WireMinnow
This is the CNIT 315 final project. This network packet parser can output to a file and display results.

## Usage

1. Compile the program using a C compiler (e.g., GCC):
    ```
    gcc -o packet_manipulation packet_manipulation.c -lpcap
    ```

2. Run the program:
    ```
    ./packet_manipulation
    ```

3. Follow the on-screen instructions to interact with the program:
       - List Interfaces
       - Add Interface
       - Exit

4. The user may specify the data once an interface is selected:
       - Display Whole Capture
       - Display ICMP Packets
       - Display UDP Packets
       - Display TCP Packets
       - Go Back
   
6. In a separate menu, users can start the capture or return if they make a mistake:
       - Start Capture
       - Go Back

## Requirements
- C compiler (e.g., GCC)
- libpcap library

## Authors
Matthew Graham, Gabe Samide, and Nathan Geller


## Notes
- libpcap: https://www.tcpdump.org/pcap.html
- https://www.tcpdump.org/
- http://yuba.stanford.edu/~casado/pcap/section1.html
- https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/

