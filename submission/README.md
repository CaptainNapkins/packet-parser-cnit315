# WireMinnow
This is the CNIT 315 final project. This network packet parser can output to a file and display results.

## Usage

1. Compile the program using a C compiler (e.g., GCC):
    ```
    make all
    ```

2. Run the program:
    ```
    sudo ./wire_minnow
    ```

3. Follow the on-screen instructions to interact with the program:
   ``` 
    - Select an interface to listen on 
    - Confirm the start of the packet capture       
   ```
4. The user may specify the data once an interface is selected and packets are captured:
   ```
    1. Filter by Src IP Address
    2. Filter by Dst IP Address
    3. Filter by Src Port
    4. Filter by Dst Port
    5. Display All traffic
    6. Quit
   ```

5. Additional Functionality
- Before the filter selection, enter in the name of a file to write the filtered data to
- Continually filter data, display data, and write data to a file. 

## How Does it Work?
We use libpcap to parse packets coming in over a network interface. 

In order to persistently keep the state of the packet capture, once packets are captured, 
their information is placed into user defined structs. These structs hold information like IPs, 
ports, sequence numbers, etc. Each packet is a struct and each struct is added to a master buffer.
This buffer is used by other functions to view and parse this stateful packet capture. 

`capture.c` - Defines the structs used to store IP and protocl specific information, the libpcap callback
function, as well as the large global buffer used to statefully store packets. 

`filter.c` - Iterates through the master buffer and based on user defined filters can iterate through it
and parse all all of the packet information and display it to users. 

`file_ops.c` - Does the same thing as `filter.c` except instead of printing packet data to the screen, 
it will write it a file of the users choosing based on a passed file pointer. 

`main.c` - Contains all base program logic. Takes user input, defines the loops, and governs the control flow of the program. 

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

