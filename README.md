![BSD License](https://img.shields.io/badge/license-BSD-blue.svg) ![Latest Release](https://img.shields.io/github/release/Dev-iL/pcap2matlab.svg) ![# Latest Commits](https://img.shields.io/github/commits-since/Dev-iL/pcap2matlab/v1.03.svg)

# pcap2matlab

`pcap2matlab` brings the TShark network protocol analyzer capabilities to MATLAB. This allows performing live packet captures as well as analyses of saved capture files (`*.pcap`, `*.pcapng` etc.), inside MATLAB.

The function is based on the [TShark network protocol analyzer](http://www.wireshark.org/docs/man-pages/tshark.html) and can operate in two modes:
  1. **Capture mode** in which it starts listening on the requested network interface, capturing
      packets based on some predefined criteria (i.e. filter) and outputs the relevant packet fields
      based on the `decodeas` and dissector input arguments.
  2. **Read mode** in which it reads an already existing packet capture ("_pcap_") file, extracts and dissects packets based on some predefined criteria (i.e. filter) and output the relevant packet fields based on the `decodeas` and dissector input arguments.

The function currently supports Windows 32/64-bit as well as Linux 32/64-bit platforms. Other platforms may be easily added in the future.

## Usage
```
pcap2matlab(filter, decodeas_and_dissector,filename_or_interface, capture_stop_criteria)
```
### Inputs:
 * **`filter`** – A TShark format capture filter argument (TShark [`-f flag`](https://www.wireshark.org/docs/man-pages/tshark.html#f-capture-filter) like `'net 10.10.10.4 and src port 12001'`) or a display filter argument (TShark [`-Y flag`](https://www.wireshark.org/docs/man-pages/tshark.html#Y-displaY-filter) like `'ip.src==10.10.10.4 and udp.srcport==12001'`), depending on the selected mode of operation (i.e. capture or read).
For more information see the Wireshark wiki articles on [Capture Filters](http://wiki.wireshark.org/CaptureFilters) and [Display Filters](http://wiki.wireshark.org/DisplayFilters).

 * **`decodeas_and_dissector`** – One of two types:
  **1)** A MATLAB structure whose field names are the requested packet field names to extract
    where the content of each field of this structure comprises the byte/bits offsets to
    capture for this specific field. The content of the structure may be in one of the following forms:

    **_(a):_** A MATLAB decimal vector specifying the byte offsets to capture. For example:
  ```
decodeas_and_dissector.sn = [43 44 45 46]
decodeas_and_dissector.timestamp: [47:54]
  ```
    will instruct the function to capture 2 fields named "sn" and "timestamp" with byte offsets `43-46` and `47-54` respectively. The offset is calculated from the very first byte (offset `0`) of the packet including the layer 2 portion (starting from the MAC destination address in the case of an ethernet frame). The returned value will be a **decimal number** having the value of these aggregated byte offsets.

    **_(b):_** A string comprising the offset bytes to capture in hexadecimal representation. For example:
  ```
decodeas_and_dissector.sn = '43:46'
decodeas_and_dissector.timestamp: '47:54'
  ```
will instruct the function to capture 2 fields named "sn" and "timestamp" with byte offsets `43-46` and `47-54` respectively. The returned value will be a **string** comprising the entire content of these byte offsets (if only a single byte offset is required, the colon can be omitted, e.g. `decodeas_and_dissector.sn = '43'`).

    **_(c):_** Same as **_(b)_** with an additional `'/'` character followed by a specific BIT offsets to be extracted from the specified byte offsets (specified before the `'/'`). For example, the dissector lines:
  ```
decodeas_and_dissector.firstflag = '43/0:1'
decodeas_and_dissector.secondflag = '45/6'
  ```
will instruct the function to capture MSB bits `0:1` from byte offset `43` in the `'firstflag'` field and bit `6` from byte offset `45` in the `'secondflag'` field. The returned value is a **decimal number** having the value of the extracted bits.

  **2)** A cell vector of strings comprising the TShark `decodeas` expression (TShark
    [`-d` flag](https://www.wireshark.org/docs/man-pages/tshark.html#d-layer-type-selector-decode-as-protocol)) (not mandatory, but if required it must appear first) as well as additional
    TShark dissector expressions (TShark [`-e` flag](https://www.wireshark.org/docs/man-pages/tshark.html#e-field)). Each dissector expression results in a matching field in the output `struct`. For example: the cell of strings `{'tcp.port==8888,http';'frame.number';'frame.time';'tcp.length';'tcp.srcport'}` will instruct the function to decode packets captured from TCP port `8888` as `http`.Then, 4 fields will be extracted from each captured packet: `frame.number`, `frame.time`, `tcp.length` and `tcp.srcport` and written to the output `struct`:
  ```
capture =

1x97 struct array with fields:

      framenumber
      frametime
      tcplength
      tcpsrcport
  ```

 * **`filename_or_interface`** – Can be one of two things:
  1. An integer that identifies the network interface from which to start capturing (TShark [`-i` flag](https://www.wireshark.org/docs/man-pages/tshark.html#i-capture-interface)). Setting this input argument to an integer (as opposed to a string) will automatically set the function to work in capture mode.
  2. A filename string that identifies the pcap file to read. Setting this input argument to a filename string (as opposed to an integer) will automatically set the function to work in read mode.

* **`capture_stop_criteria`**  – **_Relevant to capture mode only_** (should not be assigned when working in read mode). Sets the "capture stop" criteria (TShark [-a](https://www.wireshark.org/docs/man-pages/tshark.html#a-capture-autostop-condition) or [-c](https://www.wireshark.org/docs/man-pages/tshark.html#c-capture-packet-count) flags). This input
    argument can be one of the following:
  1. An integer that prescribes the total number of packets to capture (TShark -c flag).
  2. A string that identifies the _capture stop_ criteria (TShark -a flag).
  3. A cell array containing several _capture stop_ criteria. For example, `{'duration:10',100}` will stop capturing after 10 sec or 100 packets, **whichever comes first**.

### Outputs:
The output is a MATLAB `struct` containing one row for each captured packet, where the fields of the `struct` contain the results of packet dissection, according to the fields requested in the input arguments.

### Examples:
An example of parsing a GVSP ([GigE Vision Stream Protocol](http://www.visiononline.org/vision-standards-details.cfm?type=5)) capture is shown in `pcap2matlab_example.m`.
Before running the example, please make sure that:
  1. Wireshark v2.0.0 or above installed (for it to be able to recognize the `gvsp` protocol).
  2. The folder containing the TShark binary (i.e. `tshark.exe`; e.g. `C:\Program Files\Wireshark`) is added to your system PATH.

### Testing environment:
The code that was added after release 1.03 was developed and tested on _Windows 10 + MATLAB R2016a_.

--------------
### Related projects:
* [`sharktools`](https://github.com/armenb/sharktools) - a set of tools written in C that are built using the Wireshark sources resulting in `MEX` files. For **Mac / Linux only!**

### Contributors, 3rd party code, and licenses:
* **Jake Hughey** for the included library "[Nested sort of structure arrays](http://www.mathworks.com/matlabcentral/fileexchange/28573-nested-sort-of-structure-arrays)" (BSD License).
* **Alon Geva** (`v <= 1.03`) (BSD License).
* **Dev-iL** (`v > 1.03`) (BSD License).