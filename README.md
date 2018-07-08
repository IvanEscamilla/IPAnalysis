# IP Packet Analysis 

program written in C (C99) to show the implementation of the following signature:

`bool is_local_address(uint8_t *ipv4_header, uint32_t address, uint32_t subnet_mask);`

This function should return **true** if both of the following conditions are true:

* The 'address' is part of the same local network as the source address provided in the header
* The checksum in 'ipv4_header' is valid.

The byte buffer 'ipv4_header' represents an Internet Protocol header as defined in RFC 791
(http://www.ietf.org/rfc/rfc791.txt)

## Execute notes

* Clone the repository.
* make sure you have **gcc** compiler and **GNU make** installed on your computer.
    
**Installing compiler using apt command**
```
$ sudo apt-get update
$ sudo apt-get upgrade
$ sudo apt-get install build-essential
```
**Verify installation**

```
$ whereis gcc make
$ gcc --version
$ make -v
```

* go to the repository folder.
* `make`
* Run the program using `./IPAnalysis.o`.
