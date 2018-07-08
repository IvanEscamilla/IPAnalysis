//*********************************************************************************
// Headers
//*********************************************************************************
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

//*********************************************************************************
// Defines
//*********************************************************************************

// internet addres struct
typedef struct {
    uint32_t addr; // 32-bit int (4 bytes)
} in_addr;

// IP header addres
typedef struct __attribute__((packed, aligned(1)))  {
	uint8_t ip_tos;       		// Type of service 1 Byte
	uint8_t ip_ihl:4;			// IHL 4bits 
	uint8_t ip_version:4; 		// IP Version 4bits
    uint16_t ip_lenght;  		// Total lenght 2 Byte
    uint16_t ip_id;   			// Identification 2 Byte
    uint16_t ip_offset;  		// Flags and Fragmentation Offset 2 Byte
    uint8_t ip_p;        	 	// Protocol 1 Byte
    uint8_t ip_ttl;       		// Time to live 1 Byte
    uint16_t ip_chksum;  			// Header Checksum 2 Byte
    uint32_t ip_src;        	// Source addres 4 Byte
    uint32_t ip_dst;        	// Destination addres 4 Byte
} ip_header;


//*********************************************************************************
// Global variables
//*********************************************************************************

bool isInSameNetwork = false;
uint8_t* headerPointer;
//*********************************************************************************
// Function declaration
//*********************************************************************************

uint32_t address_to_inet(const char *str);
uint32_t swap_32(uint32_t value);
uint16_t swap_16(uint16_t value);
bool calculate_checksum(uint8_t *ipv4_header, uint32_t length);
bool is_local_address(uint8_t *ipv4_header, uint32_t address, uint32_t subnet_mask);

//*********************************************************************************
// Main
//*********************************************************************************

int main(void) {

	ip_header theHeader;
	in_addr ipAddress, subnetMask;
	
	/*header  example 1
		45 00 00 6c
        92 cc 00 00
        38 06 e4 04
        92 95 ba 14 <- source ip
        a9 7c 15 95 <- destination ip

        0x4 	<- ip version
        0x5 	<- IHL
        0x00	<- type of service
        0x006c	<- total length
        0x92cc	<- id
        0x0000	<- Flags and fragmentation offset
        0x38	<- time to live
        0x06 	<- protocol
        0xe404	<- checksum
        0x9295ba14 <- source ip 146.149.186.20
        0xa97c1595 <- destination ip 169.124.21.149
	*/
	theHeader.ip_version = (uint8_t)0x04;
	theHeader.ip_ihl = (uint8_t)0x05;
    theHeader.ip_tos = (uint8_t)0x00;
    theHeader.ip_lenght = (uint16_t)0x006c;
    theHeader.ip_id = (uint16_t)0x92cc;
    theHeader.ip_offset = (uint16_t)0x0000;
    theHeader.ip_ttl = (uint8_t)0x38;
    theHeader.ip_p = (uint8_t)0x06;
    theHeader.ip_chksum = (uint16_t)0xe404;
    theHeader.ip_src = (uint32_t)0x9295ba14;
	theHeader.ip_dst = (uint32_t)0xa97c1595;

	headerPointer = (uint8_t*)(&theHeader);

	ipAddress.addr = address_to_inet("192.168.100.1");
	subnetMask.addr = address_to_inet("255.255.255.0");
	
	isInSameNetwork = is_local_address(headerPointer, ipAddress.addr, subnetMask.addr);
	
	if (isInSameNetwork){
		printf("Example 1 result: is in same network\n");
	} else {
		printf("Example 1 result: is not in same network\n");
	}

	/*header  example 2

		00:1c:42:00:00:08 > 00:1c:42:8e:f9:42, IPv4, length 98: 10.211.55.2 > 10.211.55.9: ICMP echo request, id 33845, seq 0, length 64

		45 00 00 54 
		f4 36 00 00 
		40 01 02 c2 
		0a d3 37 02
		0a d3 37 09

        0x4 	<- ip version
        0x5 	<- IHL
        0x00	<- type of service
        0x0054	<- total length
        0xf436	<- id
        0x0000	<- Flags and fragmentation offset
        0x40	<- time to live
        0x01 	<- protocol
        0x02c2	<- checksum
        0x0ad33702 <- source ip 10.211.55.2
        0x0ad33709 <- destination ip 10.211.55.9
	*/

	theHeader.ip_version = (uint8_t)0x04;
	theHeader.ip_ihl = (uint8_t)0x05;
    theHeader.ip_tos = (uint8_t)0x00;
    theHeader.ip_lenght = (uint16_t)0x0054;
    theHeader.ip_id = (uint16_t)0xf436;
    theHeader.ip_offset = (uint16_t)0x0000;
    theHeader.ip_ttl = (uint8_t)0x40;
    theHeader.ip_p = (uint8_t)0x01;
    theHeader.ip_chksum = (uint16_t)0x02c2;
    theHeader.ip_src = (uint32_t)0x0ad33702;
	theHeader.ip_dst = (uint32_t)0x0ad33709;

	ipAddress.addr = address_to_inet("192.168.0.3");
	subnetMask.addr = address_to_inet("255.255.255.0");
	
	isInSameNetwork = is_local_address(headerPointer, ipAddress.addr, subnetMask.addr);
	
	if (isInSameNetwork){
		printf("Example 2 result: is in same network\n");
	} else {
		printf("Example 2 result: is not in same network\n");
	}

	/*header  example 3
		45 00 00 54 
		
		f4:5c:89:bd:06:1d > 2c:0e:3d:4e:f7:f0, IPv4, length 98: 192.168.0.3 > 192.168.0.10: ICMP echo reply, id 3, seq 1, length 64
		
		45 00 00 54 
		00 00 40 00 
		40 01 b9 4b 
		c0 a8 00 03
		c0 a8 00 0a

        0x4 	<- ip version
        0x5 	<- IHL
        0x00	<- type of service
        0x0054	<- total length
        0x0000	<- id
        0x4000	<- Flags and fragmentation offset
        0x40	<- time to live
        0x01 	<- protocol
        0xb94b	<- checksum
        0xc0a80003 <- source ip 192.168.0.3
        0xc0a8000a <- destination ip 192.168.0.10
	*/

	theHeader.ip_version = (uint8_t)0x04;
	theHeader.ip_ihl = (uint8_t)0x05;
    theHeader.ip_tos = (uint8_t)0x00;
    theHeader.ip_lenght = (uint16_t)0x0054;
    theHeader.ip_id = (uint16_t)0x0000;
    theHeader.ip_offset = (uint16_t)0x4000;
    theHeader.ip_ttl = (uint8_t)0x40;
    theHeader.ip_p = (uint8_t)0x01;
    theHeader.ip_chksum = (uint16_t)0xb94b;
    theHeader.ip_src = (uint32_t)0xc0a80003;
	theHeader.ip_dst = (uint32_t)0xc0a8000a;

	ipAddress.addr = address_to_inet("192.168.0.10");
	subnetMask.addr = address_to_inet("255.255.255.0");
	
	isInSameNetwork = is_local_address(headerPointer, ipAddress.addr, subnetMask.addr);
	
	if (isInSameNetwork){
		printf("Example 3 result: is in same network\n");
	} else {
		printf("Example 3 result: is not in same network\n");
	}

	return 0;

}


/**
* is_local_address
* This function calculates the checksum of the ipv4 header.
* 
* The checksum algorithm is:
*
*  	The checksum field is the 16 bit one's complement of the one's
*   complement sum of all 16 bit words in the header.  For purposes of
*	computing the checksum, the value of the checksum field is zero.
*
* @param  	ipv4_header  	Pointer of the ipv4 header
* @param  	header_length  	header length
*
* @return bool	if the checksum calculated is equal to the header checksum
*				return true else false
*/
bool is_local_address(uint8_t *ipv4_header, uint32_t address, uint32_t subnet_mask){

	//reconstruct the struct
	ip_header *hd = (ip_header*) ipv4_header;

	// revert network byte order of the addess and mask
	uint32_t addr = swap_32(address);
	uint32_t sMask = swap_32(subnet_mask);

	uint32_t shift = 24;
	uint8_t maskOct[4] = {0,0,0,0};
	uint8_t addrOct[4] = {0,0,0,0};
	uint8_t hAddrOct[4] = {0,0,0,0};
	uint8_t octA[4] = {0,0,0,0};
	uint8_t octB[4] = {0,0,0,0};
	uint32_t bitMask = 0xFF000000;
	uint8_t i= 0;

	// verify if the checksum is valid
	if( calculate_checksum( ipv4_header, sizeof(ip_header)) ) {
		//printf("checksum is valid\n");
		for( i = 0; i < 4; i++){
			maskOct[i] = (uint8_t)(( sMask & bitMask) >> shift);
			addrOct[i] = (uint8_t)(( addr & bitMask) >> shift);
			hAddrOct[i] = (uint8_t)(( hd->ip_src & bitMask) >> shift);

			octA[i] = addrOct[i] & maskOct[i];
			octB[i] = hAddrOct[i] & maskOct[i];

			bitMask = bitMask >> 8;
			shift -= 8;
		}

		if ((octA[0] == octB[0]) && (octA[1] == octB[1]) && (octA[2] == octB[2]) && (octA[3] == octB[3])) {
			 return true;
		}
	}

	return false;
}


/**
* calculate_checksum
* This function calculates the checksum of the ipv4 header.
* 
* The checksum algorithm is:
*
*  	The checksum field is the 16 bit one's complement of the one's
*   complement sum of all 16 bit words in the header.  For purposes of
*	computing the checksum, the value of the checksum field is zero.
*
* @param  	ipv4_header  	Pointer of the ipv4 header
* @param  	header_length  	header length
*
* @return bool	if the checksum calculated is equal to the header checksum
*				return true else false
*/
bool calculate_checksum(uint8_t *ipv4_header, uint32_t header_length) {
	
	//reconstruct the struct
	ip_header *hd = (ip_header*) ipv4_header;
	uint16_t headerChksm = hd->ip_chksum;

	//set the header chksum to 0 for purposes of computing the checksum
	hd->ip_chksum = 0;

	uint16_t* headerPointer = (uint16_t*) ipv4_header;	// Cast the 8-bit pointor to a 16-bits pointer
	uint32_t sum = 0;									// sum variable
	uint16_t i = 0;										// counter variable
	uint8_t carry = 0;									// carry variable
	
	for ( i = 0; i < header_length/2; ++i) {
		// get 16-bits 
		uint16_t msb = *headerPointer++;

		// one's complement of the value pointed
		msb = (uint16_t)~msb;
		sum += msb;
		// get the carry from the sum result
		carry = (uint8_t)((sum&0XF0000) >> 16);
		// check if there is a carry from the sum result
		// if carry is grater tha 0, first we have to remove it
		// form the sum variable and add it to the sum result
		if( carry > 0){
			sum = (sum&0XFFFF);
			sum += carry;
			carry = 0;
		}
	}

	// one's complement the result
	// sum = (uint16_t)~sum;

	//restore the header chksum
	hd->ip_chksum = headerChksm;
	// check if the computed checksum us equal to the header checksum
	return headerChksm == sum;
}

/**
* address_to_inet
* This function convert an ipv4 string to a network byte order address.
*
* @param  	*str  	Char pointer to the string to be converted
s
* @return uint32_t	network byte order address
*/
uint32_t address_to_inet(const char *str) {
	
	uint32_t addr = 0;
	uint32_t shift = 0;
	uint32_t num = 0;

	while( shift < 32){
		uint32_t character = (uint32_t)*str++;
		// make a shift if the character is a point or the end of the char array
		if(  character == '.' || character == 0) {
			addr |= (num << shift);
			shift += 8;
			num = 0;
		} else {
			// remover the ascii offset of the ascii digit and convert it to 
			// a base-10 number
			num = 10*num + (character - '0');
		}
	}

	return addr;
}

/**
* swap_32
*  This function swap a 32-bit (4-byte) value.
*
* @param 	value  	32-bit value to be swapped
s
* @return uint32_t	value swapped
*/
uint32_t swap_32(uint32_t value){
  return (uint32_t)(((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | ((value & 0xFF0000) >> 8) | ((value & 0xFF000000) >> 24));
}

/**
* swap_16
*  This function swap a 16-bit (2-byte) value.
*
* @param 	value  	16-bit value to be swapped
s
* @return uint32_t	value swapped
*/
uint16_t swap_16(uint16_t value){
  return (uint16_t)(((value & 0xFF) << 8) | ((value & 0xFF00) >> 8));
}