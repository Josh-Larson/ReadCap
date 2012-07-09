#ifndef INTERPRET_H
#define INTERPRET_H
#include <iostream>
#include <iomanip>
#include "PcapRead.h"
#include <vector>
#include <cstdio>
#include <sstream>
#include "Analyze.h"
using namespace std;

/*
Type:
	1 = Sony
	2 = SWG
*/
void InterpretPacket(char *packet, int length, int type, int packetNum) {
	unsigned int pktOpcode = 0;
	if (type == 1) {
		pktOpcode = (unsigned int) (*((unsigned short*)packet));
	} else if (type == 2) {
		pktOpcode = *((unsigned int*)&packet[2]);
	}
	if (packet[0] == 0 && packet[1] == 0x09 && type == 1) {
		if (packet[4] == 0 && packet[5] == 0x19) { /* Multi-Pkt */
			char subPacket[500];
			int offset = 0;
			int size = 0;
			int startSize = 0;
			for (int i = 6; i < length; i++) {
				if (size == 0) {
					size = packet[i];
					if (startSize != 0)
						InterpretPacket(subPacket, startSize, 2, packetNum); // Recurse into other packets
					for (int o = 0; o < offset; o++) subPacket[o] = 0;
					offset = 0;
					startSize = size;
				} else {
					subPacket[offset] = packet[i];
					size--;
					offset++;
				}
			}
		} else {
			InterpretPacket(packet+4, length-4, 2, packetNum);
		}
	} else if (type == 2) {
		//cout << hex << "Found Opcode [" << *((unsigned int*)&packet[2]) << "] at packet # " << packetNum << "\n";
		unsigned int opcode = ( (unsigned char)packet[2] << 24)
							 | ((unsigned char)packet[3] << 16)
							 | ((unsigned char)packet[4] << 8)
							 |  (unsigned char)packet[5];
		pktOpcode = opcode;
		//cout << "Opcode: " << hex << opcode << dec << " - " << packetNum << "\n";
		for (int i = 0; SwgStrOpcodes[i] != ""; i++) {
			if (opcode == (unsigned int)SwgOpcodes[i][0]) {
				bool foundPacket = false;
				for (unsigned int a = 0; a < foundInPacket.size(); a++) {
					if (SwgOpcodes[i][0] == foundInPacket[a][0] && packetNum == foundInPacket[a][1]) {
						foundPacket = true;
						break;
					}
				}
				if (!foundPacket) {
					SwgOpcodes[i][1]++;
					vector <int> tmp;
					tmp.push_back(SwgOpcodes[i][0]);
					tmp.push_back(packetNum);
					foundInPacket.push_back(tmp);
					
					char subPacket[500];
					int offset = 0;
					for (int a = 6; a < length; a++) {
						subPacket[offset] = packet[a];
						offset++;
					}
					AnalyzeStruct(subPacket, length-6-3, SwgOpcodes[i][0]); // -6 for the offset, -3 for the footer
				}
			}
		}
	}
	// writeTxt
	// FilterOpcodesAllow
	// FilterOpcodesDeny
	if (!filter.compare("all")) {
		for (int i = 0; FilterOpcodesDeny[i] != -1 && writeTxt; i++) {
			if (pktOpcode == (unsigned int)FilterOpcodesDeny[i]) writeTxt = false;
		}
	} else if (!filter.compare("deny")) {
		for (int i = 0; FilterOpcodesAllow[i] != -1 && !writeTxt; i++) {
			if (pktOpcode == (unsigned int)FilterOpcodesAllow[i]) {
				writeTxt = true;
				continue;
			}
		}
	}
}
#endif
