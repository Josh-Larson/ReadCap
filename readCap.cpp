/*
 * Author: Josh Larson
 * Date Created: July 2, 2012
 * Last Modified: July 9, 2012
 * Description: This program reads .cap/.pcap files and
 *    searches through them for specific opcodes or search
 *    strings
 * 
 * To-Do:
 *  # Brute-Force CRC Calculator
 *  # Packet Order, have it determine which packets come after what
 *  # Read ObjController message
 *  # Read DeltasMessage
 * 
 * Example CRC's:
[14:11:35] <@Treeku> FD8E7F7F = 4,253,974,399
[14:11:38] <@Treeku> BE09EB2F = 3,188,321,071
[14:11:41] <@Treeku> 8982BBFE = 2,307,046,398
[14:11:43] <@Treeku> 60C3FFFD = 1,623,457,789
[14:11:46] <@Treeku> EA6BE77D = 3,932,940,157
[14:11:50] <@Treeku> E327FB7F = 3,811,048,319
 */
#include <iostream>
#include <sstream>
#include <fstream>

#include <iomanip>
#include <vector>
#include <cstdio>
#include <climits>
#include <algorithm>

#include "PcapRead.cpp"
#include "Depend.h"
#include "Interpret.h"
#include "Analyze.h"
using namespace std;

void ProcessFile(string file, string outputFile, string search);
bool testCRC(unsigned int CRC, string file);
void getCRC(string file);
vector <unsigned short> crcList(string file);

int main(int argc, char *argv[]) {
	string file = "";
	string outputFile = "";
	string search = "";
	bool getCrc = false;
	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			if (!string(argv[i]).compare("-f")) {
				if (i + 1 >= argc) continue;
				file = argv[i+1];
			}
			if (!string(argv[i]).compare("-o")) {
				if (i + 1 >= argc) continue;
				outputFile = argv[i+1];
			}
			if (!string(argv[i]).compare("-disableAsciiOutput")) {
				asciiValues = false;
			}
			if (!string(argv[i]).compare("-disableOutput")) {
				output = false;
			}
			if (!string(argv[i]).compare("-filter")) {
				if (i + 1 >= argc) continue;
				filter = argv[i+1];
			}
			if (!string(argv[i]).compare("-search")) {
				if (i + 1 >= argc) continue;
				search = argv[i+1];
			}
			if (!string(argv[i]).compare("-getCRC")) {
				getCrc = true;
			}
		}
	}
	if (getCrc == true) {
		getCRC(file);
	} else {
		if (file == "") {
			cout << "You did not specify a file.\n";
			help(argv[0]);
			return 0;
		}
		if (output && outputFile == "") {
			outputFile = "output.txt";
			ofstream STREAM(outputFile.c_str());
			STREAM.close();
		}
		if (1) {
			ofstream STREAM(outputFile.c_str());
			STREAM.close();
		}
		ProcessFile(file, outputFile, search);
	}
	return 0;
}

void ProcessFile(string file, string outputFile, string search) {
	PcapReader reader(file, false);
	bool reading = true;
	int numPackets = 0;
	vector <int> searchPackets;
	bool ascii = true;
	for (unsigned int i = 0; i < search.length(); i++) {
		if (!isalpha(search[i])) ascii = false;
	}
	string asciiSearch = "";
	string unicodeSearch = "";
	for (int i = 0; i < search.length(); i++) {
		stringstream STREAM;
		STREAM << hex << (int)search[i];
		asciiSearch.append(STREAM.str());
		unicodeSearch.append(STREAM.str());
		unicodeSearch.append("00");
	}
	/*
		Read through packets in capture log
	*/
	while (reading) {
		char *packet = reader.GetNext();
		int length = reader.length();
		numPackets = reader.packets();
		/*
			Set default writing
		*/
		if (filter.compare("deny") == 0)
			writeTxt = false;
		else
			writeTxt = true;
		/*
			Determine if we are at end of file
			If not, then interpret the file
		*/
		if (reader.end()) {
			cout << dec << "Hit end of file. After " << numPackets << " packets.\n";
			reading = false;
			continue;
		} else {
			if (packet == NULL) continue;
			if (packet[1] == 2 && packet[0] == 0) {
				reader.SetCRC(htonl(*((uint32 *)&packet[6])));
				cout << "Set CRC. - " << hex << (unsigned int)htonl(*((uint32 *)&packet[6])) << dec << "\n";
			}
			/*
			Search:
				Search for packets that have the ASCII/UNICODE string in it, or the actual hexcode
			 */
			if (search != "") {
				string packetStr = "";
				char *finalhash = new char[length*2+1];
				char hexval[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
				for (int j = 0; j < length; j++){
					finalhash[j*2] = hexval[((packet[j] >> 4) & 0xF)];
					finalhash[(j*2) + 1] = hexval[(packet[j]) & 0x0F];
				}
				finalhash[length*2] = '\0';
				packetStr = finalhash;
				delete[] finalhash;
				/*for (int i = 0; i < length; i++) {
					stringstream STREAM;
					STREAM << hex << packet[i];
					if (STREAM.str() == "4f") cout << "\n";
					packetStr.append(STREAM.str());
				}*/
				if (packetStr.find(search) != string::npos) {
					searchPackets.push_back(numPackets);
				} else if (ascii) {
					if (packetStr.find(asciiSearch) != string::npos) {
						searchPackets.push_back(numPackets);
					} else if (packetStr.find(unicodeSearch) != string::npos) {
						searchPackets.push_back(numPackets);
					}
				}
			}
			InterpretPacket(packet, length, 1, numPackets);
		}
		/*
			Output the packet to file if the conditions say so
		*/
		if (writeTxt && output && packet != NULL) {
			ofstream outputSTREAM(outputFile.c_str(), ios::out | ios::app);
			string fileOutput = "";
			int ticks = 0;
			string strAsciiValues = "";
			for (int i = 0; i < length; i++) {
				fileOutput = "";
				fileOutput.append("0x");
				char fileBuf[16];
				sprintf(fileBuf, "%.2X", (unsigned char) packet[i]);
				fileOutput.append(fileBuf);
				fileOutput.append(", ");
				outputSTREAM << fileOutput;
				if (asciiValues) {
					if (isprint((unsigned char)packet[i]))
						strAsciiValues.push_back((unsigned char)packet[i]);
					else
						strAsciiValues.push_back('.');
				}
				ticks++;
				if (ticks >= 16 || i+1 == length) {
					ticks = 0;
					if (asciiValues) {
						outputSTREAM << "#    " << strAsciiValues << "\n";
					} else {
						outputSTREAM << "\n";
					}
					strAsciiValues = "";
				}
			}
			outputSTREAM << "\n";
			outputSTREAM.close();
		}
		//if (numPackets >= 10) reader.close();
	}
	reader.close();
	for (int i = 0; SwgStrOpcodes[i] != ""; i++) {
		cout << "Opcode: " << hex << SwgOpcodes[i][0] << " \"" << SwgStrOpcodes[i] << "\"";
		cout << dec << " [" << SwgOpcodes[i][1] << "]\n";
		for (unsigned int t = 0; t < foundInPacket.size(); t++) {
			if (SwgOpcodes[i][0] == foundInPacket[t][0]) {
				cout << "\tFound in packet #" << foundInPacket[t][1] << "\n";
			}
		}
		cout << "\t";
		for (unsigned int o = 0; o < opcodeDataExample.size(); o++) {
			if ((unsigned int)opcodeDataExample[o][0] == (unsigned int)SwgOpcodes[i][0]) {
				for (int a = 1; a < opcodeDataExample[o].size(); a++) {
					printf("%.2X ", (unsigned char)opcodeDataExample[o][a]);
				}
			}
		}
		cout << "\n";
		cout << "\t";
		for (unsigned int o = 0; o < opcodeDataExample.size(); o++) {
			if ((unsigned int)opcodeDataExample[o][0] == (unsigned int)SwgOpcodes[i][0]) {
				for (int a = 1; a < opcodeDataExample[o].size(); a++) {
					int itemID = 0;
					for (int b = 0; b < struc.size(); b++) {
						if ((unsigned int)struc[b][0] == (unsigned int)SwgOpcodes[i][0]) {
							if ((struc[b][1] < a-1 && struc[b][1] + struc[b][2] >= a-1)) {
								itemID = struc[b][3];
							}
						}
					}
					cout << " " << itemID << " ";
				}
			}
		}
		cout << "\n";
	}
	cout << "Packets with your search parameters: [" << dec << searchPackets.size() << "]\n";
	for (unsigned int i = 0; i < searchPackets.size(); i++) {
		cout << "\tFound in packet #" << searchPackets[i] << "\n";
	}
}

void getCRC(string file) {
	/*cout << "Getting CRC's from file.\n";
	vector <unsigned int> knownCRC;
	if (1) {
		ifstream STREAM("crc_list.txt");
		string line= "";
		while (STREAM.good()) {
			getline(STREAM, line);
			bool comma = false;
			string crc = "";
			for (int i = 0; i < line.length(); i++) {
				if (line[i] == ',') { comma = true; continue; }
				if (comma == false) continue;
				crc.push_back(line[i]);
			}
			stringstream ss;
			ss << crc;
			unsigned int CRC = 0;
			ss >> CRC;
			if (CRC < 1000000001) continue;
			knownCRC.push_back(CRC);
		}
	}
	sort(knownCRC.begin(), knownCRC.begin()+knownCRC.size());*/
	cout << "Beginning CRC Scanning.\n";
	int currentCRC = 0;
	int starting = 1;
	int currentStart = starting;
	int modifier = 0;
	int startingModifier = 8;
	bool crcWorks = false;
	unsigned int crc = 0;
	time_t startTime = time(NULL);
	for (modifier = startingModifier; modifier > 1 && !crcWorks; modifier /= 2) {
		if (modifier != startingModifier) currentStart += modifier;
		cout << "At modifier " << modifier << "\n";
		cout << "\tTime taken:      " << time(NULL) - startTime << "\n";
		cout << "\tCRC's Processed: " << (UINT_MAX-currentStart) / 8 << "\n";
		for (unsigned int i = currentStart; i < UINT_MAX && !crcWorks; i++) {
			
			/* Debugging stuff - not neccessary */
			if (((i-starting)/*/8*/) % 1000000 == 0) cout << (i-starting)/1000000/*/8*/ << "\n";
			if (time(NULL) - startTime >= 60) { crcWorks = true; crc = i; }
			
			if (i < 800000000) continue;
			
			/* Test the hexcode to see if it's accurate */
			if (*((char *)&i)   <= 5) continue;
			if (*((char *)&i+1) <= 5) continue;
			if (*((char *)&i+2) <= 5) continue;
			if (*((char *)&i+3) <= 5) continue;
			
			
			/* Test the 3 zero's in a row */
			if (i % 1000000000 < 1000000) continue;
			if (i % 1000000 < 1000) continue;
			if (i % 1000 == 0) continue;
			
			/* Test the CRC */
			crcWorks = testCRC(i, file);
			if (crcWorks) crc = i; // See if the CRC works
		}
	}
	cout << (crc-starting) << " crc's per minute.\n";
	cout << "Ending CRC: " << crc << "\n";
	//cout << "Working CRC: 0x" << hex << crc << "\n";
}
/*
CRC Test 1: 7630       - Original
CRC Test 2: 7584       - Removed counter for ObjControllers
CRC Test 3: 1,031,452  - Change conditionals to be faster
CRC Test 4: 1,044,618  - Modified conditionals
*/

bool testCRC(unsigned int CRC, string file) {
	PcapReader reader(file, true);
	reader.SetCRC(CRC);
	bool reading = true;
	/*
		Read through packets in capture log
	*/
	while (reading) {
		char *packet = reader.GetNext();
		int length = reader.length();
		if (length == -1) continue;
		if (packet == NULL) { reading = false; continue; }
		/* Check CRC At end of packet */
		if (length <= 30) continue;
		/*
			Determine if we are at end of file
			If not, then scan the file
		*/
		if (packet[5] == 0x19) {
			if (packet[4] == 0x00) {
				for (unsigned int i = 10; i < length-3; i++) { /* 7 + 3 = 10 */
					if (packet[i] == 0x80) {
						if (packet[i-1] == 0xCE) {
							if (packet[i-2] == 0x5E) {
								if (packet[i-3] == 0x46) {
									reader.close();
									return true;
								}
							}
						}
					}
				}
				reader.close();
				return false;
			}
		}
		// -----
		for (unsigned int i = 11; i < 25; i++) { /* 8 + 3 = 10 [2 + 2 + 2 + 2]*/
			if (packet[i] == 0x80) {
				if (packet[i-1] == 0xCE) {
					if (packet[i-2] == 0x5E) {
						if (packet[i-3] == 0x46) {
							reader.close();
							return true;
						}
					}
				}
			}
		}
	}
	reader.close();
	return false;
}

vector <unsigned short> crcList(string file) {
	PcapReader reader(file);
	bool reading = true;
	vector <unsigned short> list;
	/*
		Read through packets in capture log
	*/
	while (reading) {
		char *packet = reader.GetNext();
		int length = reader.length();
		if (length == -1) continue;
		if (packet == NULL) { reading = false; continue; }
		/* Check CRC At end of packet */
		if (length <= 30) continue;
		/*
			Determine if we are at end of file
			If not, then scan the file
		*/
		if (packet[0] == 0 && packet[1] == 0x09) {
			unsigned short crc =   ((unsigned short)(packet[length-2] << 8) & 0xFF00)
								 | ((unsigned short)packet[length-1] & 0x00FF);
			bool valid = true;
			for (int i = 0; i < list.size() && valid; i++) {
				if (list[i] == crc) valid = false;
			}
			if (valid) {
				list.push_back(crc);
			}
		}
	}
	reader.close();
	return list;
}

