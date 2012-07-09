#ifndef ANALYZE_H
#define ANALYZE_H
#include <iostream>
#include <iomanip>
#include "PcapRead.h"
#include <vector>
#include <cstdio>
#include <sstream>
#include "Depend.h"
using namespace std;

void AnalyzeStruct(char *packet, int length, unsigned int opcode) {
	vector <int> tmp; tmp.push_back(0); tmp.push_back(0); tmp.push_back(0); tmp.push_back(0);
	int row[2] = {0, 0}; // [0] = Non-Zero elements in a row  [1] = Zero elements in a row
	int lastElement = -1;
	for (int t = 0; t < 5; t++) { // Cycle through the packet five times to guarantee finding the struct
		for (int i = 0; i < length; i++) {
			bool canAdd = true;
			for (unsigned int a = 0; a < struc.size(); a++) {
				if ((struc[a][1] < i && struc[a][2] + struc[a][3] >= i && (unsigned int)struc[a][0] == opcode)) {
					canAdd = false;
				}
			}
			if (packet[i] == 0) {
				if (!canAdd) {
					lastElement = 1;
				} else {
					row[1]++;
					if (lastElement == 0) {
						row[1] = 1;
					}
					lastElement = 1;
				}
			} else {
				if (!canAdd) {
					lastElement = 1;
				} else {
					row[0]++;
					if (lastElement == 1) {
						row[0] = 1;
					}
					lastElement = 0;
				}
			}
			if (i < length-4) { /* Find floats */
				float fValue = 0.0;
				fValue = getFloat(&packet[i]);
				if ((fValue >= .01 && fValue < 15000) || (fValue <= -.01 && fValue > -15000)) {
				 	bool isVariable = true;
					for (unsigned int a = 0; a < struc.size(); a++) {
						if (struc[a][1] + struc[a][2] >= i
						 && struc[a][1] <= i
						 && struc[a][3] != 4
						 && (unsigned int)struc[a][0] == opcode) {
							isVariable = false;
						}
					}
					if (isVariable) {
						tmp[0] = (unsigned int) opcode;
						tmp[1] = i;
						tmp[2] = 4;
						tmp[3] = 3;
						row[0] = 0;
						row[1] = 1;
						struc.push_back(tmp);
					}
				}
			}
			if (lastElement == 1 || i+1 == length) {
				int sub = 0;
				if (lastElement == 1) sub = 1;
				if (row[0] == 5 && row[1] == 3) {
					tmp[0] = (unsigned int)opcode;
					tmp[1] = i-8;
					tmp[2] = 8;
					tmp[3] = 8;
					row[0] = 0;
					row[1] = 0;
					struc.push_back(tmp);
				}
				if (row[0] >= 4 && row[0] != 5) {
					bool isVariable = true;
					for (unsigned int a = 0; a < struc.size(); a++) {
						if (struc[a][1] + struc[a][2] >= i-4
						 && struc[a][1] < i-4
						 && (unsigned int)struc[a][0] == opcode) {
							isVariable = false;
						}
					}
					if (isVariable) {
						float fl = getFloat(&packet[i-4]);
						tmp[0] = (unsigned int)opcode;
						tmp[1] = i-4-sub;
						tmp[2] = 4;
						tmp[3] = 4;
						row[0] = 0;
						row[1] = 1;
						if (fl >= .01 || fl <= -.01) {
							tmp[3] = 3;
						}
						struc.push_back(tmp);
					}
				}
				if (row[0] == 2) {
					bool isVariable = true;
					for (unsigned int a = 0; a < struc.size(); a++) {
						if (struc[a][1] + struc[a][2] >= i-2
						 && struc[a][1] <= i-2
						 && (unsigned int)struc[a][0] == opcode) {
							isVariable = false;
						}
					}
					if (isVariable) {
						tmp[0] = (unsigned int) opcode;
						tmp[1] = i-2-sub;
						tmp[2] = 2;
						tmp[3] = 2;
						struc.push_back(tmp);
						row[0] = 0;
						row[1] = 1;
					}
				}
			}
		}
	}
	int foundOpcode = -1;
	for (int i = 0; i < opcodeDataExample.size() && foundOpcode == -1; i++) {
		if ((unsigned int)opcodeDataExample[i][0] == opcode) {
			foundOpcode = i;
		}
	}
	if (foundOpcode >= 0) {
		vector <int> data;
		data.push_back(opcode);
		for (int i = 0; i < length; i++) {
			data.push_back(packet[i]);
		}
		opcodeDataExample[foundOpcode] = data;
	} else {
		vector <int> data;
		data.push_back(opcode);
		for (int i = 0; i < length; i++) {
			data.push_back(packet[i]);
		}
		opcodeDataExample.push_back(data);
	}
	//for (int i = 0; i < length; i++) { printf("%.2X ", (unsigned char)packet[i]); }
	//cout << "\n";
	/*if (opcode == 0xd93bbc2e) {
		for (int i = 0; i < length; i++) {
			int itemID = 0;
			for (int a = 0; a < struc.size(); a++) {
				if ((struc[a][1] < i && struc[a][1] + struc[a][2] >= i)) {
					itemID = struc[a][3];
				}
			}
			cout << " " << itemID << " ";
		}
	}
	cout << "\n";*/
	//cout << "\n\n";*/
}
#endif
