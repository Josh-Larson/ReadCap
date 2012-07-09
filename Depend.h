#ifndef DEPEND_H
#define DEPEND_H
#include <string>
#include <vector>
#include <cstdlib>
#include <time.h>
#include <sstream>
#include <cmath>
using namespace std;

static int SoeOpcodes[][2] = {{1, 0}, {2, 0}, {9, 0}};
static string SoeStrOpcodes[] = {"SessionRequest", "SessionResponse", "Data Packet", ""};
static int SwgOpcodes[][2] = {{0xAC797F87, 0}, {0x56138D1E, 0}, {0x79C618BD, 0}, {0xD5B1648A, 0}, {0xD93BBC2E, 0}};
static string SwgStrOpcodes[] = 
{"SurveyMessage",
 "AddItemMessage",
 "ResourceHarvesterActivatePageMessage",
 "ResourceListForSurveyMessage",
 "ServerTimeMessage",
 ""};

static int FilterOpcodesAllow[] = {0xD93BBC2E, 0x56138D1E, -1};
static int FilterOpcodesDeny[]  = {-1};
static string filter            = ""; // all - Allow All  |  deny - Deny All (Excluding the filter)
static vector <vector <int> > foundInPacket;
static vector <vector <int> > opcodeDataExample;
static vector <vector <int> > struc; // [0] = Opcode  |  [1] = Offset  |  [2] = Number of bytes
static bool writeTxt = true;
static bool asciiValues = true;
static bool output = true;

string itoa(unsigned int i) {
	stringstream STREAM;
	STREAM << i;
	return STREAM.str();
}

void help(string command) {
	cout << "Help\n";
	cout << command << " -f file.cap\n";
}

float getFloat(char *memory) {
	float ret = 0.0;
	ret = *((float *)memory);
	return ret;
}

unsigned short getShort(char *memory) {
	unsigned short ret = ((unsigned char)memory[1] << 8) | ((unsigned char)memory[0]);
	return ret;
}

/*
	Gets the packet starting at the opcode, and determines if it is of ObjController type
 */
bool isObjController(char *packet, string type) {
	unsigned int objType =((int)type[0] << 24) | ((int)type[1] << 16) | ((int)type[2] << 8) | ((int)type[3]);
	if (*((unsigned int *)&packet[12]) == objType) {
		return true;
	}
	return false;
}

/*
	Checks if the number is prime
*/
bool isPrime(unsigned int n) {
	if (n % 2 == 0) return false;
	if (n % 3 == 0) return false;
	if (n % 5 == 0) return false;
	if (n % 7 == 0) return false;
	for (int i = 9; i < n/2; i+=2) {
		if (n % i == 0) return false;
	}
	return true;
}


#endif
