#include "PcapRead.h"

const int PcapReader::CompBuf = 800;

PcapReader::PcapReader() {
	_file = "";
	_packetNum = 0;
	_ready = false;
	_length = 0;
	_closed = true;
	memoryFreed = -1;
	mCrcSeed = 0;
}

PcapReader::PcapReader(string file, bool fastRead) {
	_file = file;
	_packetNum = 0;
	_handler = pcap_open_offline(file.c_str(), errbuf);
	if (_handler) {
		_ready = true;
	} else {
		_ready = false;
	}
	_length = 0;
	_closed = false;
	_fastRead = fastRead;
	memoryFreed = -1;
	mCrcSeed = 0;
}

PcapReader::~PcapReader() {
	if (_closed == false) {
		_closed = true;
		_ready = false;
		pcap_close(_handler);
	}
}

void PcapReader::close() {
	if (_closed == false) {
		_closed = true;
		_ready = false;
		pcap_close(_handler);
	}
}

char *PcapReader::GetNext() {
	if (_ready) {
		struct pcap_pkthdr header;
		const u_char *buffer = pcap_next(_handler, &header);
		if (buffer == NULL) {
			_ready = false;
			_length = 0;
			return NULL;
		} else {
			_packetNum++;
			if (buffer[1] != 0x09  && buffer[0] != 0x00 && _fastRead) {
				_length = -1;
				return NULL;
			} else {
				_length = header.len - 42;
				char *packet = (char *)buffer;
				packet += 42;
				Decode(packet, (unsigned short &)_length);
				return packetData;
			}
		}
	} else {
		_length = 0;
		return NULL;
	}
}

bool PcapReader::end() {
	return !_ready; // Inverse of ready - are we done
}

int PcapReader::packets() {
	return _packetNum;
}

int PcapReader::length() {
	return _length;
}

void PcapReader::SetCRC(uint32 CRCSeed) {
	mCrcSeed = CRCSeed;
}

void PcapReader::Decrypt(char *pData,unsigned short nLength,unsigned int nCrcSeed)
{
	unsigned int *Data;
	if(pData[0] == 0x00) {
		nLength-=4;
		Data = (unsigned int*)(pData+2);
	} else {
		nLength-=3;
		Data = (unsigned int*)(pData+1);
	}
	short block_count = (nLength / 4);
	short byte_count = (nLength % 4);
	unsigned int itemp;
	for (short count = 0;count<block_count;count++) {
		itemp = *Data;
		*Data ^= nCrcSeed;
		nCrcSeed = itemp;
		Data++;
	}
	pData = (char*)Data;
	for (short count = 0;count<byte_count;count++) {
		*pData ^= nCrcSeed;
		pData++;
	}
}

char *PcapReader::Decompress(char *pData, unsigned short &nLength) {
	unsigned short offset;
	if(pData[0] == 0x00)
	 offset = 2;
	else
	 offset = 1;
	z_stream packet;
	char output[CompBuf];
	unsigned short newLength=0;
	packet.zalloc = Z_NULL;
	packet.zfree = Z_NULL;
	packet.opaque = Z_NULL;
	packet.avail_in = 0;
	packet.next_in = Z_NULL;
	inflateInit(&packet);
	packet.next_in = (Bytef*)(pData+offset);
	packet.avail_in = (nLength - offset -3);
	packet.next_out = (Bytef*)output;
	packet.avail_out = CompBuf;
	inflate(&packet,Z_FINISH);
	newLength = packet.total_out;
	inflateEnd(&packet);
	char *Decomp_pData  = new char [newLength + offset + 3];
	memoryFreed = 0;
	char *begDecomp_pData = Decomp_pData;
	*Decomp_pData = pData[0];
	Decomp_pData++;
	if(offset == 2) {
	 *Decomp_pData = pData[1];
	 Decomp_pData++;
	}
	for(short x=0;x<newLength;x++) {
		*Decomp_pData = output[x];
		Decomp_pData++;
	}
	*Decomp_pData = 0x01;
	Decomp_pData++;
	pData += (nLength-2);
	Decomp_pData = begDecomp_pData;
	*(unsigned short*)Decomp_pData = *(unsigned short*)pData;
	nLength = newLength + offset + 3;
	return Decomp_pData;
}

unsigned int PcapReader::GenerateCrc(char* pData,unsigned short nLength,unsigned int nCrcSeed) {
	unsigned int nCrc = g_nCrcTable[(~nCrcSeed) & 0xFF];
	nCrc ^= 0x00FFFFFF;
	unsigned int nIndex = (nCrcSeed >> 8) ^ nCrc;
	nCrc = (nCrc >> 8) & 0x00FFFFFF;
	nCrc ^= g_nCrcTable[nIndex & 0xFF];
	nIndex = (nCrcSeed >> 16) ^ nCrc;
	nCrc = (nCrc >> 8) & 0x00FFFFFF;
	nCrc ^= g_nCrcTable[nIndex & 0xFF];
	nIndex = (nCrcSeed >> 24) ^ nCrc;
	nCrc = (nCrc >> 8) &0x00FFFFFF;
	nCrc ^= g_nCrcTable[nIndex & 0xFF];

	for( short i = 0; i < nLength; i++ )
	{
		nIndex = (pData[i]) ^ nCrc;
		nCrc = (nCrc >> 8) & 0x00FFFFFF;
		nCrc ^= g_nCrcTable[nIndex & 0xFF];
	}
	return ~nCrc;
}


bool PcapReader::CrcTest(char *pData, unsigned short nLength,unsigned int nCrcSeed, short nCrcLength) {
	bool crctest = true;
	if(nCrcLength > 0)
	{
		unsigned int p_crc = GenerateCrc(pData,(nLength-nCrcLength),nCrcSeed);
		unsigned int  crc = 0;
		unsigned int mask = 0;
		unsigned int pullbyte = 0;
		pData = pData + (nLength-nCrcLength);
		for( short i = 0; i < nCrcLength; i++ )
		{
			pullbyte = (unsigned char)pData[i];
			crc |=(pullbyte << (((nCrcLength - 1) - i) * 8));
			mask <<= 8;
			mask |= 0xFF;
		}
		p_crc &= mask;
		if(p_crc != crc)
			crctest = false;
	}
	return crctest;
}


char *PcapReader::Decode(char *pData, unsigned short &nLength) {
	int newlyFreed = 0;
	if (packetData != NULL && memoryFreed == 0) {
		delete[] packetData;
		packetData = NULL;
		memoryFreed = 1;
		newlyFreed = 1;
	}
	bool comp = false;
	if (!_fastRead) {
		switch(pData[1]) {
			case 3:
				//"Multi-SOE Packet: "
				if (CrcTest(pData,nLength,mCrcSeed)) {
					Decrypt(pData,nLength,mCrcSeed);
				}
			
				if (pData[2] == 'x') {
					comp = true;
					pData = Decompress(pData,nLength);
				}
				break;
			case 9:
				//"Data Channel: "
				Decrypt(pData,nLength,mCrcSeed);
				if (pData[2] == 'x') {
					comp = true;
					pData = Decompress(pData,nLength);
					//sLog.logDebug("DataA: %X%X: %X", pData[0], pData[1], pData);
				}
				break;
			case 13:
				//"Fragmented: "
				Decrypt(pData,nLength,mCrcSeed);
				if (pData[2] == 'x') {
					comp = true;
					pData = Decompress(pData,nLength);
				}
				//sLog.logDebug("Fragment: %X%X: %X", pData[0], pData[1], pData);
				break;
			case 6:
				//"SOE Ping: "
				Decrypt(pData,nLength,mCrcSeed);
				break;
			case 7:
				//"Client Net-Status: "
				Decrypt(pData,nLength,mCrcSeed);
				if (pData[2] == 'x') {
					comp = true;
					pData = Decompress(pData,nLength);
				}
				break;
			case 21:
				//"Acknowledge: "
				Decrypt(pData,nLength,mCrcSeed);
				break;
			case 5:
				//"Disconnect: "
				Decrypt(pData,nLength,mCrcSeed);
				break;

			case 17:
				//"Future Packet: "
				Decrypt(pData,nLength,mCrcSeed);
				break;
			default:
				// I dunno
				break;
		}
		packetData = pData;
	} else {
		if (mCrcSeed & 0x0000FFFF != *((unsigned short *)&pData[nLength-2])) { /* Invalid CRC Case */
			nLength = -1;
			packetData = NULL;
		} else {
			if (pData[1] == 9) { /* Data Packet */
				Decrypt(pData,nLength,mCrcSeed);
				if (pData[2] == 'x') {
					comp = true;
					pData = Decompress(pData,nLength);
				}
				packetData = pData;
			} else { /* Other - Don't care about */
				nLength = -1;
				packetData = NULL;
			}
		}
	}
	return pData;
}

