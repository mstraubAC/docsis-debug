#include <iostream>
#include <iomanip>
#include <string>
#include <exception>
#include <stdexcept>
#include <boost/iostreams/device/mapped_file.hpp>
#include <sys/stat.h>
#include <arpa/inet.h>

using namespace std;

const uint16_t docsisPID = 0x1ffe;

struct tsHeader {
	enum e_tsc { tsc_not = 0, tsc_even = 0x80, tsc_odd = 0xc0, tsc_reserved = 0x40 };
	enum e_adapt { adapt_payload = 1, adapt_only = 2, adapt_mixed = 3, adapt_reserved = 0x00 };

	bool tei; // true if a demodulator can't correct errors from FEC data |--> packet is corrupt
	bool pusi; // Payload Unit Start Indicator true if a PES, PSI or DVB-MIP packet begins immediately following the header
	bool priority; // true if current packet has higher priority than other packets with the same PID
	uint16_t pid; // Packet identifier, describing the payload data
	int8_t tsc; // Transport Scrambling Control (0x00 --> not scrambled)
	int8_t adapt; // 
	uint8_t seqNo; // sequence number of payload packets 4 bit within each stream except PID 8191. incremented per PID only wehan a payload flag is set

};

tsHeader parseTsHeader(const char* ptr) {
	tsHeader result;
	uint32_t a = ntohl(*(const uint32_t*)(ptr));

	if ((a & 0xff000000) >> 24 != 0x47) {
		cerr << "parseTsHeader: ERROR wrong sync byte value" << endl;
		throw invalid_argument("parseTsHeader: ERROR wrong sync byte value");
	}

	result.tei      = (a & 0x800000) > 0;
	result.pusi     = (a & 0x400000) > 0;
	result.priority = (a & 0x200000) > 0;
	result.pid      = (a & 0x1fff00) >> 8;
	result.tsc      = (a & 0x0000c0) >> 4;
	result.adapt    = (a & 0x000030) >> 4;
	result.seqNo    = (a & 0x00000f);
	if(false) {
		cout << "FULL:     " << hex << a << dec << endl;
		cout << "TEI:      " << (result.tei ? "TRUE" : "FALSE") << endl;
		cout << "PUSI:     " << (result.pusi ? "TRUE" : "FALSE") << endl;
		cout << "PRIORITY: " << (result.priority ? "TRUE": "FALSE") << endl;
		cout << "PID:      " << hex << result.pid << dec << endl;
		cout << "TSC:      " << hex << uint32_t(result.tsc) << dec << endl;
		cout << "Adaption: " << hex << uint32_t(result.adapt) << dec << endl;
		cout << "SeqNo:    " << hex << uint32_t(result.seqNo) << dec << endl;
	}

	return result;
}

int main(int argc, char** argv) {
	cout << "DOCSIS transport stream parser" << endl;

	const size_t frameSize = 188;
	const string fileName = "../data/test.m2ts";

	struct stat statBuf;
	if (stat(fileName.c_str(), &statBuf) != 0) {
		return 1;
	}

	boost::iostreams::mapped_file_source fFile;
	fFile.close();

	// open file
	fFile.open(fileName);
	cout << "File size=" << fFile.size()/1024/1024 << "MiB" << endl;

	// search for sync byte
	size_t nPackets = 0;	
	for (size_t i = 0; i < fFile.size(); ) {
		uint32_t a = ntohl(*(const uint32_t*)(fFile.data() + i));
		a = (a & 0xff000000) >> 24;
		if (a == 0x47) {
			auto header = parseTsHeader(fFile.data() + i);
			
			if (header.pid == docsisPID && header.pusi) {
				cout << endl << "=================================" << endl;
				cout << "DOCSIS start telegram found (" << uint32_t(header.seqNo) << " seq packets)" << endl;

			}

			// done do pointer arithmetics and bookkeeping;
			if (nPackets > 20) break;
			i += frameSize;
			nPackets++;
			continue;
		}
		else {
			i += 1;
		}
	}

	// done
	fFile.close();
	return 0;
}
