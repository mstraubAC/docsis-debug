#include <vector>
#include <iostream>
#include <iomanip>
#include <string>
#include <exception>
#include <stdexcept>
#include <boost/iostreams/device/mapped_file.hpp>
#include <cstdint>
#include <sys/stat.h>
#include <arpa/inet.h>

using namespace std;

const uint16_t docsisPID = 0x1ffe;

struct packet {
	typedef std::vector<uint8_t> PDU;

	virtual PDU& getPDU() { return fPdu; }
	virtual const PDU& getPDU() const { return fPdu; }
	virtual ~packet() {};

	PDU fPdu;
	PDU fRawPacket;
};

std::ostream& operator<<(std::ostream& os, const packet::PDU& pdu) {
	ios::fmtflags flags(os.flags());

	for (size_t i = 0; i < pdu.size(); ++i) {
		os << hex << setfill('0') << setw(2) << uint32_t(pdu[i]) << " ";
		if (i % 16 == 15) os << endl;
	}
	os << endl;

	os.flags(flags);
	return os;
}

#define MPEG_TS_FRAME_LEN 188
#define MPEG_TS_HEADER_LEN 4
#define MPEG_TS_PDU_LEN MPEG_TS_FRAME_LEN-MPEG_TS_HEADER_LEN
#define DOCSIS_STUFFBYTE 0xff
struct mpegTransportStream : public packet {
	enum e_tsc { tsc_not = 0, tsc_even = 0x80, tsc_odd = 0xc0, tsc_reserved = 0x40 };
	enum e_adapt { adapt_payload = 1, adapt_only = 2, adapt_mixed = 3, adapt_reserved = 0x00 };

	bool tei; // true if a demodulator can't correct errors from FEC data |--> packet is corrupt
	bool pusi; // Payload Unit Start Indicator true if a PES, PSI or DVB-MIP packet begins immediately following the header
	bool priority; // true if current packet has higher priority than other packets with the same PID
	uint16_t pid; // Packet identifier, describing the payload data
	int8_t tsc; // Transport Scrambling Control (0x00 --> not scrambled)
	int8_t adapt; // 
	uint8_t seqNo; // sequence number of payload packets 4 bit within each stream except PID 8191. incremented per PID only wehan a payload flag is set

	mpegTransportStream(const packet::PDU& in) :
		tei(false), pusi(false), priority(false),
		pid(0), tsc(0), adapt(0), seqNo(0)
	{
		packet::fRawPacket = in;

		// parse header
		parseHeader();

		// seperate pdu
		fPdu.resize(in.size()-MPEG_TS_HEADER_LEN);
		for (size_t i = 0; i < fPdu.size(); ++i) {
			fPdu[i] = fRawPacket[i+MPEG_TS_HEADER_LEN];
		}
	};

	void parseHeader() {
		uint32_t a = ntohl(*(const uint32_t*)(packet::fRawPacket.data()));

		if ((a & 0xff000000) >> 24 != 0x47) {
			cerr << "parseTsHeader: ERROR wrong sync byte value" << endl;
			throw invalid_argument("parseTsHeader: ERROR wrong sync byte value");
		}

		tei      = (a & 0x800000) > 0;
		pusi     = (a & 0x400000) > 0;
		priority = (a & 0x200000) > 0;
		pid      = (a & 0x1fff00) >> 8;
		tsc      = (a & 0x0000c0) >> 4;
		adapt    = (a & 0x000030) >> 4;
		seqNo    = (a & 0x00000f);
		if(false) {
			cout << "FULL:     " << hex << a << dec << endl;
			cout << "TEI:      " << (tei ? "TRUE" : "FALSE") << endl;
			cout << "PUSI:     " << (pusi ? "TRUE" : "FALSE") << endl;
			cout << "PRIORITY: " << (priority ? "TRUE": "FALSE") << endl;
			cout << "PID:      " << hex << pid << dec << endl;
			cout << "TSC:      " << hex << uint32_t(tsc) << dec << endl;
			cout << "Adaption: " << hex << uint32_t(adapt) << dec << endl;
			cout << "SeqNo:    " << hex << uint32_t(seqNo) << dec << endl;
		}
	}
};

#define DOCSIS_SYNC 1 /* timing syncrhonization */
#define DOCSIS_MAP 3 /* upstream bandwidth allocation */
#define DOCSIS_RNG_REQ 4 /* ranging request */
#define DOCSIS_RNG_RSP 5 /* ranging response */
#define DOCSIS_REG_REQ 6 /* registration request */
#define DOCSIS_REG_RSP 7 /* registration response */
#define DOCSIS_UCC_REQ 8 /* upstream channel change request */
#define DOCSIS_UCC_RSP 9 /* upstream channel change response */
//
//
#define DOCSIS_BPKM_REQ 12 /* privacy key management request (DOCSIS SEC v3.0) */
#define DOCSIS_BPKM_RSP 13 /* privacy key management response (DOCSIS SEC v3.0) */
#define DOCSIS_REG_ACK 14 /* registration acknowledge */
#define DOCSIS_DSA_REQ 15 /* dynamic service addition request */
#define DOCSIS_DSA_RSP 16 /* dynamic service addition reponses */
#define DOCSIS_DSA_ACK 17 /* dynamic service addition acknowledge */
#define DOCSIS_DSC_REQ 18 /* dynamic service change request */
#define DOCSIS_DSC_RSP 19 /* dynamic service change response */
#define DOCSIS_DSC_ACK 20 /* dynamic service change acknowledge */
#define DOCSIS_DSD_REQ 21 /* dynamic service deletion request */
#define DOCSIS_DSD_RSP 22 /* dynamic service deletion response */
#define DOCSIS_DSD_ACK 23 /* dynamic service delection acknowledge */
#define DOCSIS_DCC_REQ 23 /* dynamic channel change request */
#define DOCSIS_DCC_RSP 24 /* dynamic channel change response */
#define DOCSIS_DCC_ACK 25 /* dynamic channel change acknowledge */
#define DOCSIS_DCI_REQ 26 /* device class identification request */
#define DOCSIS_DCI_RSP 27 /* device class identification response */
#define DOCSIS_UP_DIS 28 /* upstream transmitter disable */
//
#define DOCSIS_INIT_RNG_REQ 30 /* initial ranging request */
#define DOCSIS_TST_REQ 31 /* Test request message */
#define DOCSIS_DCD 32 /* downstream channel descriptor */
#define DOCSIS_MDD 33 /* MAC Domain Descriptor */
#define DOCSIS_B_INIT_RNG_REQ 34 /* Bonded initial Ranging Request */
//
#define DOCSIS_DBC_REQ 36 /* Dynamic Bonding Change Request */
#define DOCSIS_DBC_RSP 37 /* Dynamic Bonding Change Resposne */
#define DOCSIS_DBC_ACK 38 /* Dynamic Bonding Change Acknowledge */
#define DOCSIS_DPV_REQ 39 /* DOCSIS Path Verify Request */
#define DOCSIS_DPV_RSP 40 /* DOCSIS Path Verify Response */
#define DOCSIS_CM_STATUS 41 /* Status Report */
#define DOCSIS_CM_CTRL_REQ 42 /* CM Control */
#define DOCSIS_CM_CTRL_RSP 43 /* CM Control Response */
#define DOCSIS_REG_REQ_MP 44 /* Multipart Registration Request */
#define DOCSIS_REG_RSP_MP 45 /* Multipart Registration Response */
#define DOCSIS_EM_REQ 46 /* Energy Management Request */
#define DOCSIS_EM_RSP 47 /* Energy Management Response */
#define DOCSIS_CM_STATUS_ACK 48 /* Status Report Acknowledge */
struct docsisPacket : public packet {
	/**
	 *  identifies the type of MAC header
	 *
	 */
	typedef union {
		uint8_t raw;
		struct {
			// 1 indicates presence of EHDR
			uint8_t ehdr_on:1;
			/*
			 *  parameter bits, use depents on type value
			 *  All 0 other values are reserved for future use
			 */
			uint8_t parm:5;
			/*
			 * 00 Data PDU packet
			 * 01 ATM PDU packet
			 * 10 Isolation Packet PDU MAC Header
			 * 11 MAC-Specific Header
			 */
			uint8_t type:2;
		} decoded;
	} fc_t;
	fc_t fc;
	/// added parameters based on the type of MAC header
	uint8_t mac_parm;
	/**
	 * length of the MAC package as calculated from the length
	 * of the extended header (if present) and the number of bytes
	 * following the HCS field. If the MAC packet is a request packet
	 * (see "MAC-Specific Messages"), this field contains a SID value.
	 * The SID is a unique value assigned to the CM during the initialization
	 * and registration process.
	 */
	uint16_t len_sid;
	/**
	 * Contains supplemental information pertinent to the handling of the MAC packet
	 * length of 0..240 bytes
	 */
	packet::PDU ehdr;
	/**
	 * Contains the Cyclic Redundancy Chech (CRC), to protect the preceding fields,
	 * and us used to indicate one or more bit errors in the MAC header
	 */
	uint16_t hcs;

	// Destination Address
	uint64_t dst_addr; // its actual a 48 bit MAC address

	// Source Address
	uint64_t src_addr; // its actual a 48 bit MAC address

	uint16_t data_len_type;


	void parseDataPdu() {
		if (fPdu.size() < 13) {
			throw out_of_range("docsisPacket::parseDataPdu(): the extracted PDU is smaller than the header!");
		}
		dst_addr = 0 |
				(uint64_t(fPdu[0]) << 40) |
				(uint64_t(fPdu[1]) << 32) |
				(uint64_t(fPdu[2]) << 24) |
				(uint64_t(fPdu[3]) << 16) |
				(uint64_t(fPdu[4]) << 8) |
				uint64_t(fPdu[5]);
		src_addr = 0 |
				(uint64_t(fPdu[6]) << 40) |
				(uint64_t(fPdu[7]) << 32) |
				(uint64_t(fPdu[8]) << 24) |
				(uint64_t(fPdu[9]) << 16) |
				(uint64_t(fPdu[10]) << 8) |
				uint64_t(fPdu[11]);

		data_len_type = ntohs(*(const uint16_t*)(fPdu.data() + 12));
		cout << "src=0x" << hex << src_addr << " | dst=0x" << dst_addr << " | Len/Type=" << dec << data_len_type << " (0x" << hex << data_len_type << ")" << endl;
	}

	void parseMacMgmtPdu() {
		if (fPdu.size() < 13) {
			throw out_of_range("docsisPacket::parseMacMgmtPdu(): the extracted PDU is smaller than the header!");
		}
		dst_addr = 0 |
				(uint64_t(fPdu[0]) << 40) |
				(uint64_t(fPdu[1]) << 32) |
				(uint64_t(fPdu[2]) << 24) |
				(uint64_t(fPdu[3]) << 16) |
				(uint64_t(fPdu[4]) << 8) |
				uint64_t(fPdu[5]);
		src_addr = 0 |
				(uint64_t(fPdu[6]) << 40) |
				(uint64_t(fPdu[7]) << 32) |
				(uint64_t(fPdu[8]) << 24) |
				(uint64_t(fPdu[9]) << 16) |
				(uint64_t(fPdu[10]) << 8) |
				uint64_t(fPdu[11]);

		data_len_type = ntohs(*(const uint16_t*)(fPdu.data() + 12));

		uint8_t dsap = *(fPdu.data()+14);
		uint8_t ssap = *(fPdu.data()+15);
		uint8_t control = *(fPdu.data()+16);
		uint8_t version = *(fPdu.data()+17);
		uint8_t type = *(fPdu.data()+18);
		uint8_t rsvd = *(fPdu.data()+19);

		if (dsap != 0) {
			throw out_of_range("docsisPacket::parseMacMgmtPdu(): DSAP value of non zero violates specification");
		}

		if ( !((type == DOCSIS_RNG_REQ) || (type == DOCSIS_INIT_RNG_REQ) || (type == DOCSIS_B_INIT_RNG_REQ) ) && (ssap != 0)) {
			throw out_of_range("docsisPacket::parseMacMgmtPdu(): SSAP value of non zero violates specification");
		}


		cout << "MAC MGMT PDU: src=0x" << hex << src_addr << " | dst=0x" << dst_addr << " | Len/Type=" << dec << data_len_type << " (0x" << hex << data_len_type << "): " <<
				"DSAP=0x" << hex << uint32_t(dsap) << ", " <<
				"SSAP=0x" << uint32_t(ssap) << ", " <<
				"control=0x" << uint32_t(control) << ", " <<
				"version=0x" << uint32_t(version) << ", " <<
				"type=0x" << uint32_t(type) << ", " <<
				"rsvd=0x" << uint32_t(rsvd) << ", " <<
				endl;
	}

	docsisPacket(const packet::PDU& in)
	{
		if (in.size() < 6) throw out_of_range("docsisPacket(..): The provided packet is too short");
		fRawPacket = in;

		size_t ptr = 0;
		size_t lenHeader = 0;
		fc.raw = fRawPacket.data()[ptr++]; lenHeader++;
		mac_parm = fRawPacket.data()[ptr++]; lenHeader++;

		len_sid = ntohs(*(const uint16_t*)(fRawPacket.data() + ptr));
		ptr += 2; lenHeader += 2;

		// handle extended header if there
		if (fc.decoded.ehdr_on == 1) {
//			cout << "Extended Header is here" << endl;
			ehdr.resize(mac_parm);
			lenHeader += mac_parm;
			for (size_t i = 0; i < mac_parm; ++i) {
				ehdr[i] = fRawPacket.data()[ptr++];
			}
		}

		// get header check sequence
		hcs = ntohs(*(const uint16_t*)(fRawPacket.data() + ptr));
		ptr += 2; lenHeader += 2;

		// get PDU
		if (lenHeader > in.size()) {
			throw out_of_range("docsisPacket: Header longer than packet!");
		}
		size_t lenPdu = in.size() - lenHeader;
		fPdu.resize(lenPdu);
//		cout << "Total Header Length: " << lenHeader << endl <<
//				"Pdu Length:         " << lenPdu << endl << flush;
		for (size_t i = 0; i < lenPdu; ++i) {
			packet::fPdu[i] = fRawPacket[ptr++];
		}

		switch (fc.decoded.type) {
			case 0:
//				cout << "DATA PDU" << endl;
//				parseDataPdu();
				break;
			case 1:
//				cout << "ATM PDU" << endl;
				break;
			case 2:
//				cout << "Isolation Packet PDU MAC Header" << endl;
//				parseDataPdu();
				break;
			case 3:
//				cout << "MAC Specific Header";
				parseMacMgmtPdu();
				break;
		}
	}
};

int main(int argc, char** argv) {
	cout << "DOCSIS transport stream parser" << endl;

	const string fileName = "../docsis-debug/data/test.m2ts";
//	if (stat(fileName.c_str(), &statBuf) != 0) {
//		return 1;
//	}

	boost::iostreams::mapped_file_source fFile;
	fFile.close();

	// open file
	fFile.open(fileName);
	cout << "File size=" << fFile.size()/1024/1024 << "MiB" << endl;

	// search for sync byte
	packet::PDU rawDocsis;
	
	size_t nPackets = 0;	
	for (size_t i = 0; i < fFile.size(); ) {
		uint32_t a = ntohl(*(const uint32_t*)(fFile.data() + i));
		a = (a & 0xff000000) >> 24;
		if (a == 0x47) {
			packet::PDU rawData(MPEG_TS_FRAME_LEN);
			for (size_t j = 0; j < MPEG_TS_FRAME_LEN; ++j) rawData[j] = *(fFile.data() + i + j);

			auto ts = mpegTransportStream(rawData);
			
			if (ts.pid == docsisPID && ts.pusi) {
//				cout << endl << "=================================" << endl;
//				cout << "DOCSIS start telegram found (" << uint32_t(ts.seqNo) << " seq packets)" << endl;

				// check which part still belongs to the last started docsis packet
				const size_t docsisStart = ts.getPDU()[0];
				if (docsisStart > 0) {
//					cout << "Completing last DOCSIS Frame" << endl;
					for (size_t j = 0; j < docsisStart; ++j) rawDocsis.push_back(ts.getPDU()[j+1]);
				}

				// do something with the last full docsis packet
				if (rawDocsis.size() > 0) {
//					cout << rawDocsis;

					try {
						docsisPacket dp(rawDocsis);
					}
					catch (const std::exception& e) {
						cout << "Exception during DOCSIS package parsin: " << e.what() << endl;
					}
				}

				// clear up the raw Docsis buffer
				rawDocsis.clear();

				// add this data gram
				bool stuffTest = true;
				for (size_t j = docsisStart; j < MPEG_TS_PDU_LEN-1; ++j) {
					// ignore stuff bytes
					if (stuffTest) {
						if (ts.getPDU()[j+1] == DOCSIS_STUFFBYTE) continue;
						stuffTest = false;
					}
					rawDocsis.push_back(ts.getPDU()[j+1]);
				}
			}

			// done do pointer arithmetics and bookkeeping;
//			if (nPackets > 30) break;
			i += MPEG_TS_FRAME_LEN;

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
