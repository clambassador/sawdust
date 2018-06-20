#include <cassert>
#include <fstream>
#include <sstream>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/formatting.h"
#include "ib/tokenizer.h"

#include <leveldb/db.h>

using namespace std;
using namespace sawdust;

int main(int argc, char** argv) {
        Config::_()->load("sawdust.cfg");

	leveldb::DB* db;
	if (argc < 2) {
		Logger::info("usage: ./payload_grep filter list");
		return -1;
	}

	leveldb::Options options;
	options.create_if_missing = false;
	leveldb::Status status = leveldb::DB::Open(
		options, Config::_()->gets("packetdb"), &db);
	if (!status.ok()) {
		Logger::error("error opening %", Config::_()->gets("packetdb"));
		Logger::error("result %", status.ToString());
		return -1;
	}
	leveldb::ReadOptions read_options;
	auto *x = db->NewIterator(read_options);
	Packet::_db = db;

//	if (argc == 3) {
//		x->Seek(argv[2]);
//		x->Next();
//	} else {
		x->SeekToFirst();
//	}
	while (x->Valid()) {
		if (x->key().ToString().length() == 40) {
			bool found = true;
			for (int i = 1; i < argc; ++i) {
				if (x->value().ToString().find(argv[i]) == string::npos) {
					found = false;
					break;
				}
			}
			if (found) {
				Packet p(x->key().ToString());
				cout << x->key().ToString() << endl
				     << p._dns << ":" << p._port
				     << endl
				     << p._app << ',' << p._time << endl;
				vector<string> tokens;
				Tokenizer::split_with_empty(p._data, "\r\n", &tokens);
				stringstream ss;
				for (auto &x : tokens) {
					if (x.empty()) break;
					ss << x << endl;
				}
				cout << ss.str() << endl << endl;
			}
		}
		x->Next();
	}
	delete x;
	delete db;
	return 0;
}
