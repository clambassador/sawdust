#include <cassert>
#include <fstream>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/formatting.h"
#include "ib/tokenizer.h"

#include <leveldb/db.h>

using namespace std;

int main(int argc, char** argv) {
        Config::_()->load("sawdust.cfg");

	leveldb::DB* db;
	if (argc < 2) {
		Logger::info("usage: ./packet hash [highlight pos]");
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


	string data;
	db->Get(leveldb::ReadOptions(), argv[1], &data);
	delete db;
	if (data.empty()) {
		Logger::info("no packet found for %", argv[1]);
		return -1;
	}
	if (argc == 2) {
		cout << data << endl;
	} else {
		int pos = atoi(argv[2]);
		assert(pos >= 0 && pos < data.length());
		cout << data.substr(0, pos);
		cout << "\033[1;31m" << data[pos] << "\033[0m" <<
		    data.substr(pos + 1);
	}
	return 0;
}
