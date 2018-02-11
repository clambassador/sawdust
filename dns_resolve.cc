#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <unistd.h>

#include "bigdata_processor.h"
#include "i_processor.h"
#include "id_search_processor.h"
#include "keymap_processor.h"
#include "mood.h"
#include "mood_processor.h"
#include "null_processor.h"
#include "packet_source_processor.h"
#include "save_processor.h"
#include "packet.h"

#include "ib/csv_table.h"
#include "ib/logger.h"
#include "ib/tokenizer.h"

using namespace std;
using namespace ib;
using namespace sawdust;

int main(int argc, char** argv) {
	if (argc < 2) {
		Logger::error("usage: packetprocessor packetfile");
		return -1;
	}
	CSVTable table_in;
	map<string, string> corrections;
	CSVTable::load_map(argv[2], &corrections);
	table_in.load(argv[1]);
	const vector<string>& ip = table_in.project(5);
	vector<string> dns = table_in.project(3);
	for (size_t i = 0; i < dns.size(); ++i) {
		if (dns[i].empty() && corrections.count(ip[i])) {
			dns[i] = corrections[ip[i]];
		}
	}
	table_in.project(3, dns);
	string prefix;
	Tokenizer::extract("%.csv", argv[1], &prefix);
	table_in.save(Logger::stringify("%-dns.csv", prefix));

}
