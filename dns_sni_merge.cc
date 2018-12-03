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
	if (argc < 4) {
		Logger::error("usage: dns_sni_merge csv col1 col2");
		return -1;
	}
	CSVTable<true> table_in;
	table_in.load(argv[1]);
	int col1 = atoi(argv[2]);
	int col2 = atoi(argv[3]);
	vector<string> dns = table_in.project(col1);
	vector<string> sni = table_in.project(col2);
	for (size_t i = 0; i < dns.size(); ++i) {
		if (dns[i].empty() && !sni[i].empty()) {
			dns[i] = sni[i];
		}
	}
	table_in.project(col1, dns);
	string prefix;
	Tokenizer::extract("%.csv", argv[1], &prefix);
	table_in.save(Logger::stringify("%-dns.csv", prefix));
}
