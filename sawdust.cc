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
#include "null_processor.h"
#include "save_processor.h"
#include "packet.h"

#include "ib/fileutil.h"
#include "ib/logger.h"
#include "ib/tokenizer.h"

using namespace std;
using namespace ib;
using namespace sawdust;

int main(int argc, char** argv) {
	Config::_()->load("sawdust.cfg");
	string devfile = "";
	if (argc > 3) devfile = argv[2];
	map<string, string> processor_description;
	map<string, unique_ptr<IProcessor>> processors;
	processors["keymap"].reset(new KeymapProcessor());
	processors["bigdata"].reset(new BigdataProcessor());
	processors["id_search"].reset(new IDSearchProcessor(devfile));
	processors["null"].reset(new NullProcessor());
	processors["save"].reset(new SaveProcessor());

	if (argc < 5) {
		Logger::error("usage: packetprocessor filename device hwid processor args");
		Logger::error("");
		Logger::error("processors: %", processors);
		return -1;
	}
	if (!processors.count(argv[4])) {
		Logger::error("No processor %", argv[4]);
		Logger::error("");
		Logger::error("processors: %", processors);
		return -1;
	}
	IProcessor *cur = processors[argv[4]].get();

	int last = 0;
	for (int i = 0; i < strlen(argv[1]); ++i) {
		if (argv[1][i] == '/') last = i + 1;
	}
	string filename = argv[1] + last;
	string app, version, device, time;
	device = argv[3];
	if (Tokenizer::extract("%-%-%.log", filename, &app, &version, &time) != 3) {
		Tokenizer::extract("%-%.log", filename, &app, &version);
	}

	cur->init(app, version, device, time, argc - 5, argv + 5);

	string message, post, working;
	set<string> seen;
	string header = "Haystack.Flow: Outbound connection contents for ";
	string footer = "Haystack.Flow: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";
	bool saved = false;
	string key = app + "," + version + "," + time;
	string database = Config::_()->gets("packet_database")
	                  + "/" + key;

	ifstream fin(database);
	if (SaveProcessor::check(app, version, time)) {
		vector<string> packets;
		Fileutil::read_file(SaveProcessor::get_database(app, version,
								time),
				    &packets);
		assert(packets.size());
		assert(packets.back() == "---");
		packets.pop_back();
		for (auto &x : packets) {
			Packet packet(x);
			if (packet.valid() && packet._from == app) {
				cur->process(&packet);
			}
		}
	} else {
		string data;
		Fileutil::read_file(argv[1], &data);
		while (true) {
			int tid = 0;
			string tmp;
			int ret = Tokenizer::extract("% I " + header + "%",
					  	     data, &tmp, &post);
			if (ret < 2) break;
			Tokenizer::last_token(tmp, " ", &tid);
			ret = Tokenizer::extract(
				"%" + Logger::stringify("%", tid) + " I " + footer + "%",
						 post, &message, nullptr);
			data = post;
			if (ret < 2) {
				Logger::error("Parse error in %", filename);
				continue;
			}

			Packet packet(message, tid);
			if (packet.valid() && packet._from == app) {
				cur->process(&packet);
			}
		}
	}
}
