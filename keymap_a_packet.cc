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

#include "ib/fileutil.h"
#include "ib/logger.h"
#include "ib/tokenizer.h"

using namespace std;
using namespace ib;
using namespace sawdust;

int main(int argc, char** argv) {
	Config::_()->load("sawdust.cfg");
        assert(!Config::_()->gets("packetdb").empty());

	SaveProcessor sp;

	string devfile = "";
	map<string, string> processor_description;
	map<string, unique_ptr<IProcessor>> processors;
	processors["keymap"].reset(new KeymapProcessor());

	if (argc < 2) {
		Logger::error("usage: keymap_a_packet packetname");
		Logger::error("");
		Logger::error("processors: %", processors);
		return -1;
	}
        string packetname = argv[1];
	Packet packet(packetname);
	assert(packet.valid());
	IProcessor *cur = processors["keymap"].get();

	cur->init(packet._app, "", "", "", 0, nullptr);
	cur->process(&packet);
}
