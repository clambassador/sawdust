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
	string devfile = "";
	map<string, string> processor_description;
	map<string, unique_ptr<IProcessor>> processors;

	if (argc < 2) {
		Logger::error("usage: packetprocessor packetfile");
		return -1;
	}
	string data;
	Fileutil::read_file(argv[1], &data);
	Packet packet("", "", data, 1, 0, "O");
	packet.add_base64();
	packet.trace();
}
