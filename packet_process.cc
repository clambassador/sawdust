#include <cassert>
#include <fstream>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/formatting.h"
#include "ib/tokenizer.h"
#include "save_processor.h"

#include <leveldb/db.h>

using namespace std;
using namespace sawdust;

int main(int argc, char** argv) {
        Config::_()->load("sawdust.cfg");

	SaveProcessor sp;
	while (cin.good()) {
		string packetname;
		getline(cin, packetname);
		if (packetname.empty()) break;
		Packet packet(packetname);
		packet.trace(true, true);
	}

	return 0;
}
