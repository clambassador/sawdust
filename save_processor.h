#ifndef __SAWDUST__SAVE_PROCESSOR__H__
#define __SAWDUST__SAVE_PROCESSOR__H__

#include <cassert>
#include <fstream>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/formatting.h"
#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class SaveProcessor : public IProcessor {
public:
	SaveProcessor() {
	}
	virtual ~SaveProcessor() {
		_packetdb << "---" << endl;
	}

	virtual void init(const string& app,
			  const string& version,
			  const string& device,
			  const string& time,
			  int argc,
			  char** argv) {
		_app = app;
		_version = version;
		_device = device;
		assert(argc == 0);
		string key = app + "," + version + "," + time;
		string database = Config::_()->gets("packet_database")
		    + "/" + key;

		ifstream fin(database);
		string last;
		while (fin.good()) {
			getline(fin, last);
		}
		if (last == "---") exit(0);  // already processed;

		_packetdb.open(database,
			       ios_base::out);
	}

	void process(Packet* packet) {
		if (packet->_from != _app) return;
		_packetdb << packet->_digest << endl
		          << packet->_full_digest << endl;
	}

	virtual string trace() const {
		return "save all packets and a db of app run to its packets\n";
	}

protected:
	ofstream _packetdb;
};

}  // namespace sawdust

#endif  // __SAWDUST__SAVE_PROCESSOR__H__
