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
		ifstream packetdb(Config::_()->gets("packet_database"));
		ifstream appdb(Config::_()->gets("app_database"));
		string key = app +"," + version + "," + time;
		bool header = true;
		while (appdb.good()) {
			string line;
			getline(appdb, line);
			if (line.find(key) != string::npos) {
				Logger::error("already processed % as %", key, line);
				int state = 0;
				while (packetdb.good()) {
					string pline;
					getline(packetdb, pline);
					if (pline == key) {
						assert(!state);  // app appears	twice
						state = 1;
					} else if (state == 1) {
						// another app before terminal
						if (pline.find(",")) assert(0);
						if (pline == "---") state = 2;
					}
				}
				if (state == 2)	exit(0);
				header = false;
				break;
			}
		}
		_packetdb.open(Config::_()->gets("packet_database"),
			       ios_base::app | ios_base::out);
		if (header) {
			_appdb.open(Config::_()->gets("app_database"),
				    ios_base::app | ios_base::out);
			_appdb << key << endl;
			_packetdb << key << endl;
		}
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
	ofstream _appdb;
};

}  // namespace sawdust

#endif  // __SAWDUST__SAVE_PROCESSOR__H__
