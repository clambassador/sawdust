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

	static string make_key(const string& app,
			       const string& version,
			       const string& time) {
		return app + "," + version + "," + time;
	}

	static string get_database(const string& app,
			           const string& version,
			           const string& time) {
		return Config::_()->gets("packet_database")
		    + "/" + make_key(app, version, time);
	}

	static bool check(const string& app,
			  const string& version,
			  const string& time) {
		ifstream fin(get_database(app, version, time));
		string last, next_to_last;
		while (fin.good()) {
			next_to_last = last;
			getline(fin, last);
		}
		if (next_to_last == "---") return true;
		return false;
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
		string database = get_database(app, version, time);
		if (check(app, version, time)) exit(0);  // already processed;

		_packetdb.open(database,
			       ios_base::out);
	}

	void process(Packet* packet) {
		packet->save();
//		if (packet->_from != _app) return;
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
