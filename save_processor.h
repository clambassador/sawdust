#ifndef __SAWDUST__SAVE_PROCESSOR__H__
#define __SAWDUST__SAVE_PROCESSOR__H__

#include <cassert>
#include <fstream>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/formatting.h"
#include "ib/tokenizer.h"

#include <leveldb/db.h>

using namespace std;

namespace sawdust {

class SaveProcessor : public IProcessor {
public:
	SaveProcessor() {
		_committed = true;
		if (!_db) {
			if (Config::_()->gets("packetdb").empty()) {
				Logger::error("No packetdb set. Missing sawdust.cfg?");
				exit(-1);
			}
			leveldb::Options options;
			options.create_if_missing = true;
			leveldb::Status status = leveldb::DB::Open(
			    options, Config::_()->gets("packetdb"), &_db);
			Packet::_db = _db;
			if (!_db) {
				Logger::error("error opening %: %",
					      Config::_()->gets("packetdb"),
					      status.ToString());
			}
			assert(_db);
		}
	}
	virtual ~SaveProcessor() {
		if (_db) {
			commit();
			string unaffiliated;
			_db->Get(leveldb::ReadOptions(), "unaffiliated", &unaffiliated);
			unaffiliated += "\n" + _unaffiliated.str();
			_db->Put(leveldb::WriteOptions(), "unaffiliated", unaffiliated);

			delete _db;
			_db = nullptr;
		}
	}

	virtual void commit() {
		if (_committed) return;
		_committed = true;

		_packets << "---";
		_db->Put(leveldb::WriteOptions(), _key, _packets.str());

		_packets.str("");
		_packets.clear();
	}

	bool check() {
		return check(_key);
	}

	bool blankcheck() {
		return blankcheck(_key);
	}

	static string makekey(const string& app,
			      const string& version,
			      const string& time) {
		return app + "," + version + "," + time;
	}

	static bool check(const string& app,
			  const string& version,
			  const string& time) {
		return check(makekey(app, version, time));
	}

	static bool check(const string& key) {
		string ret;
		_db->Get(leveldb::ReadOptions(), key, &ret);
		return !ret.empty();
	}

	static bool blankcheck(const string& key) {
		string ret;
		_db->Get(leveldb::ReadOptions(), key, &ret);
		return !ret.empty() || ret == "---";
	}

        static string getdb(const string& app,
                          const string& version,
                          const string& time) {
                return getdb(makekey(app, version, time));
        }

        static string getdb(const string& key) {
                string ret;
                _db->Get(leveldb::ReadOptions(), key, &ret);
                return ret;
        }

	virtual void init(const string& app,
			  const string& version,
			  const string& device,
			  const string& time,
			  int argc,
			  char** argv) {
		commit();

		_app = app;
		_version = version;
		_device = device;
		_time = time;
		_key = makekey(app, version, time);
		_committed = false;

//		if (argc == 0 && check()) throw string("overboard");  // already processed;
//		if (argc == 1 && !blankcheck()) throw string("overboard");  // already processed;
	}

	void process(Packet* packet) {
		packet->save();
		cout << Logger::stringify("%,%,%,%,%,%,%,%,%,%,%,%\n", packet->_app,
			     _version, _time, _device,
			     packet->_ip,
			     packet->_sni, packet->_dns, packet->_port, _app,
			     packet->_digest,
			     packet->_full_digest, packet->_app != _app);
		if (packet->_app == "") {
			_unaffiliated << packet->_digest << endl
			                << packet->_full_digest << endl;
		}
		if (packet->_app != _app) return;
		_packets << packet->_digest << endl
		         << packet->_full_digest << endl;
	}

	virtual string trace() const {
		return "save all packets and a db of app run to its packets\n";
	}

protected:
	stringstream _packets;
	stringstream _unaffiliated;
	string _key;
	string _time;
	static leveldb::DB* _db;
	bool _committed;
};

}  // namespace sawdust

#endif  // __SAWDUST__SAVE_PROCESSOR__H__
