#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <unistd.h>

#include "auth_processor.h"
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

/* compares two timestamps, returns if a is strictly less than b.
   note that this is not Y10K compatible.
*/
bool timestamp_lt(const string& a, const string& b) {
	int year_a, year_b, unit_a, unit_b;
	stringstream ss;
	ss << a.substr(0, 4);
	ss >> year_a;
	ss.clear();
	ss << b.substr(0, 4);
	ss >> year_b;
	ss.clear();
	if (year_a < year_b) return true;
	if (year_a > year_b) return false;

	for (int i = 4; i < 14; i += 2) {
		stringstream ss;
		ss << a.substr(i, 2);
		ss >> unit_a;
		ss.clear();
		ss << b.substr(i, 2);
		ss >> unit_b;
		ss.clear();
		if (unit_a < unit_b) return true;
		if (unit_a > unit_b) return false;
	}
	assert(a == b);
	return false;
}

string lumen_packet_id(const string& row, bool replace) {
	string y = row;
	string x, z;
	if (!replace) {
		Tokenizer::extract("%bytes total, % written here%",
			   y, &x, nullptr, &z);
	} else {
		Tokenizer::extract("%bytes raw, % processed%",
			   y, &x, nullptr, &z);
	}

	return x + z;
}

void cross_reference_times(const vector<string> data,
			   const int year,
			   map<string, string>* in,
			   map<string, string>* out) {
	const string in_line = "I Haystack.Flow: Inbound connection contents";
	const string out_line = "I Haystack.Flow: Outbound connection contents";

	for (const auto &x : data) {
		if (x.find(in_line) != string::npos) {
			string y = lumen_packet_id(x, true);
			string date, time, match;
			Tokenizer::extract("% % %Haystack.Flow: %",
					   y, &date, &time,
					   nullptr, &match);
			(*in)[match] = Logger::stringify("% % %",
							 year, date, time);
		}
		if (x.find(out_line) != string::npos) {
			string date, time, match;
			string y = lumen_packet_id(x, true);
			Tokenizer::extract("% % %Haystack.Flow: %",
					   y, &date, &time,
					   nullptr, &match);
			(*out)[match] = Logger::stringify("% % %", year,
							  date, time);
		}
	}
}

int do_log(const string& log) {
	string devfile = log.substr(0, log.length() - 3) + "device";
	unique_ptr<IDSearchProcessor> curid;
//	unique_ptr<KeymapProcessor> cur;
	if (!Fileutil::exists(devfile)) return 0;
	curid.reset(new IDSearchProcessor(devfile));
	IDSearchProcessor* cur = curid.get();
//	cur.reset(new KeymapProcessor());

	int last = 0;
	for (int i = 0; i < log.length(); ++i) {
		if (log[i] == '/') last = i + 1;
	}
	string filename = log.substr(last);
	string app, version, device, time;
	device = curid->hwid();
	if (device.empty()) return 0;
	if (Tokenizer::extract("%-%-test-%.log", filename, &app, &version, &time) != 3) {
		Tokenizer::extract("%-%.log", filename, &app, &version);
	}

	if (app.empty()) {
		Logger::error("Unable to parse app name from file name. "
			      "Use format: app-version-time.log");
		//return 0;
		time = "99990101010101";
		app = "*";
		version = "1";
	}
	bool side_file = false;
	int year = 2017;
	if (!time.empty()) {
		if (timestamp_lt(time, "20180227205300")) {
			// no side_file
		} else if (timestamp_lt(time, "20180301174500")) {
			return 0;  // don't even run
		} else {
			side_file = true;
		}
		stringstream ss;
		ss << time.substr(0, 4);
		ss >> year;
	}
	try {
		cur->init(app, version, device, time, 0, nullptr);
	} catch (string s) {
		if (s == "overboard") return 0;  // clean up
	}

	string message, post, working;
	set<string> seen;
	string header_in = "Haystack.Flow: Inbound connection contents for ";
	string header_out = "Haystack.Flow: Outbound connection contents for ";
	string footer = "Haystack.Flow: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";
	string key = app + "," + version + "," + time;
//	string database = Config::_()->gets("packet_database")
//	                  + "/" + key;

	//ifstream fin(database);
	string packet_list = SaveProcessor::getdb(app, version, time);
	if (!packet_list.empty()) {
		vector<string> packets;
		Tokenizer::split(packet_list, "\n", &packets);
		assert(packets.size());
		assert(packets.back() == "---");
		packets.pop_back();
		bool full = false;
		for (auto &x : packets) {
			if (full == false) {
				full = true;
				continue;
			} else {
				full = false;
			}
			Packet packet(x);
			if (packet.valid()) {
				cur->process(&packet);
			}
		}
	} else {
		Logger::error("Unable to process % % %", app, version, time);
	}
	return 0;
}

int main(int argc, char** argv) {
	Config::_()->load("sawdust.cfg");
	map<string, string> processor_description;
	map<string, unique_ptr<IProcessor>> processors;
	processors["keymap"].reset(new KeymapProcessor());
	processors["bigdata"].reset(new BigdataProcessor());
	//processors["id_search"].reset(new IDSearchProcessor(devfile));
	processors["auth"].reset(new AuthProcessor());
	processors["mood"].reset(new MoodProcessor());
	processors["null"].reset(new NullProcessor());
	processors["save"].reset(new SaveProcessor());
	processors["packet_source"].reset(new PacketSourceProcessor());


	vector<string> logs;
	Fileutil::read_file(argv[1], &logs);
	for (auto &x : logs) {
		do_log(x);
	}

}


