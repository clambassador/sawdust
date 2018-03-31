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

int main(int argc, char** argv) {
	Config::_()->load("sawdust.cfg");
	string devfile = "";
	if (argc > 3) devfile = argv[2];
	if (devfile == "none") devfile = "";
	map<string, string> processor_description;
	map<string, unique_ptr<IProcessor>> processors;
	processors["keymap"].reset(new KeymapProcessor());
	processors["bigdata"].reset(new BigdataProcessor());
	processors["id_search"].reset(new IDSearchProcessor(devfile));
	processors["auth"].reset(new AuthProcessor());
	processors["mood"].reset(new MoodProcessor());
	processors["null"].reset(new NullProcessor());
	processors["save"].reset(new SaveProcessor());
	processors["packet_source"].reset(new PacketSourceProcessor());

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
	if (Tokenizer::extract("%-%-test-%.log", filename, &app, &version, &time) != 3) {
		Tokenizer::extract("%-%.log", filename, &app, &version);
	}

	if (app.empty()) {
		Logger::error("Unable to parse app name from file name. "
			      "Use format: app-version-time.log");
		return 0;
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
		cur->init(app, version, device, time, argc - 5, argv + 5);
	} catch (string s) {
		if (s == "overboard") return 0;  // clean up
	}

	string message, post, working;
	set<string> seen;
	string header_in = "Haystack.Flow: Inbound connection contents for ";
	string header_out = "Haystack.Flow: Outbound connection contents for ";
	string footer = "Haystack.Flow: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";
	string key = app + "," + version + "," + time;
	string database = Config::_()->gets("packet_database")
	                  + "/" + key;

	ifstream fin(database);
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
		if (side_file == false) {
			vector<pair<string, string>> headers;
			headers.push_back(make_pair("I", header_in));
			headers.push_back(make_pair("O", header_out));
			string dir;
			for (auto &x : headers) {
				string data;
				Mood mood(app, year);
				Fileutil::read_file(argv[1], &data);
				mood.consider(data);
				while (true) {
					int tid = 0;
					string tmp;
					int ret = Tokenizer::extract("% I " + x.second + "%",
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
					uint64_t ts = 0;
					Tokenizer::extract("%(started %)%",
							   message,
							   nullptr, &ts,
							   nullptr);
					if (!ts)
						ts = mood.last_timestamp(message);

					Packet packet(message, tid, mood(ts),
						      x.first, year);
					if (packet.valid()) {
						cur->process(&packet);
					}
				}
			}
		} else {
			Mood mood(app, year);
			map<string, string> in, out;
			{
				string data;
				vector<string> lines;
				Fileutil::read_file(argv[1], &data);
				Tokenizer::split(data, "\n", &lines);
				mood.consider(data);
				cross_reference_times(lines, year, &in, &out);
			}
			string root = argv[1];
			root = root.substr(0, root.length() - 3);
			string lumen_file = root + "lumen";
			vector<string> data;
			if (!Fileutil::exists(lumen_file)) {
				Logger::error("Cannot find: %", lumen_file);
				return 0;
			}

			Fileutil::read_file(lumen_file, &data);
			string out_header =
			    "-------------------------------------------------------------------";
			string in_header =
			    "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";
			string footer =
			    "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";

			for (size_t i = 0; i < data.size(); ++i) {
				assert(data[i].find(in_header) != string::npos ||
				       data[i].find(out_header) !=
				       string::npos);
				string dir = "I";
				if (data[i].find(out_header) != string::npos) dir = "O";
				size_t j = i + 1;
				stringstream ss;
				uint64_t ts;
				Tokenizer::extract("%(started %)", data[j],
						   nullptr, &ts);
				string y = lumen_packet_id(data[j], false);

				string time;
				if (dir == "I" && in.count(y)) time = in[y];
				if (dir == "O" && out.count(y)) time = out[y];
				if (time == "") {
					time = "0";
				}
				while (data[j] != footer) {
					ss << data[j] + '\n';
					++j;
					assert(j < data.size());
				}
				Packet packet(ss.str(), dir,
					      mood.timestamp(time),
					      time);
				if (packet.valid()) {
					cur->process(&packet);
				}
				i = j;
			}
		}
	}
}
