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

int do_log(const string& log, SaveProcessor* save) {
	string devfile = log.substr(0, log.length() - 3) + "device";
	unique_ptr<IDSearchProcessor> curid;
//	unique_ptr<KeymapProcessor> cur;
	if (!Fileutil::exists(devfile)) return 0;
	curid.reset(new IDSearchProcessor(devfile));
	//cur.reset(new KeymapProcessor());

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
	string message, post, working;
	set<string> seen;
	string header_in = "Haystack.Flow: Inbound connection contents for ";
	string header_out = "Haystack.Flow: Outbound connection contents for ";
	string footer = "Haystack.Flow: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^";
	string key = app + "," + version + "," + time;

	string packet_list = SaveProcessor::getdb(app, version, time);
	if (!packet_list.empty() && packet_list != "---" &&
	    !Config::_()->get("overwrite")) {
	} else {
		try {
			save->init(app, version, device, time, 0, nullptr);
		} catch (string s) {
			if (s == "overboard") return 0;  // clean up
		}


                if (side_file == false) {
                        vector<pair<string, string>> headers;
                        headers.push_back(make_pair("I", header_in));
                        headers.push_back(make_pair("O", header_out));
                        string dir;
                        for (auto &x : headers) {
                                string data;
                                Mood mood(app, year);
                                Fileutil::read_file(log, &data);
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
                                                save->process(&packet);
                                        }
                                }
                        }
                } else {
                        Mood mood(app, year);
                        map<string, string> in, out;
                        {
                                string data;
                                vector<string> lines;
                                Fileutil::read_file(log, &data);
                                Tokenizer::split(data, "\n", &lines);
                                mood.consider(data);
                                cross_reference_times(lines, year, &in, &out);
                        }
                        string root = log;
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
                                        save->process(&packet);
                                }
                                i = j;
                        }
                }
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
	SaveProcessor* save = new SaveProcessor();
	processors["save"].reset(save);
	processors["packet_source"].reset(new PacketSourceProcessor());


	vector<string> logs;
	Fileutil::read_file(argv[1], &logs);
	for (auto &x : logs) {
		do_log(x, save);
	}

}


