#ifndef __SAWDUST__KEYMAP_PROCESSOR__H__
#define __SAWDUST__KEYMAP_PROCESSOR__H__

#include <cassert>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/formatting.h"
#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class KeymapProcessor : public IProcessor {
public:
	KeymapProcessor() {
	}
	virtual ~KeymapProcessor() {
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
	}

	void process(Packet* packet) {
		if (packet->_app != _app) return;
		pull_query(packet);
		pull_json(packet);
	}

	virtual string trace() const {
		return "output a map of key-values based on the "
		       "packet data with json objections and http requests\n";
	}

protected:

	bool skip(char c) {
	        if (c == '}') return true;
	        if (c == ']') return true;
	        if (c == '{') return true;
	        if (c == '[') return true;
	        if (c == ';') return true;
	        if (c == '"') return true;
	        if (c == ' ') return true;
	        if (c == '\n') return true;
	        if (c == '\r') return true;
	        if (c == '\t') return true;
		return false;
	}

	string trim(const string& s) {
		int begin = 0, end = s.length() - 1;
		while (begin < end && skip(s[begin])) ++begin;
		while (begin < end && skip(s[end])) --end;
	        return s.substr(begin, end - begin + 1);
	}

	void observe(Packet* packet, const string& key, const string& value) {
	        cout << _app << ","
		     << _version << ","
		     << _device << ","
		     << packet->_to << ","
		     << packet->_tls << ","
		     << Formatting::csv_escape(Formatting::to_lower(trim(key))) << ","
		     << Formatting::csv_escape(trim(value)) << endl;
	}

	void pull_json(Packet* packet) {
	        vector<string> jsons;
        	Tokenizer::extract_all_paired("{", "}", packet->_data, &jsons);
	        for (const auto& x : jsons) {
        	        vector<string> tokens;
                	Tokenizer::split(x, ",", &tokens);
	                for (const auto& y : tokens) {
        	                vector<string> entries;
                	        Tokenizer::split(y, ":", &entries);
	                        if (entries.size() == 2) {
        	                        observe(packet, entries[0], entries[1]);
                	        }
	                }
        	}
	}

	void pull_query(Packet* packet) {
	        vector<string> queries;
	        Tokenizer::extract_all("?%\4", packet->_data, &queries);
        	Tokenizer::extract_all(" %\4", packet->_data, &queries);
	        for (const auto& z : queries) {
                	string x;
        	        x = Tokenizer::replace(z, "%3D", "=");
	                x = Tokenizer::replace(x, "%3d", "=");
                	x = Tokenizer::replace(x, "%26", "&");
        	        vector<string> tokens;
	                Tokenizer::split(x, "&", &tokens);
                	for (const auto & y : tokens) {
        	                vector<string> pairs;
	                        Tokenizer::split(y, "?", &pairs);
                        	if (pairs.size() > 1) continue;
                	        pairs.clear();
        	                Tokenizer::split(y, "=", &pairs);
	                        if (pairs.size() == 2) {
                        	        observe(packet, pairs[0], pairs[1]);
                	        }
        	        }
        	}
	}
	int _packet;
};

}  // namespace sawdust

#endif  // __SAWDUST__KEYMAP_PROCESSOR__H__
