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
	//        cout << "app,version,hwid,direction,dest,tls,digest,key,value" << endl;
	}

	void process(Packet* packet) {
		if (packet->_app != _app) return;
		pull_header(packet);
		pull_query(packet);
		pull_json(packet);
		pull_xml(packet);
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
		if (Logger::is_binary(key) || Logger::is_binary(value))
			return;
	        cout << _app << ","
		     << _version << ","
		     << _device << ","
		     << packet->_dir << ","
		     << packet->_to << ","
		     << packet->_tls << ","
		     << packet->_full_digest << ","
		     << Formatting::csv_escape(Formatting::to_lower(trim(key))) << ","
		     << Formatting::csv_escape(trim(value)) << endl;
	}

	void pull_xml(Packet* packet) {
	        vector<string> xmls;
        	Tokenizer::extract_all_paired("<", ">", packet->_data, &xmls);
		set<string> seen;
		if (xmls.empty()) return;
		for (int i = 0; i < xmls.size() - 1; ++i) {
			if (seen.count(xmls[i])) continue;
			if ("/" + xmls[i] == xmls[i+1]) {
				vector<string> values;
				Tokenizer::extract_all_paired(
				   "<" + xmls[i] + ">", "<" + xmls[i+1] + ">",
				   packet->_data, &values);
				for (auto j : values) {
					observe(packet, xmls[i], j);
				}
				seen.insert(xmls[i]);
			}
		}
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

	void pull_header(Packet* packet) {
	        vector<string> headers;
		string header;
		string tmp;
	        Tokenizer::extract("%\n\n%", packet->_data, &header, &tmp);
	        Tokenizer::extract_all("\n%\n\n", packet->_data, &headers);
		headers.push_back(header);
	        for (const auto& z : headers) {
                	string x;
			vector<string> lines;
			Tokenizer::split(z, "\n", &lines);
			for (const auto &y : lines) {
				vector<string> pieces;
				Tokenizer::split(y, ":", &pieces);
				if (pieces.size() == 2) {
					observe(packet, pieces[0], pieces[1]);
				}
			}
		}
	}
	void pull_query(Packet* packet) {
	        vector<string> queries;
	        Tokenizer::extract_all("?%\4", packet->_data, &queries);
        	Tokenizer::extract_all(" %\4", packet->_data, &queries);
	        Tokenizer::extract_all("\n&% ", packet->_data, &queries);
	        Tokenizer::extract_all("\n\n%\n", packet->_data, &queries);
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
