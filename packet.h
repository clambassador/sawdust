#ifndef __SAWDUST__PACKET__H__
#define __SAWDUST__PACKET__H__

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <openssl/sha.h>

#include "ib/config.h"
#include "ib/fileutil.h"
#include "ib/logger.h"
#include "ib/marshalled.h"
#include "ib/tokenizer.h"

using namespace std;
using namespace ib;

namespace sawdust {

class Packet {
public:
	Packet(const string& from, const string& to,
	       const string& data, bool tls,
	       int mood, const string& dir)
		: _from(from), _to(to), _data(data), _tls(tls),
		  _valid(true), _loaded(false), _mood(mood),
		  _dir(dir) {
	}

	Packet(const string& raw, int tid, int mood,
	       const string& dir) : _tls(false), _mood(mood), _dir(dir) {
		pull_packet(raw, tid, true);
	}

	Packet(const string& file) {
		load(file);
	}

	Packet(const string& raw, const string& dir) :
			_mood(2), _dir(dir) {
		pull_packet(raw, -1, false);
	}

	virtual ~Packet() {}

	virtual void trace() {
		Logger::info("%", _data);
	}

	virtual void save() {
		save(_raw, &_digest);
		save(_data, &_full_digest);
	}

	virtual void hash() {
		hash(_raw, &_digest);
		hash(_data, &_full_digest);
	}

	virtual void get(const string& raw, const string& name, string* to) {
		if (Tokenizer::extract("%(" + name + ":%)%\n%", raw, nullptr,
				       to, nullptr, nullptr) < 4) {
			*to= "";
		}
	}

	virtual bool valid() const {
		return _valid;
	}

	virtual void pull_packet(const string& raw, int tid, bool reject_binary) {
		_loaded = false;
		stringstream ss;
        	string next;
		string tls;

		size_t pos;
		bool done = false;
		_valid = true;
		for (pos = 0; pos < raw.length(); ++pos) {
			if (raw[pos] == '\n') {
			       if (done) break;
			       done = true;
			}
		}
		string rawheader = raw.substr(0, pos);
		string time, date;
		if (Tokenizer::extract("%\n% % %", rawheader, nullptr, &date, &time, nullptr)
		    < 3) {
			assert(tid == -1);
		} else {
			_time = date + " " + time;
		}
		get(rawheader, "dns", &_dns);
		get(rawheader, "sni", &_sni);
		get(rawheader, "app", &_app);

		assert(Tokenizer::extract("%->%-%(%", rawheader,
					  nullptr, &_ip, &_port, nullptr)
		       == 4);


	        int ret = Tokenizer::extract("%(dns:%)(app:%)%\n%",
        	        raw, nullptr, &_to, &_from, &tls, &next);
	        if (ret < 5) {
        	        ret = Tokenizer::extract("%(app:%)(sni:%)%\n%",
                	        raw, nullptr, &_from,
				&_to, &tls, &next);
			if (ret < 5) {
				ret = Tokenizer::extract("%->%-%(app:%)%\n%",
					raw, nullptr, &_to, nullptr,
					&_from, &tls, &next);
				if (ret != 6) {
					_valid = false;
					return;
				}
			}
		}
		_tls = tls.find("TLS") != string::npos;

		ret = Tokenizer::extract("%packets (% bytes raw%",
				         tls, nullptr, &_length, nullptr);
		if (ret < 3) {
			ret = Tokenizer::extract("%packets (% bytes total,%",
				         tls, nullptr, &_length, nullptr);
			if (ret < 3) {
				_valid = false;  // haystack throws exception
				return;
			}
		}

	        string data;
		string tmp;
		if (reject_binary) {
		        while (true) {
			        tmp = "";
				data = "";
				int ret = Tokenizer::extract(
			                Logger::stringify("%% % I ", tid) +
					"Haystack.Flow:%\n%", next, nullptr, &data, &tmp);
		                if (ret < 3) break;
				/* Discard invalid packets */
				for (int i = 0; i < data.length(); ++i) {
					if ((unsigned char) data[i] > 127) {
						_valid = false;
						return;
					}
				}
			        ss.write(data.c_str(), data.length());
				next = tmp;
			}
			_raw = ss.str();
		} else {
			assert(tid == -1);
			_raw = next;
		}
		_data = Tokenizer::hex_unescape(_raw);

		add_base64();
		hash();
		save();
	}

	virtual void add_base64() {
		if (_base64.empty()) {
			base64_init();
		}
		stringstream ss;
		stringstream add;
		bool go = false;
		int last_base = 0;
		string rev = _data;
		reverse(rev.begin(), rev.end());
		_data += rev;

		for (size_t i = 0; i < _data.length(); ++i) {
			if (_data[i] == '=') {
				ss << _data[i];
				last_base = i;
				go = true;
			} else if (go) {
				if (ss.str().length()) add << base64_try(ss.str());
				if (ss.str().length() > 1)
					add << base64_try(ss.str().substr(1));
				if (ss.str().length() > 2)
					add << base64_try(ss.str().substr(2));
				ss.str("");
				go = false;
			}
			if (_is_base64_char[(size_t) _data[i]]) {
				ss << _data[i];
				last_base = i;
			} else if (_data[i] == '\\') {
				++i;
			} else if (_data[i] == '"') {
				go = true;
			} else if (_data[i] == '&') {
				go = true;
			} else if (_data[i] == ';') {
				go = true;
			}
		}
		if (ss.str().length()) add << base64_try(ss.str());
		if (ss.str().length() > 1) add << base64_try(ss.str().substr(1));
		if (ss.str().length() > 2) add << base64_try(ss.str().substr(2));
		_data += add.str();
	}

	virtual string base64_try(string s) {
		if (s.empty()) return "";
		static const int B64index [256] = {
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0, 0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0, 0,  0,  0,  0,  0,  0,
0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,
0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6, 7,  8, 9, 10, 11, 12, 13, 14,
15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0, 0,  0, 0, 63,  0, 26, 27, 28,
29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
49, 50, 51 };
		unsigned char* p = (unsigned char*) s.c_str();
		int len = s.length();

		int pad = len > 0 && (len % 4 || p[len - 1] == '=');
		const size_t L = ((len + 3) / 4 - pad) * 4;
		string str(L / 4 * 3 + pad, '\0');
		for (size_t i = 0, j = 0; i < L; i += 4) {
		        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
		        str[j++] = n >> 16;
		        str[j++] = n >> 8 & 0xFF;
		        str[j++] = n & 0xFF;
		}
		if (pad) {
			int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
			str[str.size() - 1] = n >> 16;
			if (len > L + 2 && p[L + 2] != '=') {
				 n |= B64index[p[L + 2]] << 6;
			         str.push_back(n >> 8 & 0xFF);
			}
		}

		int longrun = 0;
		int longrunm = 0;
		int ascii = 0;
		int asciim = 0;
		int run = 0;
		int runm = 0;
		int i;
		int late_start = -1;
		int late_startm = -1;
		string mask1 = Config::_()->gets("mask1");
		string mask2 = Config::_()->gets("mask2");
		if (mask1.empty() || mask2.empty()) {
			mask1 = string("\0", 1);
			mask2 = string("\0", 1);
		}
		int i1 = 0;
		int i2 = 0;
		stringstream ss;

		for (i = 0; i < str.length(); ++i) {
			char c = str[i];
			char cm = str[i] ^ mask1[i1] ^ mask2[i2];
			ss << cm;
			i1 = (i1 + 1) % mask1.length();
			i2 = (i2 + 1) % mask2.length();
			if (_decent_char[(size_t) c]) {
				if (late_start == -1) late_start = i;
				++ascii;
				++run;
			}  else {
				if (run > longrun) longrun = run;
				run = 0;
			}
			if (_decent_char[(size_t) cm]) {
				if (late_startm == -1) late_startm = i;
				++asciim;
				++runm;
			} else {
				if (runm > longrunm) longrunm = runm;
				runm = 0;
			}
		}
		if (run > longrun) longrun = run;
		if (runm > longrunm) longrunm = runm;

		string ret = "";
		if (!i) return "";
		if (_dns.find("startapp") != string::npos ||
		    _sni.find("startapp") != string::npos) {
			if ((longrunm > 30) || (longrunm > 5 && ((asciim * 100) /
						     (str.length() -
						      late_startm)) > 95)) {
				if (late_startm == 0) ret += ss.str();
				else ret += ss.str().substr(0, late_startm) + " "
					+ ss.str().substr(late_startm) + " ";
			}
		}

		if ((longrun > 25) || (longrun > 5 && ((ascii * 100) /
						     (str.length() -
						      late_start)) > 85)) {
			if (late_start == 0) ret += str;
			else ret += str.substr(0, late_start) + " " + str.substr(late_start) + " ";
		}
		return ret;
	}

	virtual bool is_decent_char(char c) {
		return isalnum(c) || isspace(c) || c == 0x00 || c == '\xFF'
			    || c == ',' || c == '{' || c == '}' ||
			    c == '.' ||
			    c == '&' || c == '=' || c == ':' || c == '"' ||
			    c == '$' || c == '!' || c == '%' || c == '-' ||
			    c == '_' || c == '[' || c == ']' || c == '(' ||
			    c == ')' || c == '/' || c == '\\' || c == '\'';
	}

	virtual void base64_init() {
		int i = 0;
		assert(_base64.empty());
		for (char c = 'A'; c <= 'Z'; ++c) {
			_base64[c] = i++;
		}
		for (char c = 'a'; c <= 'z'; ++c) {
			_base64[c] = i++;
		}
		for (char c = '0'; c <= '9'; ++c) {
			_base64[c] = i++;
		}
		_base64['+'] = i++;
		_base64['/'] = i++;
		for (size_t c = 0; c < 256; ++c) {
			_decent_char[c] = is_decent_char((char) c);
			_is_base64_char[c] = _base64.count((char) c);
		}
	}

	virtual void hash(const string &data, string* digest) {
		unsigned char hash[SHA_DIGEST_LENGTH];
		SHA1((const unsigned char* ) data.c_str(), data.length(), hash);
		*digest = Logger::hexify(hash, SHA_DIGEST_LENGTH);
	}

	virtual void save(const string &data, string* digest) {
		if (_loaded) return;
		unsigned char hash[SHA_DIGEST_LENGTH];
		SHA1((const unsigned char* ) data.c_str(), data.length(), hash);
		*digest = Logger::hexify(hash, SHA_DIGEST_LENGTH);
		ofstream fout(Config::_()->gets("packets") + "/" + *digest,
			      ios::out | ios::binary);
		if (!fout.good()) return;
		fout.write(data.c_str(), data.length());
		fout.close();

		Marshalled me(_from, _to, _dir, _dns, _sni,
			      _app, _time, _ip, _port, _tls, _length, _valid,
			      _mood, _digest, _full_digest);
		ofstream fheader(Config::_()->gets("packets") + "/" + *digest
			      + ".h",
			      ios::out | ios::binary);
		if (!fheader.good()) return;
		fheader.write(me.str().c_str(), me.str().length());
		fheader.close();
	}

	virtual void load(const string &filename) {
		_loaded = true;
		ifstream fheader(Config::_()->gets("packets") + "/" +
				 filename + ".h");
		assert(fheader.good());
		string data;
		Fileutil::read_file(Config::_()->gets("packets") + "/" +
		                    filename + ".h", &data);
		Marshalled me;
		me.data(data);
		me.pull(&_from, &_to, &_dir, &_dns, &_sni,
			&_app, &_time, &_ip, &_port, &_tls, &_length, &_valid,
			&_mood, &_digest, &_full_digest);
		Fileutil::read_file(Config::_()->gets("packets") + "/" +
				    filename, &_data);
		_raw = _data;
	}

	string _from;
	string _to;
	string _dns;
	string _sni;
	string _app;
	string _time;
	string _ip;
	int _port;
	string _data;
	string _raw;
	string _digest;
	string _full_digest;
	bool _tls;
	size_t _length;
	bool _valid;
	bool _loaded;
	int _mood;
	string _dir;
	static map<char, int> _base64;
	bool _decent_char[256];
	bool _is_base64_char[256];
};

}  // namespace sawdust

#endif  // __PACKET__H__
