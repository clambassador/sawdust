#ifndef __SAWDUST__PACKET__H__
#define __SAWDUST__PACKET__H__

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <leveldb/db.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <zlib.h>

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
	static leveldb::DB* _db;

	Packet(const string& from, const string& to,
	       const string& data, bool tls,
	       int mood, const string& dir)
		: _from(from), _to(to), _data(data), _tls(tls),
		  _valid(true), _loaded(false), _mood(mood),
		  _dir(dir) {
	}

	Packet(const string& raw, int tid, int mood,
	       const string& dir, int year) : _tls(false), _mood(mood),
			_dir(dir), _year(year) {
		pull_packet(raw, tid, true);
	}

	Packet(const string& file) {
		load(file);
	}

	Packet(const string& raw, const string& dir, int mood,
	       const string& time) : _time(time), _mood(mood), _dir(dir) {
		pull_packet(raw, -1, false);
	}

	virtual ~Packet() {}

	virtual void trace() {
		Logger::info("%", _data);
	}

	virtual void trace(bool header, bool outgoing_only) {
		if (outgoing_only && _dir == "I") return;

		if (header) cout << _app << "," << _dns << "," << _ip << "," <<
			_full_digest << endl;
		cout << _data.substr(0, _data.length() / 2) << endl << endl;
	}

	virtual void hash() {
		hash(_raw, &_digest);
		hash(_data, &_full_digest);
	}

	virtual void save() {
		save(_raw, &_digest);
		save(_data, &_full_digest);
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
		string time, date; string test1, test2;
		if (Tokenizer::extract("%\n% % %", rawheader, &test1, &date,
				       &time, &test2)
		    < 3) {
			assert(tid == -1);
		} else if (_time == "") {
			_time = Logger::stringify("% % %", _year, date, time);
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
		string unchunk = maybe_unchunk(_raw);
		if (!unchunk.empty()) {
			if (unchunk[unchunk.length() - 1] == '\n') unchunk = unchunk.substr(0, unchunk.length() - 1);
			ofstream fout("/tmp/chunked_data");
			fout.write(unchunk.c_str(), unchunk.length());
			fout.close();
			unlink("/tmp/gunziped");
			system("zcat /tmp/chunked_data > /tmp/gunziped 2>/dev/null");
			unchunk = "";
			Fileutil::read_file("/tmp/gunziped", &unchunk);
			unlink("/tmp/chunked_data");
		}
		_data = Tokenizer::hex_unescape(_raw);
		if (!unchunk.empty()) {
			_data += "\r \r" + unchunk;
			Logger::error("unchunked: %", unchunk);
		}


		add_base64(_data, 4);
		hash();
		save();
	}

	virtual string maybe_unchunk(const string& raw) {
		string hexval, tmp;
		stringstream retss;
		size_t pos = 0;
		while (pos < raw.length() - 4 && raw.substr(pos, 4) != "\r\n\r\n") ++pos;
		if (pos == raw.length() - 4) return "";
		do {
			while (pos < raw.length() && (raw[pos] == '\r' || raw[pos] == '\n')) ++pos;
			if (pos >= raw.length()) {
				break;
			}
			Tokenizer::extract("%\r\n%", raw.substr(pos), &hexval, &tmp);
			stringstream ss;
			uint64_t len;
			ss << hexval;
			ss >> hex >> len;

			if (len < 1000000) {
				if (tmp.length() < len) len = tmp.length();
				retss << tmp.substr(0, len);
				pos += len + hexval.length() + 2;
			} else {
				retss.str("");
				break;
			}
		} while (true);
		return retss.str();
	}

	virtual void add_base64(const string& data, int depth) {
		if (_base64.empty()) {
			base64_init();
		}
		stringstream ss;
		stringstream add;
		bool go = false;
		string rev = data;
		reverse(rev.begin(), rev.end());
		ss << data << "\r \r" << rev << "\r \r";
		size_t len = data.length();
		string mdata = data;
		for (int i = 0; i < len; ++i) {
			if (mdata[i] == '_') {
				assert(rev[len - i - 1] == '_');
				mdata[i] = '/';
				rev[len - i] = '/';
			}
			if (mdata[i] == '-') {
				assert(rev[len - i - 1] == '-');
				mdata[i] = '+';
				rev[len - i] = '+';
			}
		}
		ss << mdata << "\r \r" << rev << "\r \r";
		string search_data = ss.str();
		ss.str("");

		for (size_t i = 0; i < search_data.length(); ++i) {
			if (search_data[i] == '=') {
				ss << search_data[i];
				go = true;
			} else if (go) {
				if (ss.str().length()) add << base64_try(ss.str());
				if (ss.str().length() > 1)
					add << base64_try(ss.str().substr(1));
				if (ss.str().length() > 2)
					add << base64_try(ss.str().substr(2));
				if (ss.str().length() > 3)
					add << base64_try(ss.str().substr(3));
				ss.str("");
				go = false;
			}
			if (_is_base64_char[(size_t) search_data[i]]) {
				ss << search_data[i];
			} else if (search_data[i] == '\\') {
				++i;
				if (search_data[i] == '/') ss << search_data[i];
			} else if (search_data[i] == '"') {
				go = true;
			} else if (search_data[i] == '&') {
				go = true;
			} else if (search_data[i] == ';') {
				go = true;
			} else if (search_data[i] == ':') {
				go = true;
			} else if (search_data[i] == '}') {
				go = true;
			} else if (search_data[i] == '\r') {
				if (i + 2 < search_data.length()
				    && (search_data[i + 1] == ' ' ||
					search_data[i + 1] == '\n')
				    && search_data[i + 2] == '\r')
					go = true;
			}
		}
		if (ss.str().length()) add << base64_try(ss.str());
		if (ss.str().length() > 1) add << base64_try(ss.str().substr(1));
		if (ss.str().length() > 2) add << base64_try(ss.str().substr(2));
		if (ss.str().length() > 3) add << base64_try(ss.str().substr(3));
		_data += add.str();
		if (add.str().length() && depth) {
			add_base64(add.str(), depth - 1);
		}
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
		int longrund = 0;
		int ascii = 0;
		int asciim = 0;
		int asciid = 0;
		int run = 0;
		int runm = 0;
		int rund = 0;
		int i;
		int late_start = -1;
		int late_startm = -1;
		int late_startd = -1;
		string mask1 = Config::_()->gets("mask1");
		string mask2 = Config::_()->gets("mask2");
		string mask_1 = Config::_()->gets("mask_1");
		if (mask1.empty() || mask2.empty()) {
			mask1 = string("\0", 1);
			mask2 = string("\0", 1);
		}
		if (mask_1.empty()) mask_1 = string("\0", 1);
		int i1 = 0;
		int i2 = 0;
		int i3 = 0;
		stringstream ss;
		stringstream ssd;

		for (i = 0; i < str.length(); ++i) {
			char c = str[i];
			char cm = str[i] ^ mask1[i1] ^ mask2[i2];
			char d = str[i] ^ mask_1[i3];
			ss << cm;
			ssd << d;
			i1 = (i1 + 1) % mask1.length();
			i2 = (i2 + 1) % mask2.length();
			i3 = (i3 + 1) % mask_1.length();
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
			if (_decent_char[(size_t) d]) {
				if (late_startd == -1) late_startd = i;
				++asciid;
				++rund;
			} else {
				if (rund > longrund) longrund = rund;
				rund = 0;
			}
		}
		if (run > longrun) longrun = run;
		if (runm > longrunm) longrunm = runm;
		if (rund > longrund) longrund = rund;

		string ret = "";
		if (!i) return "";
		if (_dns.find("startapp") != string::npos ||
		    _sni.find("startapp") != string::npos) {
			if ((longrund > 30) || (longrund > 5 && ((asciid * 100) /
						     (str.length() -
						      late_startd)) > 95)) {
				if (late_startd == 0) ret += ssd.str();
				else ret += ssd.str().substr(0, late_startd) + " "
					+ ssd.str().substr(late_startd) + " ";
			}
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
		if (str.length() > 40) {
			EVP_CIPHER_CTX *ctx;
			int r;
			int len = 0;
			size_t out_enc_len = str.length() + 32;
			unsigned char* out_enc = (unsigned char*)
			    malloc(out_enc_len);
			memset(out_enc, 0, out_enc_len);

			ctx = EVP_CIPHER_CTX_new();
			assert(ctx);
			r = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(),
					   NULL,
					   (uint8_t*)
					   Config::_()->gets("aes_key1").c_str(),
					   (uint8_t*) _iv);
			r = EVP_DecryptUpdate(ctx, out_enc, &len,
					  (uint8_t*) str.c_str(),
					  str.length());

			r = EVP_DecryptFinal_ex(ctx, out_enc + len, &len);
			EVP_CIPHER_CTX_free(ctx);
			if (r) {
				ret += Tokenizer::hex_unescape(
				    string((char*) out_enc, out_enc_len));
			}

			int i = 1;
			while (!Config::_()->gets("aes", i).empty()) {
				string key = Logger::dehexify(
				    Config::_()->gets("aes", i));
				string iv = Logger::dehexify(
				    Config::_()->gets("iv", i));
				++i;
				memset(out_enc, 0, out_enc_len);
				ctx = EVP_CIPHER_CTX_new();
				assert(ctx);
				r = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(),
					   NULL,
					   (uint8_t*) key.c_str(),
					   (uint8_t*) iv.c_str());
				len = 0;
				r = EVP_DecryptUpdate(ctx, out_enc, &len,
					  (uint8_t*) str.c_str(),
					  str.length());

				r = EVP_DecryptFinal_ex(ctx, out_enc + len, &len);
				EVP_CIPHER_CTX_free(ctx);
				if (r) {
					ret += Tokenizer::hex_unescape(
					    string((char*) out_enc, out_enc_len));
				}
			}
			i = 1;
			while (!Config::_()->gets("aes_128_cbc", i).empty()) {
				string key = Logger::dehexify(
				    Config::_()->gets("aes_128_cbc", i));
				string iv = Logger::dehexify(
				    Config::_()->gets("iv_128_cbc", i));
				++i;
				memset(out_enc, 0, out_enc_len);
				ctx = EVP_CIPHER_CTX_new();
				assert(ctx);
				r = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(),
					   NULL, (uint8_t*) key.c_str(),
					   (uint8_t*) iv.c_str());
				len = 0;
				r = EVP_DecryptUpdate(ctx, out_enc, &len,
					  (uint8_t*) str.c_str(),
					  str.length());

				r = EVP_DecryptFinal_ex(ctx, out_enc + len, &len);
				EVP_CIPHER_CTX_free(ctx);
				if (r) {
					ret += Tokenizer::hex_unescape(
					    string((char*) out_enc, out_enc_len));
				}
				uint64_t chunklen = be_number((uint8_t*) str.c_str());
				if (chunklen < str.length() + 8) {
					uint64_t pos = chunklen + 8;
					chunklen = be_number(((uint8_t*) str.c_str()) + pos);
					pos += 8;
					if (pos + chunklen < str.length()) {
						memset(out_enc, 0, out_enc_len);
						ctx = EVP_CIPHER_CTX_new();
		                                assert(ctx);
                		                r = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(),
                                		           NULL, (uint8_t*) key.c_str(),
		                                           (uint8_t*) iv.c_str());
		                                len = 0;
                		                r = EVP_DecryptUpdate(ctx, out_enc, &len,
                                		          (uint8_t*) str.c_str() + pos, chunklen);
		                                r = EVP_DecryptFinal_ex(ctx, out_enc + len, &len);
                		                EVP_CIPHER_CTX_free(ctx);
						if (r) {
							ret += Tokenizer::hex_unescape(
		                                            string((char*) out_enc, out_enc_len));
						}
					}
				}
			}
			i = 1;
			while (!Config::_()->gets("aes_128_ecb", i).empty()) {
				string key = Logger::dehexify(
				    Config::_()->gets("aes_128_ecb", i));
				++i;
				memset(out_enc, 0, str.length() + 32);
				ctx = EVP_CIPHER_CTX_new();
				assert(ctx);
				r = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(),
					   NULL, (uint8_t*) key.c_str(), NULL);
				len = 0;
				r = EVP_DecryptUpdate(ctx, out_enc, &len,
					  (uint8_t*) str.c_str(),
					  str.length());

				r = EVP_DecryptFinal_ex(ctx, out_enc + len, &len);
				EVP_CIPHER_CTX_free(ctx);
				if (r) {
					ret += Tokenizer::hex_unescape(
					    string((char*) out_enc, out_enc_len));
				}
			}
			free (out_enc);
		}
		if (s.find("hUR") != string::npos && s.find("hUR") != 0)
			return ret + base64_try(s.substr(s.find("hUR")));
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
		memset(_iv, 0, 16);

	}

	virtual void hash(const string &data, string* digest) {
		unsigned char hash[SHA_DIGEST_LENGTH];
		Marshalled me(_from, _to, _dir, _dns, _sni,
			      _app, _time, _ip, _port, _tls, _length, _valid,
			      _mood);

		SHA1((const unsigned char* ) (me.str() + data).c_str(),
		     me.str().length() + data.length(), hash);
		*digest = Logger::hexify(hash, SHA_DIGEST_LENGTH);
	}

	virtual void save(const string &data, string* digest) {
		if (_loaded) return;
		unsigned char hash[SHA_DIGEST_LENGTH];
		Marshalled me(_from, _to, _dir, _dns, _sni,
			      _app, _time, _ip, _port, _tls, _length, _valid,
			      _mood);

		SHA1((const unsigned char* ) (me.str() + data).c_str(),
		     me.str().length() + data.length(), hash);
		*digest = Logger::hexify(hash, SHA_DIGEST_LENGTH);
		_db->Put(leveldb::WriteOptions(), *digest, data);

		me.push(_digest, _full_digest);
		_db->Put(leveldb::WriteOptions(), *digest + ".h", me.str());
	}

	virtual void load(const string &filename) {
		assert(_db);
		_loaded = true;

		string header;
		_db->Get(leveldb::ReadOptions(), filename, &_data);
		_db->Get(leveldb::ReadOptions(), filename + ".h", &header);
		Marshalled me;
		me.data(header);
		me.pull(&_from, &_to, &_dir, &_dns, &_sni,
			&_app, &_time, &_ip, &_port, &_tls, &_length, &_valid,
			&_mood, &_digest, &_full_digest);
		_raw = _data;
	}

	virtual uint64_t be_number(uint8_t* data) {
		return *((uint64_t*) data);
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
	static bool _decent_char[256];
	static bool _is_base64_char[256];
	static char _iv[AES_BLOCK_SIZE];

	int _year;
};

}  // namespace sawdust

#endif  // __PACKET__H__
