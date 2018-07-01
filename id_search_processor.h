#ifndef __SAWDUST__ID_SEARCH_PROCESSOR__H__
#define __SAWDUST__ID_SEARCH_PROCESSOR__H__

#include <algorithm>
#include <cassert>
#include <iostream>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/csv_table.h"
#include "ib/fileutil.h"
#include "ib/logger.h"
#include "ib/tokenizer.h"

#include <openssl/sha.h>
#include <openssl/md5.h>

using namespace std;

namespace sawdust {

class IDSearchProcessor : public IProcessor {
public:
	IDSearchProcessor(const string& device_file) {

		_productions.push_back(Config::_()->gets("p1"));
		_productions.push_back(Config::_()->gets("p2"));

		vector<string> lines;
		if (device_file.empty()) return;
		Fileutil::read_file(device_file, &lines);
		for (auto &x : lines) {
			vector<string> tokens;
			Tokenizer::split(x, ": ", &tokens);
			if (tokens.size() == 2) {
				if (tokens[1].empty()) continue;
				if (tokens[1] == " ") continue;
				if (tokens[1] == "0") continue;
				add_search(tokens[0], tokens[1]);
			}
		}
		vector<string> items;
		for (auto &x : _pii) {
			items.push_back(x.first);
		}
		for (auto &x : items) {
			unsigned char hash[SHA_DIGEST_LENGTH];
			unsigned char md5hash[MD5_DIGEST_LENGTH];
			MD5((const unsigned char* ) _pii[x].c_str(),
			     _pii[x].length(),
			     md5hash);
			_pii["md5_u_" + x] = Logger::hexify(md5hash,
							  MD5_DIGEST_LENGTH);
			_pii["md5_" + x] = Logger::lower_hexify(md5hash,
							  MD5_DIGEST_LENGTH);
			SHA1((const unsigned char* ) _pii[x].c_str(),
			     _pii[x].length(),
			     hash);
			_pii["sha1_u_" + x] = Logger::hexify(hash, 20);
			_pii["sha1_" + x] = Logger::lower_hexify(hash, 20);
			string digest = sha256(_pii[x]);
			_pii["sha256_u_" + x] = Logger::hexify(
				(uint8_t *) digest.c_str(), digest.length());
			_pii["sha256_" + x] = Logger::lower_hexify(
				(uint8_t *) digest.c_str(), digest.length());
		}
		add_search("package_dump", "com.lexa.fakegps");
		add_search("invasive", "theserver");
		add_search("real_name", "Miwszytcgm Kjhyoucksx");
		items.clear();
		for (auto &x : _pii) {
			items.push_back(x.first);
		}
		for (auto &x : items) {
			char buf[4096];
			assert(4096 > _pii[x].length());
			Base64encode(
				buf, _pii[x].c_str(), _pii[x].length());
			_pii["base64_" + x] = buf;
			string rev = _pii[x];
			reverse(rev.begin(), rev.end());
			_pii[x + "_rev"] = rev;
		}



	}

/*https://opensource.apple.com/source/QuickTimeStreamingServer/QuickTimeStreamingServer-452/CommonUtilitiesLib/base64.c.  */

virtual int Base64encode_len(int len) {
    return ((len + 2) / 3 * 4) + 1;
}

virtual int Base64encode(char *encoded, const char *str, int len) {
    int i;
    char *p;
    string basis_64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(str[i] >> 2) & 0x3F];
    *p++ = basis_64[((str[i] & 0x3) << 4) |
                    ((int) (str[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((str[i + 1] & 0xF) << 2) |
                    ((int) (str[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[str[i + 2] & 0x3F];
    }
    if (i < len) {
    *p++ = basis_64[(str[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
        *p++ = basis_64[((str[i] & 0x3) << 4)];
        *p++ = '=';
    }
    else {
        *p++ = basis_64[((str[i] & 0x3) << 4) |
                        ((int) (str[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((str[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}

	virtual ~IDSearchProcessor() {}

	virtual void trace() {
		for (auto &x : _pii) {
			cout << x.first << " => " << x.second << endl;
		}
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
		if (argc != 0) {
			Logger::error("(id search processer) invalid arguments");
			exit(-1);
		}
	}

	void process(Packet* packet) {
		if (_app != "*" && packet->_app != _app) return;
		packet->save();
		for (const auto &x : _pii) {
			if (x.second.length() == 0) {
				Logger::error("zero length for % in %",
					      x.first, packet->_digest);
			}

			size_t pos = packet->_data.find(x.second);
			if (pos != string::npos) {
				cout << packet->_time << ","
				     << packet->_app << ","
				     << _version << ","
				     << packet->_dns << ","
				     << packet->_sni << ","
				     << packet->_ip << ","
				     << packet->_port << ","
				     << packet->_tls << ","
				     << x.first << ","
				     << pos << ","
				     << packet->_digest << ","
				     << packet->_full_digest << ","
				     << packet->_mood << ","
				     << _device << ","
				     << packet->_dir
				     << endl;
			}
		}
	}

	virtual string trace() const {
		return "outputs a list of pii that matches from packets\n";
	}

	virtual string hwid() const {
		if (!_pii.count("hwid")) return "";
		return _pii.at("hwid");
	}
protected:

	virtual void add_search(const string& key, const string& value) {
		_pii[key] = value;
		if (key == "phone") {
			string first = value.substr(value.length() - 7, 3);
			string second = value.substr(value.length() - 4);
			_pii["phone_1"] = first + second;
			_pii["phone_2"] = first + "-" + second;
			_pii["phone_3"] = first + "." + second;
			_pii["phone_4"] = first + " " + second;
		} else if (key == "geolatlon") {
			string lat, lon;
			Tokenizer::extract("%,%", value,
					   &lat, &lon);
			number_spread(3, lat, "latitude");
			number_spread(3, lon, "longitude");
			for (int i = 3; i < 6; ++i) {
				raw_gps("latitude", lat, i);
				raw_gps("longitude", lon, i);
			}
		} else if (key == "fingerprint") {
			string a,b,c,d,e;
			Tokenizer::extract("%/%/%:%/%/%:%/%",
					   value, &a, &b, &c, &d,
					   nullptr, &e, nullptr, nullptr);
			_pii["fingerprint_a"] = a;
			_pii["fingerprint_b"] = b;
			_pii["fingerprint_c"] = c;
			_pii["fingerprint_d"] = d;
			_pii["fingerprint_e"] = e;
			_pii["fingerprint_ioreye"] = "ioreye";
		} else if (key == "routerssid") {
			vector<string> ssids;
			Tokenizer::split(value, ",", &ssids);
			int i = 0;
			for (const auto &x : ssids) {
				_pii[Logger::stringify("%_%", key, i++)] =
				    Tokenizer::trimout(x, "\"");
			}
		} else if (key == "routermac" || key == "wifimac") {
			vector<string> addrs;
			Tokenizer::split(value, ",", &addrs);
			int i = 0;
			for (const auto &x : addrs) {
				string upper;
				string lower;
				transform(x.begin(),
					  x.end(),
					  back_inserter(upper),
					  ::toupper);
				transform(x.begin(),
					  x.end(),
					  back_inserter(lower),
					  ::tolower);
				if (upper == "00:00:00:00:00:00") continue;
				if (upper == "02:00:00:00:00:00") continue;
				stringstream ss;
				for (int i = 0; i < 16; i += 3) {
					int val = stoi(upper.substr(i, 2), 0, 16);
					ss << (char) val;
				}

				_pii[Logger::stringify("%_%", key, i++)] = lower;
				_pii[Logger::stringify("%_%", key, i++)] =
				    ss.str();
				_pii[Logger::stringify("%_%", key, i++)] =
				    Tokenizer::trimout(lower, ":");
				_pii[Logger::stringify("%_%_upper", key, i++)] = upper;
				_pii[Logger::stringify("%_%_upper", key, i++)] =
				    Tokenizer::trimout(upper, ":");
			}
		} else if (key == "hwid") {
			// use _productions id.
			for (auto &x : _productions) {
				string preimage = _pii[key] + x;
				unsigned char md5hash[MD5_DIGEST_LENGTH];
				unsigned char hash[SHA_DIGEST_LENGTH];
				MD5((const unsigned char* ) preimage.c_str(),
				     preimage.length(),
				     md5hash);
				SHA1((const unsigned char* ) preimage.c_str(),
				     preimage.length(),
				     hash);
				_pii[Logger::stringify("hwid_md5_%", x)]
				    = Logger::hexify(md5hash, MD5_DIGEST_LENGTH);
				_pii[Logger::stringify("hwid_md5_%_lower", x)]
				    = Logger::lower_hexify(md5hash, MD5_DIGEST_LENGTH);
				_pii[Logger::stringify("hwid_sha1_%", x)]
				    = Logger::hexify(hash, SHA_DIGEST_LENGTH);
				_pii[Logger::stringify("hwid_sha1_%_lower", x)]
				    = Logger::lower_hexify(hash, SHA_DIGEST_LENGTH);
			}
		} else if (key == "aaid") {
			map<string, string> perms;
			perms["aaid"] = value;
			string space, empty, underscore;
			for (int i = 0; i < value.length(); ++i) {
				if (value[i] == '-') {
					space += " ";
					underscore += "_";
				} else {
					space += value[i];
					empty += value[i];
					underscore += value[i];
				}
			}

			perms["aaid_space"] = space;
			perms["aaid_empty"] = empty;
			perms["aaid_underscore"] = underscore;
			for (auto &x : perms) {
				_pii[x.first] = x.second;
				string upper;
				transform(x.second.begin(),
					  x.second.end(),
					  back_inserter(upper),
					  ::toupper);
				if (upper != x.second) {
					_pii[x.first + "_upper"] = upper;
				}
			}
		} else {
			string upper;
			transform(value.begin(),
				  value.end(),
				  back_inserter(upper),
				  ::toupper);
			if (upper != value) {
				_pii[key + "_upper"] = upper;
			}
		}
	}

	virtual void subtract_one(string* number) {
		size_t pos = number->length() - 1;
		while (true) {
			if ((*number)[pos] == '0') (*number)[pos] = '9';
			else if ((*number)[pos] <= '9' && (*number)[pos] > '0') {
				(*number)[pos] -= 1;
				return;
			}
			if (pos == 0) break;
			--pos;
		}
	}

	virtual void add_one(string* number) {
		size_t pos = number->length() - 1;
		while (true) {
			if ((*number)[pos] == '9') (*number)[pos] = '0';
			else if ((*number)[pos] < '9' && (*number)[pos] >= '0') {
				(*number)[pos] += 1;
				return;
			}
			if (pos == 0) break;
			--pos;
		}
	}

	virtual void raw_gps(const string& name,
			     const string& val,
			     int digits) {
		double value = atof(val.c_str());
		double exp = 1;
		for (int i = 0; i < digits; ++i) {
			exp *= 10;
		}
		value *= exp;
		value = (int) value;
		double value2 = (int) value;
		if (value2 > 0) ++value2;
		if (value2 < 0) --value2;
		value /= exp;
		value2 /= exp;
		string prefix = Logger::stringify("%_%", name, digits);
		raw_gps_impl(prefix, value);
		raw_gps_impl(prefix + "_round", value2);

	}

	virtual string idk_string(unsigned char* c, size_t len) {
		string retval = "";

		for (size_t i = 0; i < len; ++i) {
			if (c[i] < 128) {
				retval += c[i];
			} else {
				retval += ((char) 0xef);
				retval += ((char) 0xbf);
				retval += ((char) 0xbd);
			}
		}
		return retval;
	}

	virtual string java_string(unsigned char* c, size_t len) {
		string retval = "";

		for (size_t i = 0; i < len; ++i) {
			if (c[i] < 128) {
				retval += c[i];
			} else if (c[i] < 192) {
				retval += ((char) 194);
				retval += c[i];
			} else {
				retval += ((char) 195);
				retval += c[i] - 64;
			}
		}
		return retval;
	}

	virtual void raw_gps_impl(const string& name,
				  double value) {
		unsigned char c1[sizeof(double)], c2[sizeof(double)];
		memcpy(c1, &value, sizeof(double));
		for (int i = 0; i < sizeof(double); ++i) {
			c2[sizeof(double) - 1 - i] = c1[i];
		}
		_pii[Logger::stringify("%_%_bin_ord1", name, value)] =
		    string((char *) c1, sizeof(double));
		_pii[Logger::stringify("%_%_bin_ord2", name, value)] =
		    string((char *) c2, sizeof(double));

		string hex = Logger::hexify((unsigned char *) c1, sizeof(double));
		_pii[Logger::stringify("%_%_hex_ord1", name, value)] = hex;
		hex = Logger::hexify((unsigned char *) c2, sizeof(double));
		_pii[Logger::stringify("%_%_hex_ord2", name, value)] = hex;
	}

	virtual string number_spread(int after, const string& value,
				     const string& key) {
		/* TODO: until a proper GPS circle and earth latitude analysis
		 * is done, this just puts lat.XXX0, ..., lat.XXX9 as search
		 * terms, centered around what the fourth precision digit is
		 */
		size_t pos = value.find(".");
		assert(pos != string::npos);
		int next = value[pos + 4] - '0';
		assert(next >= 0 && next < 10);
		if (next >= 5) {
			for (int i = next - 5; i < 10; ++i) {
				_pii[Logger::stringify("%_%", key, i)] =
				    value.substr(0, pos + 1 + after) +
				    Logger::stringify("%", i);
			}
			for (int i = 0; i < next - 5; ++i) {
				string prefix = value.substr(0, pos + after + 1);
				add_one(&prefix);
				_pii[Logger::stringify("%_%", key, i)] =
				    prefix + Logger::stringify("%", i);
			}
		} else {
			for (int i = 0; i < next + 5; ++i) {
				_pii[Logger::stringify("%_%", key, i)] =
				    value.substr(0, pos + 1 + after) +
				    Logger::stringify("%", i);
			}
			for (int i = next + 5; i < 10; ++i) {
				string prefix = value.substr(0, pos + after + 1);
				subtract_one(&prefix);
				_pii[Logger::stringify("%_%", key, i)] =
				    prefix + Logger::stringify("%", i);
			}
		}

		return value.substr(0, pos + 1 + after);
	}
	virtual string truncate_decimal(int after, const string& value) {
		size_t pos = value.find(".");
		assert(pos != string::npos);
		return value.substr(0, pos + 1 + after);
	}

	string sha256(const string& value) {
		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, value.c_str(), value.length());
		SHA256_Final(hash, &sha256);
		return string((const char *) hash, SHA256_DIGEST_LENGTH);
	}

	string _match;
	map<string, string> _pii;
	vector<string> _productions;
};

}  // namespace sawdust

#endif  // __ID_SEARCH_PROCESSOR__H__
