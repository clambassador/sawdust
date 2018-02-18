#ifndef __SAWDUST__AUTH_PROCESSOR__H__
#define __SAWDUST__AUTH_PROCESSOR__H__

#include <cassert>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class AuthProcessor : public IProcessor {
public:
	AuthProcessor() {}
	virtual ~AuthProcessor() {}

	virtual void init(const string& app,
			  const string& version,
			  const string& device,
			  const string& time,
			  int argc,
			  char** argv) {
		_app = app;
		_version = version;
		_device = device;

	}

	void process(Packet* packet) {
		if (packet->_app != _app) return;
		vector<string> match;
		Tokenizer::get_split_matching(&match, "\r ", packet->_data,
					      "Authorization");
		for (const auto &x : match) {
			string up;
			cout << _app << "," << _version << "," << _device
			     <<	"," << packet->_dir
			     << "," << packet->_dns
			     << "," << packet->_sni
			     << "," << packet->_ip
			     << "," << packet->_digest
			     <<	"," << x << ",";
			if (Tokenizer::extract("%Basic %", x, nullptr, &up) ==
			    2) {
				cout << packet->base64_try(up) << endl;
			} else {
				cout << "," << endl;
			}
		}
	}

	virtual string trace() const {
		return "output authorization lines\n";
	}
};

}  // namespace sawdust

#endif  // __SAWDUST__MOOD_PROCESSOR__H__
