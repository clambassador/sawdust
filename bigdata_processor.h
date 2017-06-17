#ifndef __SAWDUST__BIGDATA_PROCESSOR__H__
#define __SAWDUST__BIGDATA_PROCESSOR__H__

#include <cassert>
#include <iostream>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/logger.h"
#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class BigdataProcessor : public IProcessor {
public:
	BigdataProcessor() {}
	virtual ~BigdataProcessor() {}

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
		size_t len = packet->_length;
		size_t bits = 0;
		while (len) {
			len >>= 1;
			++bits;
		}
		cout << _app << ","
		     << _version << ","
		     << _device << ","
		     << packet->_to << ","
		     << packet->_length << ","
		     << bits << " bits,"
		     << packet->_digest << endl;
	}

	virtual string trace() const {
		return "outputs a list of packets that went to a particular "
		       "domain\n";
	}

protected:
	string _match;
};

}  // namespace sawdust

#endif  // __BIGDATA_PROCESSOR__H__
