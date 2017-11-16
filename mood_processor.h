#ifndef __SAWDUST__MOOD_PROCESSOR__H__
#define __SAWDUST__MOOD_PROCESSOR__H__

#include <cassert>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class MoodProcessor : public IProcessor {
public:
	MoodProcessor() {}
	virtual ~MoodProcessor() {}

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
		cout << _app << "," << _version << "," << _device
		     << "," << packet->_dir
		     << "," << packet->_to << ","
		     << packet->_mood << endl;
	}

	virtual string trace() const {
		return "count the packets based on the current mood\n";
	}
};

}  // namespace sawdust

#endif  // __SAWDUST__MOOD_PROCESSOR__H__
