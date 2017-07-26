#ifndef __SAWDUST__PACKET_SOURCE_PROCESSOR__H__
#define __SAWDUST__PACKET_SOURCE_PROCESSOR__H__

#include <cassert>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class PacketSourceProcessor : public IProcessor {
public:
	PacketSourceProcessor() {}
	virtual ~PacketSourceProcessor() {
		for (auto &x: _sources) {
			cout << _app << "," << x.first << ","
			     << x.second << endl;
		}
	}

	virtual void init(const string& app,
			  const string& version,
			  const string& device,
			  const string& time,
			  int argc,
			  char** argv) {
		_app = app;
		assert(argc == 0);
	}

	void process(Packet* packet) {
		_sources[packet->_app]++;
	}

	virtual string trace() const {
		return "collect counts for different packet sources\n";
	}

protected:
	string _app;
	map<string, uint32_t> _sources;
};

}  // namespace sawdust

#endif  // __SAWDUST__PACKET_SOURCE_PROCESSOR__H__
