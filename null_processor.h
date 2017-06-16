#ifndef __SAWDUST__NULL_PROCESSOR__H__
#define __SAWDUST__NULL_PROCESSOR__H__

#include <cassert>
#include <string>

#include "i_processor.h"
#include "packet.h"
#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class NullProcessor : public IProcessor {
public:
	NullProcessor() {}
	virtual ~NullProcessor() {}

	virtual void init(const string& app,
			  const string& version,
			  const string& device,
			  int argc,
			  char** argv) {
		assert(argc == 0);
	}

	void process(Packet* packet) {
	}

	virtual string trace() const {
		return "do nothing, test the other parts of the system\n";
	}
};

}  // namespace sawdust

#endif  // __SAWDUST__NULL_PROCESSOR__H__
