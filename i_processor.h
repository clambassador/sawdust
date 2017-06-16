#ifndef __SAWDUST__I_PROCESSOR__H__
#define __SAWDUST__I_PROCESSOR__H__

#include <string>

#include "packet.h"

using namespace std;

namespace sawdust {

class IProcessor {
public:
	virtual ~IProcessor() {}

	virtual void init(const string& app,
			  const string& version,
			  const string& device,
			  int argc,
			  char** argv) = 0;
	virtual void process(Packet* packet) = 0;
	virtual string trace() const = 0;

protected:
	string _app;
	string _version;
	string _device;
};

}  // namespace sawdust

#endif  // __I_PROCESSOR__H__
