#ifndef __MOOD__H__
#define __MOOD__H__

#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class Mood {
public:
	Mood(const string& app) {
		_app = app;
		_mood = MOOD_BEFORE_LAUNCH;
	}

	virtual int operator()() {
		return _mood;
	}

	virtual int last_time(const string& data) {
		string date;
		long time;
		string popped = data;
		if (popped[popped.length() - 1] == '\n')
			popped = popped.substr(0, popped.length() - 1);
		if (!Tokenizer::last_token(popped, "\n", &date)) {
			date = popped;
		}
		int hour, minute, second, millis;
		Tokenizer::extract("%-% %:%:%.% %", date,
				   nullptr, nullptr,
				   &hour, &minute, &second, &millis,
				   nullptr);
		time = minute * 60 + second;
		return time;
	}

	virtual void consider(const string& data) {
		if (_mood == MOOD_AFTER_USE) return;

		if (_mood == MOOD_BEFORE_LAUNCH) {
			string search = "%cmp=" +
			    _app + "%";
			string pre;
			if (Tokenizer::extract(search, data, &pre, nullptr) == 2) {
				_then = last_time(pre);
				_mood = MOOD_BEFORE_USE;
			}
		}
		if (_mood == MOOD_BEFORE_USE) {
			int now = last_time(data);
			if (now < _then - 1000) {
				now += 60 * 60;
			}
			if (now > _then + 25) {
				_mood = MOOD_AFTER_USE;
			}
		}
	}

	int MOOD_BEFORE_LAUNCH = 0;
	int MOOD_BEFORE_USE = 1;
	int MOOD_AFTER_USE = 2;

protected:
	int _mood;
	int _then;
	string _app;
};

}  // namespace sawdust

#endif  // __MOOD__H__
