#ifndef __MOOD__H__
#define __MOOD__H__

#include "ib/tokenizer.h"

using namespace std;

namespace sawdust {

class Mood {
public:
	Mood(const string& app, int year) {
		_app = app;
		_year = year;
		_mood = MOOD_BEFORE_LAUNCH;
	}

	virtual int operator()() {
		return _mood;
	}

	virtual int operator()(uint64_t timestamp) {
		if (!timestamp) return 2;
		for (size_t i = 0; i < _events.size(); ++i) {
			if (timestamp < _events[i]) return i;
		}
		return _events.size();
	}

	virtual time_t timestamp(const string& data) {
		if (data == "0") return 0;
		struct tm tm;
		memset(&tm, 0, sizeof(struct tm));
		setenv("TZ", "UTC", 1);
		tm.tm_isdst = 0;
		Tokenizer::extract("% %-% %:%:%.% %", data,
				   &tm.tm_year,
				   &tm.tm_mon, &tm.tm_mday,
				   &tm.tm_hour, &tm.tm_min, &tm.tm_sec,
				   nullptr, nullptr);
		tm.tm_mon--;
		time_t ts = mktime(&tm);
		return ts;
	}

	virtual time_t last_timestamp(const string& data) {
		string date;
		int i, j;
		j = data.length();
		if (data[j - 1] == '\n') --j;
		i = j - 1;
		while (data[i] != '\n') --i;
		string last_line = data.substr(i, j - i);
		struct tm tm;
		memset(&tm, 0, sizeof(struct tm));
		setenv("TZ", "UTC", 1);
		tm.tm_year = _year - 1900;
		tm.tm_isdst = 0;
		Tokenizer::extract("%-% %:%:%.% %", last_line,
				   &tm.tm_mon, &tm.tm_mday,
				   &tm.tm_hour, &tm.tm_min, &tm.tm_sec,
				   nullptr, nullptr);
		tm.tm_mon--;
		time_t ts = mktime(&tm);
		return ts;
	}

	virtual int last_time(const string& data) {
		string date;
		long time;
		int i, j;
		j = data.length();
		if (data[j - 1] == '\n') --j;
		i = j - 1;
		while (data[i] != '\n') --i;
		string last_line = data.substr(i, j - i);
		int hour, minute, second, millis;
		Tokenizer::extract("%-% %:%:%.% %", last_line,
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
				_events.push_back(last_timestamp(pre));
				_events.push_back(_events.back() + 25);
				_mood = MOOD_BEFORE_USE;
			} else {
				_then = 0;
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
	int _year;
	vector<time_t> _events;
	string _app;
};

}  // namespace sawdust

#endif  // __MOOD__H__
