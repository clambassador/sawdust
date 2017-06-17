#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <unistd.h>

#include "bigdata_processor.h"
#include "i_processor.h"
#include "id_search_processor.h"
#include "keymap_processor.h"
#include "null_processor.h"
#include "packet.h"

#include "ib/fileutil.h"
#include "ib/logger.h"
#include "ib/tokenizer.h"

using namespace std;
using namespace ib;
using namespace sawdust;

string instrumented_perms [36] = {
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_PHONE_STATE",
    "RECORD_AUDIO",
    "CALL_PHONE",
    "PROCESS_OUTGOING_CALLS",
    "ACCESS_WIFI_STATE",
    "ACCESS_NETWORK_STATE",
    "CAMERA",
    "GET_PACKAGE_SIZE",
    "GET_ACCOUNTS",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_FINE_LOCATION",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "RECEIVE_BOOT_COMPLETED",
    "RECEIVE_SMS",
    "SEND_SMS",
    "READ_SMS",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_CALENDAR",
    "WRITE_CALENDAR",
    "VIBRATE",
    "RECEIVE_EMERGENCY_BROADCAST",
    "RECEIVE_MMS",
    "RECEIVE_WAP_PUSH",
    "WRITE_SETTINGS",
    "SYSTEM_ALERT_WINDOW",
    "ACCESS_NOTIFICATIONS",
    "WAKE_LOCK",
    "ADD_VOICEMAIL",
    "USE_SIP",
    "USE_FINGERPRINT",
    "BODY_SENSORS",
    "READ_CELL_BROADCASTS"
};

bool is_instrumented(const string& perm) {
    for(const auto &x : instrumented_perms) {
        if(perm == x) {
            return true;
        }
    }

    return false;
}

int main(int argc, char** argv) {
	string devfile = "";
	if (argc < 2) {
		Logger::error("usage: permission_processor filename");
		return -1;
	}
	vector<string> lines;
	Fileutil::read_file(argv[1], &lines);
	int last = 0;
	for (int i = 0; i < strlen(argv[1]); ++i) {
		if (argv[1][i] == '/') last = i + 1;
	}
	string filename = argv[1] + last;
	string app, version, device;
	device = argv[3];
	if (Tokenizer::extract("%-%-%.log", filename, &app, &version, nullptr) != 3) {
		Tokenizer::extract("%-%.log", filename, &app, &version);
	}

	set<string> declared_permissions;
	string line = Tokenizer::trimout(lines[0], "[");
	line = Tokenizer::trimout(line, "]");
    line = Tokenizer::replace(line, "'", "");
	vector<string> permissions;
	Tokenizer::split(line, ", ", &permissions);
	for (auto &x : permissions) {
        size_t pos = x.find("android.permission.");
        if(pos == 0) {       // Only look at android.permission.*, and only the instrumented ones
            string stripped_perm;
            Tokenizer::extract("android.permission.%", x, &stripped_perm);

            if(is_instrumented(stripped_perm)) {
                declared_permissions.insert(stripped_perm);
            }
        }
	}
    for(const auto &x : declared_permissions) {
        cout << app << "," << version << "," << x << ",0,0" << endl;
    }

	map<string, string> used_permissions;

	for (auto &x : lines) {
		size_t pos = x.find("Permission-Sensitive-UCB");
		if (pos != string::npos) {
			string time, date;
			string permission, package;
			Tokenizer::extract(
			    "% % %Permission-Sensitive-UCB: android.permission.%:%:%",
			    x, &date, &time, nullptr, &permission, &package, nullptr);
			if (package == app) {
				used_permissions[permission] = date + " " + time;
			}
		}
	}
	for (const auto &x : used_permissions) {
		cout << app << "," << version << "," << x.first
		     << ",1," << x.second << endl;
	}

}
