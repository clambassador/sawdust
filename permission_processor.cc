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
    line = Tokenizer::replace(line, "\"", "");
	vector<string> permissions;
	Tokenizer::split(line, ", ", &permissions);
    /**
    Example, with some permissions having "maxSdkVersion"
    ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.ACCESS_COARSE_LOCATION',
    "android.permission.READ_EXTERNAL_STORAGE' maxSdkVersion='18",
    'android.permission.GET_ACCOUNTS', 'android.permission.USE_CREDENTIALS']
     */
	for (auto &x : permissions) {
        size_t pos = x.find("android.permission.");
        if(pos == 0) {       // Only look at android.permission.*
            string stripped_perm;
            
            size_t sdk_pos = x.find("maxSdkVersion=");
            if(sdk_pos != string::npos) {
                Tokenizer::extract("android.permission.% maxSdkVersion%", x, &stripped_perm, nullptr);
            } else {
                Tokenizer::extract("android.permission.%", x, &stripped_perm);
            }

            declared_permissions.insert(stripped_perm);
        }
	}
    for(const auto &x : declared_permissions) {
        cout << app << "," << version << "," << x << ",0,0" << endl;
    }

	map<string, string> used_permissions;

	for (auto &x : lines) {
        /*
        Legacy format:
        05-04 16:09:39.565   888  3854 I Permission-Sensitive-UCB: android.permission.READ_PHONE_STATE:edu.berkeley.icsi.devfilegen:false:checkReadPhoneState

        Permission format:
        07-08 18:42:59.869   890   901 I DataRecorder: 10011 SensitivePermission android.permission.ACCESS_WIFI_STATE:com.google.android.gms.persistent:true:com.android.launcher3:getScanResults:10.0

        */
		size_t pos_legacy = x.find(" I Permission-Sensitive-UCB:");
		size_t pos = x.find("SensitivePermission android.permission");

        bool legacy_found = pos_legacy != string::npos;
        bool perm_found = pos != string::npos;

        if(legacy_found || perm_found) {
            string time, date;
            string permission, package;

            string pattern;
            if(legacy_found) {
			    pattern = "% % %Permission-Sensitive-UCB: android.permission.%:%:%";
            } else if(perm_found) {
                pattern = "% % %SensitivePermission android.permission.%:%:%";
            }

            Tokenizer::extract(pattern, x,
                               &date, &time, nullptr, &permission, &package, nullptr);

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
