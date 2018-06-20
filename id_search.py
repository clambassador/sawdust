import sys

d = dict()

if len(sys.argv) <= 1:
    print "usage: python id_search.py filename"
    sys.exit(1)

for l in open(sys.argv[1]).read().split('\n')[:-1]:
	p = l.split(',')
        try:
            app = p[1]
    	    version = p[2]
	    dest = p[5]
	    data = p[8]

	    key = p[1] + "," + p[2] + "," + p[3] + "," + p[4] + "," + p[5] + "," + p[6] + "," + p[7]
	    if not d.has_key(key):
	    	    d[key] = dict()

	    d[key][p[8]] = p[9] + "," + p[10] + "," + p[11] + "," + p[0]
        except:
            print >> sys.stderr, "bad parse: " + l

violations = dict()
def report(v, k, d, p, n):
	if (n in d):
		if not v[k].has_key(n):
			v[k][n] = p

for key in d:
	assert(not violations.has_key(key))
	violations[key] = dict();
	lat = False
	lon = False
	loc_key = None
	loc_packet = None
	finger_b = False
	finger_c = False
	finger_d = False
	finger_key = None
	finger_packet = None
	for data in d[key]:
		report(violations, key, data, d[key][data], 'aaid')
		report(violations, key, data, d[key][data], 'wifimac')
		report(violations, key, data, d[key][data], 'simid')
		report(violations, key, data, d[key][data], 'routerssid')
		report(violations, key, data, d[key][data], 'routermac')
		report(violations, key, data, d[key][data], 'email')
		report(violations, key, data, d[key][data], 'androidid')
		report(violations, key, data, d[key][data], 'phone')
		report(violations, key, data, d[key][data], 'imei')
		report(violations, key, data, d[key][data], 'hwid')
		report(violations, key, data, d[key][data], 'gsfid')
		report(violations, key, data, d[key][data], 'package_dump')
		report(violations, key, data, d[key][data], 'invasive')
		report(violations, key, data, d[key][data], 'real_name')
		if 'geolatlon' in data:
			lon = True
			lat = True
			if loc_key == None:
				loc_key = key
				loc_packet = d[key][data]
		if 'longitude' in data:
			lon = True
			if loc_key == None:
				loc_key = key
				loc_packet = d[key][data]
		if 'latitude' in data:
			lat = True
			if loc_key == None:
				loc_key = key
				loc_packet = d[key][data]


		if 'ioreye' in data or 'fingerprint_e' in data:
			finger_b = True
			finger_c = True
			finger_d = True
			if finger_key == None:
				finger_key = key
				finger_packet = d[key][data]
		if 'fingerprint_b' in data:
			finger_b = True
			if finger_key == None:
				finger_key = key
				finger_packet = d[key][data]
		if 'fingerprint_c' in data:
			finger_c = True
			if finger_key == None:
				finger_key = key
				finger_packet = d[key][data]
		if 'fingerprint_d' in data:
			finger_d = True
			if finger_key == None:
				finger_key = key
				finger_packet = d[key][data]
	if lat == True and lon == True:
		violations[loc_key]['geolatlon'] = loc_packet
	if finger_b == True and finger_c == True and finger_d == True:
		violations[finger_key]['fingerprint']= finger_packet

for i in violations:
	for j in violations[i]:
		print i + "," + j + "," + violations[i][j]
