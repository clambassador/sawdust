from sys import stdin
import sys

apps = dict()
dests = dict()
apps_tls = dict()
dest_tls = dict()
apps_dest = dict()
names = dict()

while True:
	s = stdin.readline()
	if s == '': break
	s = s[0:-1]
	p = s.split(',')
	# app,version,hwid,direction,dest,tls,digest,key,value
	app = p[0]
	dest = p[4]
	key = p[7]
	tls = p[5]

	if not dest_tls.has_key(dest):
	    dest_tls[dest] = 0;
	    dests[dest] = 0;

	dest_tls[dest] += int(tls)
	dests[dest] += 1

	if not apps.has_key(app):
	    apps[app] = 0
	    apps_tls[app] = 1
	    apps_dest[app] = dict()
	apps_dest[app][dest] = None
	if tls == '0':
		apps_tls[app] = 0
	if not names.has_key(key):
	    names[key] = 0
	names[key] += 1

print len(apps), "different apps."
print len(dests), "different destinations."

usestls = 0
for i in apps_tls:
	usestls += apps_tls[i]
print usestls, "out of", len(apps), "only transmited with TLS (", 100*usestls/len(apps), "%)"

print
print "Synonyms:"
keys = sorted(names, key=names.get, reverse=True)
stop = 10;
if len(sys.argv) >= 2:
	stop = len(keys)
for k in keys:
	print k, names[k]
	stop -= 1
	if stop == 0: break
print
app_to_destcount = dict()
l = []
for i in apps_dest:
	l.append(len(apps_dest[i]))
	app_to_destcount[i] = l[-1]
l = sorted(l)
p25 = int(.25*len(l))
p50 = int(.50*len(l))
p75 = int(.75*len(l))
p100 = len(l)-1
print "Dests per app: min", l[0], "25", l[p25], "med", l[p50], "75", l[p75], "max",l[p100]

if len(sys.argv) == 1: sys.exit()

print "Apps:"
for app in apps:
	print app
print
print

print "dests:"
for i in sorted(dests, key=dests.get, reverse = True):
    print i, dests[i]


print "dest count:"
for i in sorted(app_to_destcount, key=app_to_destcount.get, reverse = True):
    s = ''
    for j in apps_dest[i]:
	s += j + ' '
    print i, s

print
print
print "Apps without TLS"
for i in apps_tls:
	if apps_tls[i] == 0:
		print i

