oldkey = None
for i in open('mood.csv', 'r').read().split('\n'):
    l = i.split(',')
    key = ''
    if not len(l) == 1:
	    key = l[0] + ',' + l[1] + ',' + l[2]

    if not oldkey == key:
        if oldkey != None:
	        m0 = str(float(len(moods[0])) / float(len(dests)))
		m1 = str(float(len(moods[1])) / float(len(dests)))
	        m2 = str(float(len(moods[2])) / float(len(dests)))
	        print oldkey + ',' + m0 + ',' + m1 + ',' + m2
	if len(l) == 1: break
	oldkey = key
	dests = dict()
	moods = dict()
	moods[0] = dict()
	moods[1] = dict()
	moods[2] = dict()
    moods[int(l[4])][l[3]] = 0
    dests[l[3]] = 0

