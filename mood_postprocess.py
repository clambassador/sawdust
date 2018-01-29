oldkey = None
curdir = 'I'
print "app,version,code,dir,pre,before,after,total"
while True:
  for i in open('mood_tidy.csv', 'r').read().split('\n'):
    l = i.split(',')

    key = ''
    if not len(l) == 1:
            key = l[0] + ',' + l[1] + ',' + l[2]
            if l[3] != curdir: continue

    if not oldkey == key:
        if oldkey != None:
                m0 = str(float(len(moods[0])) / float(len(dests)))
                m1 = str(float(len(moods[1])) / float(len(dests)))
                m2 = str(float(len(moods[2])) / float(len(dests)))
                print oldkey + ',' + curdir + ',' + m0 + ',' + m1 + ',' + m2 + ',' +           str(len(dests))
        if len(l) == 1: break
        oldkey = key
        dests = dict()
        moods = dict()
        moods[0] = dict()
        moods[1] = dict()
        moods[2] = dict()
    moods[int(l[5])][l[4]] = 0
    dests[l[4]] = 0
  if curdir == 'O': break
  curdir = 'O'

