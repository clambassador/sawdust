import os

PATH_TO_IB=".."
common = Split(PATH_TO_IB + """/ib/libib.a
		  packet.o
	       """)
for i in range(0, 5):
    print ""
print "libib.a set to: " + PATH_TO_IB + "/ib/libib.a"
for i in range(0, 5):
    print ""

mains = dict()
mains['sawdust.cc'] = 'sawdust'
mains['permission_processor.cc'] = 'permission_processor'
mains['string_search_dump.cc'] = 'string_search_dump'

libs = Split("""pthread
		crypto
	     """)
#env = Environment(CXX="ccache clang++ -D_GLIBCXX_USE_NANOSLEEP 		  -D_GLIBCXX_USE_SCHED_YIELD -D_GLIBCXX_GTHREAD_USE_WEAK=0		  -Qunused-arguments -fcolor-diagnostics -I.. -I/usr/include/c++/4.7/ 		  -I/usr/include/x86_64-linux-gnu/c++/4.7/", 		  CPPFLAGS="-D_FILE_OFFSET_BITS=64 -Wall -g --std=c++11 -pthread", LIBS=libs, CPPPATH=".")
env = Environment(CXX="ccache clang++ -I"+ PATH_TO_IB, CPPFLAGS="-D_FILE_OFFSET_BITS=64 -Wall -g --std=c++11 -pthread", LIBS=libs, CPPPATH=PATH_TO_IB)
env['ENV']['TERM'] = 'xterm'


Decider('MD5')

env.Object("packet.cc")
for i in mains:
	env.Program(source = [i] + common, target = mains[i])
