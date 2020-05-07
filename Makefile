BASE=/usr/local/freeswitch

SOURCES = mod_nasr.c 

OBJS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCES)))
INCLUDE=
#-I/opt/works/src/nway_authorization/nway_auth_cli/nway_auth_lib/ 
LDFLAGS =
# -L/opt/works/src/nway/mod_auth/nway_auth_cli/nway_auth_lib 
#-Wl,--gc-sections  
#-L/opt/works/src/nway_authorization/nway_auth_cli/nway_auth_lib/
%.o: %.c
	gcc -I${BASE}/include -O3 -fPIC -c $< -o $@ $(INCLUDE) $(LDFLAGS)  

%.o: %.cpp
	g++ -fPIC -I${BASE}/include -O3 -c $< -o $@ $(INCLUDE) $(LDFLAGS)  -fvisibility=hidden



mod_nasr.so: $(OBJS)
	gcc -L${BASE}/lib/ -lfreeswitch -O3 -L./ -lm -shared -fPIC -o mod_nasr.so $(OBJS) $(INCLUDE) $(LDFLAGS) -lpthread  
	#-lnway_auth_lib
	#-O1 


	
clean : 
	rm -rf $(OBJS) mod_nasr.so
	
