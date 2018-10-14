
POD2MAN=pod2man -u -c ' ' -r ' '
MANPAGES=geoip.conf.5 pam_geoip.8
MAN_5_POD=geoip.conf.5.pod
MAN_8_POD=pam_geoip.8.pod

C_FILES=pam_geoip.c parse.c args.c check.c
HEADER=pam_geoip.h
OBJECTS=pam_geoip.o parse.o args.o check.o
MODULE=pam_geoip.so
LDFLAGS=-lpam -lGeoIP -lm -shared
CCFLAGS=-Wall
PAM_LIB_DIR=$(DESTDIR)/lib/$(MULTIARCH)/security
INSTALL=/usr/bin/install

all: config.h pam_geoip.so doc

doc: $(MANPAGES_POD) $(MANPAGES) 

%.5: $(MAN_5_POD)
	$(POD2MAN) -u -s 5 -n $(shell basename $@ .5) $@.pod > $@

%.8: $(MAN_8_POD)
	$(POD2MAN) -u -s 8 -n $(shell basename $@ .8) $@.pod > $@

$(OBJECTS): $(C_FILES)
	$(CC) $(CCFLAGS) -fPIC -c $*.c

pam_geoip.so: $(OBJECTS)
	$(CC) $(CCFLAGS) $(LDFLAGS) -o $@ $(OBJECTS)

config.h:
	sh make_config_h.sh

clean:
	rm -f $(MANPAGES)
	rm -f config.h
	rm -f $(OBJECTS) $(MODULE) core *~

install: $(MODULE)
	$(INSTALL) -m 0755 -d $(PAM_LIB_DIR)
	$(INSTALL) -m 0644 $(MODULE) $(PAM_LIB_DIR)

### dev targets:
update:
	svn update
# END
