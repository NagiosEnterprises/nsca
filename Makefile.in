###############################
# Makefile for NSCA
#
# Last Modified: 10-15-2003
###############################


# Source code directories
SRC_BASE=./src/
SRC_INCLUDE=./include/

all:	
	cd $(SRC_BASE); $(MAKE) $@ ; cd ..

	@echo ""
	@echo "*** Compile finished ***"
	@echo ""
	@echo "If the compile finished without any errors, you should"
	@echo "find client and server binaries in the src/ subdirectory."
	@echo ""
	@echo "Read the README file for more information on installing"
	@echo "the binaries, creating configuration files, and using"
	@echo "the server and client."
	@echo ""

nsca:
	cd $(SRC_BASE); $(MAKE) $@ ; cd ..

send_nsca:
	cd $(SRC_BASE); $(MAKE) $@ ; cd ..

install:
	@echo ""
	@echo "Read the README file for information on installing the"
	@echo "client and server binaries."
	@echo ""

solaris-package:
	@if [ `uname -s` != "SunOS" ] ; then \
		echo "It is recommended you be running on Solaris to build a Solaris package"; \
	else \
		cd package/solaris; $(MAKE) build ; $(MAKE) pkg ; cd ../..; \
	fi

clean:
	cd $(SRC_BASE); $(MAKE) $@ ; cd ..
	cd package/solaris; $(MAKE) $@ ; cd ../..
	rm -f core
	rm -f *~ */*~

distclean: clean
	cd $(SRC_BASE); $(MAKE) $@ ; cd ..
	cd package/solaris; $(MAKE) $@ ; cd ../..
	rm -f conf.libmcrypttest config.log config.status config.cache init-script Makefile subst $(SRC_INCLUDE)config.h
	rm -f sample-config/nsca.cfg sample-config/send_nsca.cfg sample-config/nsca.xinetd

devclean: distclean

