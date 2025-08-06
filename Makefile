SEMS_MINOR_VERSION=$(shell pkg-config --modversion libsems | cut -d. -f2)

all:
	@echo use \'make deb\' to build package

init:
	git config --local core.hooksPath .githooks

check:
	./run_clang_format.py --check src unit_tests

format:
	./run_clang_format.py src unit_tests

debian/changelog: debian/changelog.in
	cp debian/changelog.in debian/changelog
	sed -i -E '1s/([0-9]+\.[0-9]+\.[0-9a-z]+)/\1core$(SEMS_MINOR_VERSION)/' debian/changelog

deb: debian/changelog
	@echo build package with sems minor version: $(SEMS_MINOR_VERSION)
	debuild -us -uc -b -j$(shell nproc)

.INTERMEDIATE: debian/changelog
