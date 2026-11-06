# Build and install keyfob without nix or Homebrew.
#   make && sudo make install            # into /usr/local
#   make install PREFIX=$HOME/.local     # without sudo
#   make pkg                             # installer package (see README)

PREFIX ?= /usr/local
VERSION ?= $(shell sed -n 's/^let version = "\(.*\)"/\1/p' Sources/keyfob/main.swift)
SWIFT ?= swift
BUILD_DIR = $(shell $(SWIFT) build -c release --show-bin-path)
# Developer ID Installer identity for `make pkg`, e.g. "Developer ID Installer: Me (TEAMID)"
PKG_SIGN ?=

.PHONY: build install uninstall test pkg clean

build:
	$(SWIFT) build -c release

install: build
	install -d "$(DESTDIR)$(PREFIX)/bin" "$(DESTDIR)$(PREFIX)/lib/pam"
	install -m 755 "$(BUILD_DIR)/keyfob" "$(DESTDIR)$(PREFIX)/bin/keyfob"
	ln -sf keyfob "$(DESTDIR)$(PREFIX)/bin/git-credential-keyfob"
	ln -sf keyfob "$(DESTDIR)$(PREFIX)/bin/age-plugin-se"
	install -m 444 "$(BUILD_DIR)/libpam_keyfob.dylib" "$(DESTDIR)$(PREFIX)/lib/pam/pam_keyfob.so"

uninstall:
	rm -f "$(DESTDIR)$(PREFIX)/bin/keyfob" "$(DESTDIR)$(PREFIX)/bin/git-credential-keyfob" \
	  "$(DESTDIR)$(PREFIX)/bin/age-plugin-se" "$(DESTDIR)$(PREFIX)/lib/pam/pam_keyfob.so"

test: build
	./scripts/e2e-test.sh "$(BUILD_DIR)/keyfob"

# Installer package for MDM / manual installs, into /usr/local. Unsigned
# unless PKG_SIGN names a Developer ID Installer identity.
pkg: build
	rm -rf .build/pkgroot && $(MAKE) install DESTDIR=$(CURDIR)/.build/pkgroot PREFIX=/usr/local
	chmod -R u+w .build/pkgroot && xattr -cr .build/pkgroot && chmod 444 .build/pkgroot/usr/local/lib/pam/pam_keyfob.so
	pkgbuild --root .build/pkgroot --identifier build.flaky.keyfob --version "$(VERSION)" \
	  --install-location / $(if $(PKG_SIGN),--sign "$(PKG_SIGN)") ".build/keyfob-$(VERSION).pkg"
	@echo "built .build/keyfob-$(VERSION).pkg"

clean:
	rm -rf .build
