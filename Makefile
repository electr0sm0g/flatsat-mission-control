# SPDX-License-Identifier: GPL-2.0-or-later
# FlatSat electr0sm0g Lab — one-command entry points (see docs/VERIFICATION.md).
#
#   make check        all gates: selftest + 56-PoC sim sweep + host checks
#                     + catalog integrity (the pre-push audit, made permanent)
#   make sweep-sim    the 56-PoC simulator sweep only
#   make sweep-hw     the 56-PoC hardware sweep (needs a flashed board)
#   make build-fw     firmware build + UF2 digest (must equal image H)
#   make flash        flash the built UF2 to the board
#   make findings     regenerate FINDINGS.json from docs/SPARTA_MAPPING.md
#   make web-demo     build the in-browser mission-control demo (web/dist/)

IMAGE_MD5 := bfc145c93039177b7393147978cdd432
UF2       := firmware/.pio/build/pico_tinyusb/firmware.uf2
BOARD ?= /dev/serial/by-id/usb-Pwnsat_Pwnsat_-_Flatsat_fsat-if02

.PHONY: check sweep-sim sweep-hw build-fw flash findings selftest web-demo

check: selftest sweep-sim
	@bash tests/host/run_host_checks.sh
	@python3 tests/host/check_catalog.py
	@echo "make check: ALL GATES GREEN"

selftest:
	@python3 simulator/flatsat_sim.py --selftest

sweep-sim:
	@fail=0; for f in poc/v0*.py poc/v1*.py; do \
		if python3 "$$f" --quiet --no-save >/dev/null 2>&1; then \
			printf 'PASS %s\n' "$$f"; \
		else printf 'FAIL %s\n' "$$f"; fail=1; fi; \
	done; test $$fail -eq 0

sweep-hw:
	@bash tests/hw/run_all_usb.sh $(BOARD)

build-fw:
	@cd firmware && export PATH="$$HOME/.local/bin:$$PATH" && pio run
	@md5sum $(UF2)
	@echo "expected: $(IMAGE_MD5)"

flash: build-fw
	@cd firmware && export PATH="$$HOME/.local/bin:$$PATH" && \
		pio run -t upload --upload-port $(BOARD)

findings:
	@python3 tests/host/gen_findings.py
	@python3 tests/host/check_catalog.py

web-demo:
	@python3 tools/build_web_demo.py
