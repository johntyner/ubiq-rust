QUIET	:= @

PROFILE	:= dev

build b:
	$(QUIET)cargo $(@) --profile $(PROFILE)

test t:
	$(QUIET)cargo $(@)

doc d:
	$(QUIET)cargo $(@) --no-deps

fmt:
	$(QUIET)[ -d src ] && find src -name "*.rs" \
	  -exec rustfmt -l --edition 2021 {} \; ; true

	$(QUIET)[ -d tests ] && find tests -name "*.rs" \
	  -exec rustfmt -l --edition 2021 {} \; ; true

devclean:
	$(QUIET)find . -name "*~" -exec rm -f {} \;

clean: devclean
	$(QUIET)cargo $(@)
