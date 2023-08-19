QUIET	:= @

PROFILE	:= dev

build b:
	$(QUIET)cargo $(@) --profile $(PROFILE)

test t:
	$(QUIET)cargo $(@)

doc d:
	$(QUIET)cargo $(@) --no-deps

fmt:
	$(QUIET)find src tests -name "*.rs" \
	  -exec rustfmt -l --edition 2021 {} \;

devclean:
	$(QUIET)find . -name "*~" -exec rm -f {} \;

clean: devclean
	$(QUIET)cargo $(@)
