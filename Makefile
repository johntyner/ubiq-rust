QUIET	:= @

PROFILE	:= dev

build b:
	$(QUIET)cargo $(@) --profile $(PROFILE)

test t:
	$(QUIET)cargo $(@)

doc d:
	$(QUIET)cargo $(@) --no-deps

fmt:
	$(QUIET)cargo $(@) --all -- -l

devclean:
	$(QUIET)find . -name "*~" -exec rm -f {} \;

clean: devclean
	$(QUIET)cargo $(@)
