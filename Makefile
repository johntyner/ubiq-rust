QUIET	:= @

build test:
	$(QUIET)cargo $(@)

fmt:
	$(QUIET)find src -name "*.rs" -exec rustfmt {} \;

devclean:
	$(QUIET)find . -name "*~" -exec rm -f {} \;

clean: devclean
	$(QUIET)rm -rf target/
