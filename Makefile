QUIET	:= @

build b test t:
	$(QUIET)cargo $(@)

fmt:
	$(QUIET)find src tests -name "*.rs" -exec rustfmt {} \;

devclean:
	$(QUIET)find . -name "*~" -exec rm -f {} \;

clean: devclean
	$(QUIET)rm -rf target/
