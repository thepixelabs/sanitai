.PHONY: install-hooks uninstall-hooks check-hooks

## install-hooks: install project git hooks from .githooks/ into .git/hooks/
install-hooks:
	@bash scripts/install-hooks.sh

## uninstall-hooks: remove project hooks from .git/hooks/
uninstall-hooks:
	@for hook in .githooks/*; do \
	  name=$$(basename "$$hook"); \
	  dest=".git/hooks/$$name"; \
	  if [ -f "$$dest" ]; then \
	    rm -f "$$dest"; \
	    echo "Removed: $$dest"; \
	  fi; \
	done

## check-hooks: verify hooks are installed
check-hooks:
	@missing=0; \
	for hook in .githooks/*; do \
	  name=$$(basename "$$hook"); \
	  if [ ! -f ".git/hooks/$$name" ]; then \
	    echo "MISSING hook: $$name (run 'make install-hooks')"; \
	    missing=1; \
	  fi; \
	done; \
	exit $$missing
