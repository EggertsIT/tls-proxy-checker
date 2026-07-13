.PHONY: install-dev test audit package build build-audit clean smoke

install-dev:
	python3 -m pip install -e ".[dev,build]"

test:
	python3 -m pytest

audit:
	python3 -m bandit -q -r src scripts
	python3 -m pip_audit

package:
	python3 -m build

build:
	PYINSTALLER_CONFIG_DIR=$(PWD)/.pyinstaller-cache python3 -m PyInstaller --clean --noconfirm --workpath build --distpath dist tls-proxy-checker.spec

build-audit:
	PYINSTALLER_CONFIG_DIR=$(PWD)/.pyinstaller-cache python3 -m PyInstaller --clean --noconfirm --workpath build-audit --distpath dist-audit tls-proxy-checker-audit.spec

smoke:
	./dist/tls-proxy-checker --help

clean:
	rm -rf build build-audit dist dist-audit *.egg-info src/*.egg-info .pytest_cache
