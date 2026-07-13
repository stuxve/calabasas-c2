.PHONY: install run keys clean lint help

PYTHON ?= python3
PIP ?= pip3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

install: ## Install Python dependencies
	$(PIP) install -r requirements.txt

keys: ## Generate RSA keypair for key exchange
	$(PYTHON) scripts/generate_keys.py

run: ## Start the operator client
	$(PYTHON) -m client.main --profile profiles/default.yaml --listen-port 8443

run-debug: ## Start operator client with debug logging
	$(PYTHON) -m client.main --profile profiles/default.yaml --listen-port 8443 --debug

lint: ## Lint Python code
	$(PYTHON) -m py_compile client/main.py
	$(PYTHON) -m py_compile client/protocol/commands.py
	$(PYTHON) -m py_compile client/protocol/tlv.py
	$(PYTHON) -m py_compile client/protocol/packet.py
	$(PYTHON) -m py_compile client/protocol/arg_packer.py
	$(PYTHON) -m py_compile client/crypto/aes_gcm.py
	$(PYTHON) -m py_compile client/crypto/key_exchange.py
	$(PYTHON) -m py_compile client/crypto/rsa.py
	$(PYTHON) -m py_compile client/crypto/nonce.py
	$(PYTHON) -m py_compile client/core/session_manager.py
	$(PYTHON) -m py_compile client/core/task_manager.py
	$(PYTHON) -m py_compile client/core/module_registry.py
	$(PYTHON) -m py_compile client/core/events.py
	$(PYTHON) -m py_compile client/listeners/base.py
	$(PYTHON) -m py_compile client/listeners/https_listener.py
	$(PYTHON) -m py_compile client/profiles/parser.py
	$(PYTHON) -m py_compile client/formatters/table.py
	$(PYTHON) -m py_compile client/formatters/transforms.py
	$(PYTHON) -m py_compile client/logging/operator_logger.py
	$(PYTHON) -m py_compile client/cli/shell.py
	$(PYTHON) -m py_compile client/cli/completer.py
	$(PYTHON) -m py_compile client/cli/commands/agents.py
	$(PYTHON) -m py_compile client/cli/commands/listeners.py
	$(PYTHON) -m py_compile client/cli/commands/modules.py
	$(PYTHON) -m py_compile client/cli/commands/help.py
	$(PYTHON) -m py_compile client/cli/commands/generate.py
	$(PYTHON) -m py_compile scripts/build_agent_c.py
	@echo "All Python files compile OK"

build-agent: ## Build C# agent binary (legacy)
	$(PYTHON) scripts/build_agent.py \
		--profile profiles/default.yaml \
		--listener-url https://127.0.0.1:8443/api/v1

build-agent-c: ## Cross-compile C agent via MinGW
	$(PYTHON) scripts/build_agent_c.py \
		--listener-url https://127.0.0.1:8443/api/v1 \
		--profile profiles/default.yaml

build-agent-c-x86: ## Cross-compile x86 C agent
	$(PYTHON) scripts/build_agent_c.py \
		--listener-url https://127.0.0.1:8443/api/v1 \
		--profile profiles/default.yaml \
		--arch x86

clean: ## Clean build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf builds/tmp 2>/dev/null || true
	rm -rf builds/agent_c_tmp 2>/dev/null || true
	rm -rf agent_c/build 2>/dev/null || true
	rm -rf logs/ 2>/dev/null || true
