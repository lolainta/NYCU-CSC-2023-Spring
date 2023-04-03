VENV = .env
PYTHON = $(VENV)/bin/python3
PIP = $(VENV)/bin/pip
TARGET = mitm_attack pharm_attack

.PHONY: clean

all: $(TARGET)

mitm_attack: $(VENV)/bin/activate ca.crt ca.key mitm.py utils.py
	@cp mitm.py mitm_attack
	@chmod +x mitm_attack

pharm_attack: $(VENV)/bin/activate pharm.py utils.py
	@cp pharm.py pharm_attack
	@chmod +x pharm_attack

ca.crt ca.key:
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 1826 -key ca.key -out ca.crt

$(VENV)/bin/activate: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install -r requirements.txt

clean:
	rm -rf __pycache__
	rm -rf $(VENV)
	rm -rf ca.crt ca.key
