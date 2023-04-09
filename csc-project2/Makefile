TARGET = mitm_attack pharm_attack

.PHONY: clean

all: $(TARGET)

mitm_attack: ca.crt ca.key mitm.py utils.py
	@cp mitm.py mitm_attack
	@chmod +x mitm_attack

pharm_attack: pharm.py utils.py
	@cp pharm.py pharm_attack
	@chmod +x pharm_attack

ca.key:
	openssl genrsa -out ca.key 4096

ca.crt: ca.key
	openssl req -new -x509 -days 1826 -key ca.key -out ca.crt -subj "/C=TW/ST=Taiwan/L=Hsinchu City/O=National Yang Ming Chiao Tung University/CN=e3.nycu.edu.tw"

clean:
	rm -rf __pycache__
	rm -rf ca.crt ca.key connection.log
	rm -rf $(TARGET)
	sudo rm -rf log
	sudo iptables -F
