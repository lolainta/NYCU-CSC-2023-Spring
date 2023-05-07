TARGET = crack_attack attack_server

.PHONY: clean

all: $(TARGET)

# infected_cat: extend.py virus.py
# 	python3 extend.py

crack_attack: crack.py victim.dat
	@cp crack.py $@
	@chmod +x $@

attack_server: server.py
	@cp server.py $@
	@chmod +x $@

clean:
	rm -rf __pycache__
	rm -f $(TARGET)
	rm -f infected_cat
