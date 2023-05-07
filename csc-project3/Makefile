TARGET = crack_attack 

.PHONY: clean

all: $(TARGET)

infected_cat: extend.py virus.py
	python3 extend.py

crack_attack: crack.py victim.dat infected_cat
	@cp crack.py $@
	@chmod +x $@

attack_server:
	@cp pharm.py $@
	@chmod +x $@

clean:
	rm -rf __pycache__
	rm -f $(TARGET)
	rm -f infected_cat
