TARGET = crack_attack 

.PHONY: clean

all: $(TARGET)

crack_attack: crack.py victim.dat
	@cp crack.py $@
	@chmod +x $@

attack_server:
	@cp pharm.py $@
	@chmod +x $@

clean:
	rm -rf __pycache__
	rm -rf $(TARGET)
