TAR := sol1-1 sol1-2 sol1-3 sol1-4 sol2-1 sol2-2
SERVER := 140.113.207.243
.PHONY = all check run clean

all: check $(TAR)

check:
	@file echooo meow.jpg

sol1-1:
	echo "echo -1 | nc $(SERVER) 8881" > $@
	chmod +x $@

sol1-2: string
	echo "strings $^ | grep RkxBR | base64 -d" > $@
	chmod +x $@

sol1-3: rand rand.py
	echo "python3 rand.py $(SERVER) 8883" > $@
	chmod +x $@

sol1-4: meow.jpg
	echo "unzip $< ; cat flag.txt && rm flag.txt" > $@
	chmod +x $@

sol2-1: ret2flag.py
	echo "python3 ret2flag.py $(SERVER) 8885" > $@
	chmod +x $@

sol2-2: echooo
	echo "python3 echooo.py $(SERVER) 8886" > $@
	chmod +x $@

rand: rand.cpp
	g++ -o $@ $^

run: $(TAR)
	./sol1-1 | grep --color FLAG
	./sol1-2 | grep --color FLAG
	./sol1-3 | grep --color FLAG
	./sol1-4 | grep --color FLAG
	./sol2-1 | grep --color FLAG
	./sol2-2 | grep --color FLAG

clean:
	rm -f rand
	rm -f flag.txt
	rm -f $(TAR)
	rm -f math random.c return2flag.c echooo.c math.c random return2flag
