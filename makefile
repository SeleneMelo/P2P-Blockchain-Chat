PYTHON = python3
SRC = main.py protocol.py peer.py peerlist.py archive.py
TARGET = peerchat

.PHONY: all run clean

all: $(SRC)

run:
	$(PYTHON) main.py pugna.snes.dcc.ufmg.br 127.0.0.1

clean:
	rm -f *.pyc __pycache__/* *.log
