all: test
test: dropper strace
	cat dropper.c
	sleep 3
	cat dropper.yar
	sleep 3
	./mini dropper.yar ./dropper
dropper: dropper.c
	gcc dropper.c -o dropper
strace: ministrace.c
	gcc ministrace.c -o mini -lyara
