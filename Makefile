test: test/keys
	@./node_modules/.bin/tap test/*.test.js

test/keys:
	@openssl genrsa 2048 > test/private.pem
	@openssl rsa -in test/private.pem -pubout > test/public.pem
	@openssl genrsa 2048 > test/wrong-private.pem
	@openssl rsa -in test/wrong-private.pem -pubout > test/wrong-public.pem
	@rm test/wrong-private.pem
	@touch test/keys

clean:
	rm test/keys

.PHONY: test