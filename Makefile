test: test/keys
	@./node_modules/.bin/tap test/*.test.js

test/keys:
	@openssl genrsa 2048 > test/private.pem
	@openssl rsa -in test/private.pem -pubout > test/public.pem
	@touch test/keys

.PHONY: test