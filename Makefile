run: main
	@PATH="$(PWD)/bin:$(PATH)" heroku local

main: main.go
	go build -o bin/backend-signer main.go

clean:
	rm -rf bin
