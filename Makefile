local: build
	@PATH="$(PWD)/bin:$(PATH)" heroku local

build: main.go
	go build -o bin/backend-signer main.go

run: main.go
	go run main.go

clean:
	rm -rf bin
