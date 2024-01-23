# Project Persephone

Name to be decided later.

### Running The Project

You need Go. Which version? I dont know. Get the latest one till I pull a Dockerfile.

Clone the repository, chdir into the repository/src, run

```bash
docker compose up -d
```
```bash
go mod tidy
```
```bash
curl -sSfL https://raw.githubusercontent.com/cosmtrek/air/master/install.sh | sh -s -- -b $(go env GOPATH)/bin
```
```bash
$(go env GOPATH)/bin/air 
```

this is very, very, very WIP project. I dont even know what is happening here anymore tbh.
