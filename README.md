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
$(go env GOPATH)/bin/air 
```

###  Notes

You need Turkey's map data for CRON jobs to work, download it from here:

https://download.geofabrik.de/europe/turkey.html

get the `osm.pbf`, put it in `src` folder without changing the filename.

You are set to go!

### Documentation

API documentation is written at Swagger.

Run

```go
go install github.com/swaggo/swag/cmd/swag@latest
swag init
```

and then navigate to 
```js
/api/swagger/index.html
```


or just read the code. As [raylib](https://www.raylib.com/) creator says:

> Best way to learn to code is reading code.

I am trying to keep it as clean as possible.
