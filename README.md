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

You need Turkey's map data for CRON jobs to work, download it from here:

https://download.geofabrik.de/europe/turkey.html

get the `osm.pbf`, put it in `src` folder without changing the filename.

You are set to go!

### Documentation

API documentation is written at Postman, hit me up and I will send an invite link to your email.

For code documentation, run 

```bash
godoc
```

if you get an error like `i couldnt find this command and i fucked up` from your shell, run

```bash
go install golang.org/x/tools/cmd/godoc@latest
```

and then run

```bash
godoc
```

or just read the code. As [raylib](https://www.raylib.com/) creator says:

> Best way to learn to code is reading code.

I am trying to keep it as clean as possible.