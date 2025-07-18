# :construction::construction: Onetime Secrets Service :construction::construction:

This projects aims to create simple onetime secrets sharing service. One of the core aims is to be able run this independently ( self-host ).

## Storage
Initial version uses [Valkey](https://valkey.io/) storage.

## Configuration
Configuration is done through environment variables.
```env
# Domain is used for generated links.
SECRET_SERVICE_DOMAIN=http://localhost:8080
# This is connection string for storage ( default Valkey )
SECRET_SERVICE_DB=localhost:8081
# This is default address to which bound api/ui
SECRET_SERVICE_HOST=localhost:8080
```

## Development
To run this project, you need [Valkey](https://valkey.io/). Either you can install it on your system or use `docker-compose.yaml` provided within this repo.
