[![GitHub license](https://img.shields.io/github/license/WorSiCa/worsica-portal.svg?maxAge=2592000&style=flat-square)](https://github.com/WorSiCa/worsica-portal/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/WorSiCa/worsica-portal.svg?maxAge=3600&style=flat-square)](https://github.com/WorSiCa/worsica-portal/releases/latest)
[![Build Status](https://jenkins.eosc-synergy.eu/buildStatus/icon?job=WORSICA%2Fworsica-frontend%2Fdevelopment)](https://jenkins.eosc-synergy.eu/job/WORSICA/job/worsica-frontend/job/development/)
# worsica-portal

WORSICA Web Portal

This is the code for the webGIS portal (worsica-frontend). The portal allows user to create processing requests, visualize processed products and upload additional products. Processing requests are submitted through API REST to worsica-intermediate service to run them either locally or to GRID.

## Features

- Web portal developed in Django with admin interface, HTML/CSS and JS+jQuery.
- Has EGI check-in federated authentication
- Create regions of interest, select ESA Sentinel-2 images or upload drone images, select water indexes for processing.
- 3 processing subservices: Coastal (for coastline detection), Inland (for water body detection) and Water Leak (for water irrigation leak detection).
- For Water Leak, create leak detections by choosing an image and upload additional products for validation.
- Functional tests

## Requirements

- worsica-essentials docker image
- PostgreSQL/PostGIS docker image
- Nextcloud docker image (if you want for image upload)

## Build

**NOTE: In order to build this image, you need to build the worsica-essentials docker image first, available at WORSICA/worsica-cicd repository.**

The Dockerfile.frontend file provided at docker_frontend/aio_v4, do:

```shell
cd docker_frontend/aio_v4
docker build -t worsica/worsica-frontend:development -f Dockerfile.frontend .
```

## Configurations

Before running, first you need to config the following files:

```
worsica_web/settings_sensitive.py: Django Settings
worsica_portal/nextcloud_access.py: Credentials and configs for Nextcloud
worsica_portal/SSecrets.py: Credentials for Sentinel image search
```

We provided their _template files to copy them and set the respective file name above. For some cases, you need to create an user account in order to make it work.

## Execute

**NOTE: Assure that you already have all the requirements installed to run the worsica-intermediate.**

Create a backend.yml file (not provided here) to be run by docker-compose. Create an intermediate service on the file.

```yaml
services:
  frontend:
    image: "worsica/worsica-frontend:development"
    container_name: "frontend"
    hostname: "frontend"
    volumes:
      - /host/path/worsica_web:/usr/local/worsica_web
      - /dev/log:/dev/log
      - /etc/hosts:/etc/hosts
    entrypoint: "/bin/bash"
    command: "/usr/local/worsica_web/worsica_runserver.sh"
    depends_on:
      - postgis
      - intermediate
    networks:
      - worsica
    ports:
      - "8001:8001"
```

On volumes, remember to replace the /host/path/ by the actual directories you have at host.

You need to create the postgis, and intermediate services too in order to run this. For postgis, do a search for a yml config for these services. For intermediate, check WORSICA/eosc-worsica-intermediate for instructions.

Then run docker-compose:

```shell
docker-compose -f backend/backend.yml up -d frontend

```

If everything goes well, you can enter on the container:

```shell
docker exec -it frontend bash
```

If you want to restart the container:

```shell
docker restart frontend
```
