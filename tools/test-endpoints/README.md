# vmsnotify test endpoints

Three throwaway notification servers on docker-nuc (192.168.0.218) for
testing vmsnotify. LAN-only test servers, not for production.

Start them from this directory: `docker compose up -d`

## Gotify (port 18080)

1. Open http://192.168.0.218:18080 and log in as `admin` with the
   password set in `compose.yaml` (`changeme` unless you changed it).
2. Create an application called `vmsnotify test`.
3. Copy its token to VMS as `VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN`.

## Apprise API (port 18000)

Store a configuration under the key `vms`, replacing `TOKEN`:

```sh
curl -X POST -d 'urls=gotify://192.168.0.218:18080/TOKEN' http://192.168.0.218:18000/add/vms
```

Test it:

```sh
curl -X POST -d 'body=test' http://192.168.0.218:18000/notify/vms
```

## ntfy (port 18081)

No setup is needed. Subscribe to the topic `openvms` at
http://192.168.0.218:18081/openvms, then test:

```sh
curl -d test http://192.168.0.218:18081/openvms
```

## Matching vmsnotify configuration

```
[endpoint gotify]
type = gotify
url = http://192.168.0.218:18080
token_file = VMSNOTIFY$ROOT:[CONF]GOTIFY.TOKEN

[endpoint apprise]
type = apprise
url = http://192.168.0.218:18000
key = vms

[endpoint ntfy]
type = ntfy
url = http://192.168.0.218:18081
topic = openvms
```

`docker compose down -v` removes the containers and all their data.
