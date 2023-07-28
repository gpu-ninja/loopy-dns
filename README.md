# loopy-dns

A ridiculously primitive DNS server that always resolves to the loopback interface.

## Usage

```shell
docker run -d -p 53:53/udp --name loopy-dns ghcr.io/gpu-ninja/loopy-dns:latest
```

## Credits

Based on code from [sslip.io](https://github.com/cunnie/sslip.io).