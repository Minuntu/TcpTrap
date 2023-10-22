# It's a trap

## Config

```yaml
hosts:
  80:
    # Write capture to:
    pcap: port80.pcap
    # Listen on:
    listen: 0.0.0.0:8123
    # Proxy to:
    target:
      host: 127.0.0.1:8000
  443:
    # Write capture to:
    pcap: port443.pcap
    # Listen on:
    listen: 0.0.0.0:8124
    # SSL Listen:
    ssl:
      enabled: true
      # Self sign with:
      cn: test.example.com
      issuer: SomeCert
      org: ACME
    # Proxy to:
    target:
      host: 192.168.2.143:443
      # SSL target
      ssl:
        enabled: true
```

## Run

```sh
$ ./tcptrap config.yaml
2023/10/22 06:59:08 Started proxy 80 - 0.0.0.0:8123 -> 127.0.0.1:8000
2023/10/22 06:59:08 Started proxy 443 - 0.0.0.0:8124 -> 192.168.4.143:443
2023/10/22 06:59:10 Proxying [::1]:55774 to 192.168.4.143:443
```

## Has

- IPv6
- SSL Decrypt
- Any TCP protocol
- Cert generation

## Needs

- CNI?
- Provide own certs
