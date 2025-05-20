[![Go Report Card](https://goreportcard.com/badge/github.com/ameshkov/gohttpbench)](https://goreportcard.com/report/ameshkov/gohttpbench)
[![Latest release](https://img.shields.io/github/release/ameshkov/gohttpbench/all.svg)](https://github.com/ameshkov/gohttpbench/releases)

# gohttpbench

A very simple HTTP benchmarking tool.

## How to install

* Using homebrew:
    ```shell
    brew install ameshkov/tap/gohttpbench
    ```
* From source:
    ```shell
    go install github.com/ameshkov/gohttpbench@latest
    ```
* You can use [a Docker image][dockerimage]:
    ```shell
    docker run --rm ghcr.io/ameshkov/gohttpbench --help
    ```
* You can get a binary from the [releases page][releases].

[dockerimage]: https://github.com/ameshkov/gohttpbench/pkgs/container/gohttpbench

[releases]: https://github.com/ameshkov/gohttpbench/releases

## Usage

```shell
Usage:
  gohttpbench [OPTIONS]

Application Options:
  -u, --url=        URL of the server that needs to be benched.
  -p, --parallel=   The number of parallel connections that needs to be used.
                    (default: 1)
  -t, --timeout=    HTTP request timeout in seconds (default: 10)
  -r, --rate-limit= Rate limit (per second) (default: 0)
  -c, --count=      The overall number of requests that should be sent
                    (default: 10000)
      --insecure    Do not validate the server certificate
  -v, --verbose     Verbose output (optional)
  -o, --output=     Path to the log file. If not set, write to stdout.

Help Options:
  -h, --help        Show this help message
```

## Examples

10 connections, 1000 requests to `example.org`:

```shell
gohttpbench -u https://example.org/ -p 10 -c 1000
```

10 connections, 1000 requests to `example.org` with rate limit not higher than
10 requests per second:

```shell
gohttpbench -u https://example.org/ -p 10 -c 1000 -r 10
```
