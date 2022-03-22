This is a proxy for the [CRG Roller Derby Scoreboard](https://github.com/rollerderby/scoreboard),
allowing for on-site and off-site read-only viewing of screens with live game stats.

# Usage

Download the binaries from the [releases page](https://github.com/DerbyStats/wsproxy/releases),
and extract them. Run the relevant binary for your machine (Darwin = OS X).

`config.ini` is the default configuration file loaded. A path to a config file can be passed
as an argument.

# Building

```
go get -d
go build
./wsproxy
```


# Deployment

There are two basic deployment scenarios, either providing live game stats only
to fans onsite via the local network or providing them via the internet.

By default the proxy will push offsite to https://live.derbystats.eu

## On-Site

On-site usage allows this proxy to serve screens to fans, without them hitting
the scoreboard directly. In the default configuration static content such as
logos, and javascript is fetched and cached from the scoreboard. No writing is
possible so viewers can't for example change the score or upload images.
All the heavy lifting is handled by this proxy rather than the scoreboard -
though venue WiFi would likely fall over long long before the scoreboard did as
a single good entreprise WiFi access point can usually handle up to 100
devices.

If a `html_directory` is provided in the config file, then static content will
be served from there rather than proxied and cached. This gives more
customisation options, and avoids any static load hitting the scoreboard.

## Off-Site

Off-site usage is more involved, as you must run a proxy both in the venue and
on the internet.

Firstly on a publicly internet accessible server, run the proxy with no
`scoreboard_address` provided and a `html_directory` with the static content
you want. If you don't have custom static content, you should use the `html`
directory of a CRG Scoreboard will do (preferably the same version).

Secondly in the venue run a proxy with `push_address` pointing at the first
proxy. This second proxy must have internet access to get to the first proxy.

Fans across the world can then access the first proxy to view live stats.
On-site fans could also access screens this way via mobile data on their
phones, without adding load to the local WiFi network and 2.4/5Ghz radio
spectrums.
