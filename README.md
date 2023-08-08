pyminihttpd
===========

`pyminihttpd` is a small HTTP server written in Python. It is designed for small
systems that require an HTTP server but do not receive a lot of traffic (like
Let’s Encrypt challenge management).

Features
--------
 - No external dependencies, self-contained in a single file
 - SSL support
 - IPv6 support
 - Multi-port support (notably, there is no need to run multiple instances to
   handle both HTTP and HTTPS)
 - Supports multiple simultaneous connections using threads
 - Multi-route support, can serve different directories/scripts on different
   URLs
 - Basic WSGI support
 - systemd integration (notify and socket activation)

Installation and usage
----------------------
Copy `pyminihttpd.py` to your system (for instance to
`/usr/local/bin/pyminihttpd`). Configure it in the `/etc/pyminihttpd.conf` file.
(You can use another configuration file by specifying the `-c <file>` command
line option). See the next section for configuration details.

You can set up a systemd service to run `pyminihttpd`. Make sure to set
`Type=notify` and `Environment=PYTHONUNBUFFERED=1` in the `[Service]`
definition so the service runs properly.

*Note:* The server currently does not drop privileges after starting. Make sure
to not run it as `root`!
 - With systemd, specify `User=<some user>` (like `www-data`) in the
   `[Service]` definition. If you want the server to listen on privileged ports,
   use systemd socket activation (see the next section for details).
 - Without systemd, start the server as a non-privileged user directly. If you
   want the server to listen on privileged ports, you need to give it the
   `CAP_NET_BIND_SERVICE` capability. For instance:
   ```
   # setpriv --reuid=<user> --regid=<group> --init-groups \
     --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
     pyminihttpd
	```

See the `examples` directory for an example of systemd service file with socket
activation that will enable and disable the sockets when service is started and
stopped.

Configuration
-------------
The `pyminihttpd.conf` is an INI file with a `[server]` and a `[routes]`
sections.

### [server] section

The `listen` option is a space or comma-delimited list of addresses/ports to
listen on without SSL.
 - To listen on the IP of a specific interface, use `<ip>:<port>`
 - To listen on all interfaces, IPv4 only, use `0.0.0.0:<port>`
 - To listen on all interfaces, IPv6 only, use `:::<port>`
 - To listen on all interfaces, IPv4 and IPv6 (if supported), use `:<port>` or
   just `<port>`. Note that if dual-stack IPv6 is not supported by the system,
   this will listen on IPv4 only; you will need to specify two listen addresses
   to listen on IPv4 and IPv6 in that case.
 - To use a listen socket created by systemd activation, use `sd:<index>` with
   the index of the socket in the systemd configuration. See below for details.

The `listen_ssl` works like the `listen` option but enables SSL support for
HTTPS on the connections. If it is used, the `ssl_cert` and `ssl_key` options
must be specified, to indicate the path the the certificate and key files to
use.

The usual configuration for a HTTP-only server will be:
```
[server]
listen = 80
```

and for a HTTP and HTTPS server:

```
[server]
listen = 80
listen_ssl = 443
ssl_cert = /path/to/cert.pem
ssl_key = /path/to/key.pem
```

Which systemd socket activation, each `ListenStream=<port>` directive in
the `.socket` file creates a socket. `sd:1` will use the socket created
by the first `ListenStream` line, `sd:2` will use the second socket, etc.

For instance, to have HTTP on port 80 and HTTPS on port 443, use the following
`.socket` file:

```
[Socket]
ListenStream=80
ListenStream=443
```

and the following server configuration:

```
[server]
listen = sd:1
listen_ssl = sd:2
ssl_cert = /path/to/cert.pem
ssl_key = /path/to/key.pem
```

### [routes] section

The `[routes]` sections describes the routing between a URL and a static
file/directory or a WSGI application.

The syntax is basically:
```
/some/url = <destination>
```

If the URL ends with a slash, it is treated as a directory URL and all
descendants of this URL will be routed to the destination (unless another
route takes precedence). If the URL does not end with a slash, it is a file URL
descendants of this URL will not be accepted. For instance, with the following
configuration:

```
[routes]
/ = static:/var/www/html/
/home/ = static:/home/www/
/users = static:/etc/passwd
```

- `http://server/` returns the index of `/var/www/html/`
- `http://server/somefile` returns the contents of `/var/www/html/somefile`
- `http://server/home/` returns the index of `/home/www`
- `http://server/home/somefile` returns the contents of `/home/www/somefile`
- `http://server/users` returns the contents of `/etc/passwd` (why would you
  do that?)
- `http://server/users/` and `http://server/users/somefile` are invalid (404)

The destination can be `static:<path>`, as indicated in the previous example,
to serve a file or a directory directly. If the URL is a directory URL, the
static path must be a directory, if it’s a file the static path must be a file.

To serve a WSGI script, use a `wsgi:` destination. If the WSGI script does not
use non-standard module paths, use `wsgi:<path to WSGI script>`.

If the WSGI script requires a module import path to be added, use
`wsgi:<module path>:<path to WSGI script within module>`. For instance, a
Django website can be served on the `/django/` URL with:

```
/django/ = wsgi:/path/to/django/project:project/wsgi.py`
```

This will add `/path/to/django/project` to the module import path, and import
the WSGI script `/path/to/django/project/project/wsgi.py`.

You will also need to specify the Django static path
`/django/static/ = static:/path/to/django/static`. (But maybe use a more capable
Web server for this purpose)

WSGI destinations are allowed with both directory and file URLs (although most
complex WSGI applications will probably require a directory URL).

TODO
----
- [ ] Implement a thread pool to reuse handler threads between requests
- [ ] Implement privileges dropping
- [ ] Improve large file support (Verify that the implementation uses
      `sendfile`, maybe add ranged queries)
- [ ] Complete WSGI support (add `wsgi.file_wrapper` and pass more request
      headers to the script)
- [ ] Add a destination handler to allow writing dynamic pages in Python without
      the complexity of WSGI.
