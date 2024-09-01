#!/usr/bin/env python3

"""
Miniature HTTP server.

Supports SSL, WSGI, multi-routes and systemd integration.
"""

# Trying to keep everything in a single file
# pylint: disable=too-many-lines

from email.utils import parsedate_tz, mktime_tz, formatdate
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from urllib.parse import quote as url_quote, unquote as url_unquote
import argparse
import configparser
import html
import ipaddress
import mimetypes
import os
import pathlib
import re
import runpy
import selectors
import shutil
import signal
import socket
import ssl
import sys
import threading
import time
import typing


class URLPrefixHandler:
    """
    Base class for URL prefix handlers
    """

    HANDLER_NAME = None
    _handlers = {}

    def __init__(self, _is_file, _arg):
        pass

    def handle_get(self, handler, prefix, rest, query):
        """
        Process a GET query for the provided BaseHTTPRequestHandler.
        """

        raise NotImplementedError("Must be implemented in subclasses.")

    def handle_post(self, handler, _prefix, _rest, _query):
        """
        Process a POST query for the provided BaseHTTPRequestHandler.
        The default implementation returns a HTTP Not Implemented error.
        """

        handler.send_error(HTTPStatus.NOT_IMPLEMENTED,
            "Unsupported method ('POST')")

    @classmethod
    def from_string(cls, is_file, handler_str):
        """
        Instantiate a URL prefix handler from the specified prefix and handler
        string.
        """

        handler_name, valid, handler_value = handler_str.partition(':')
        if not valid:
            raise ValueError(f"{handler_str}: No handler type specified")

        handler_class = cls._handlers.get(handler_name)
        if handler_class is None:
            raise ValueError(f"{handler_str}: Unknown handler {handler_name!r}")

        return handler_class(is_file, handler_value)

    def __init_subclass__(cls, /, **kwargs):
        super().__init_subclass__(**kwargs)
        assert cls.HANDLER_NAME is not None
        URLPrefixHandler._handlers[cls.HANDLER_NAME] = cls


class StaticURLPrefixHandler(URLPrefixHandler):
    """
    Handles URLs redirected to static content
    """

    HANDLER_NAME = 'static'

    def __init__(self, is_file, base_path):
        super().__init__(is_file, base_path)
        base_path = pathlib.Path(base_path)

        if is_file and not base_path.is_file():
            raise ValueError(f"{base_path}: should be a file.")

        if not is_file and not base_path.is_dir():
            raise ValueError(f"{base_path}: should be a directory.")

        self._base_path = base_path

    def handle_get(self, handler, prefix, rest, query):
        # 'rest' is already normalized so directory traversal attacks are not
        # possible. It always starts with / unless it is empty.
        norm_path = rest[1:]

        # But it could contain a null byte…
        if '\x00' in norm_path:
            handler.send_error(HTTPStatus.BAD_REQUEST,
                "Invalid character in path")
            return

        full_path = self._base_path / url_unquote(rest[1:])

        try:
            if rest.endswith('/'):
                self._handle_dir(handler, full_path, prefix, rest)
            else:
                self._handle_file(handler, full_path, prefix, rest)
        except FileNotFoundError:
            handler.send_error(HTTPStatus.NOT_FOUND)
        except PermissionError:
            handler.send_error(HTTPStatus.FORBIDDEN,
                "File/directory not readable")
        except OSError as err:
            sys.stderr.write(f"Error accessing {full_path}: {err}")
            handler.send_error(HTTPStatus.INTERNAL_SERVER_ERROR,
                "A system error occurred while accessing the file or directory")

    @classmethod
    def _handle_dir(cls, handler, full_path, prefix, rest):
        """
        Handles a directory listing or index.html.
        """

        index_path = full_path / 'index.html'
        if index_path.is_file():
            cls._handle_file(handler, index_path, prefix, rest)
            return

        virt_path = prefix + rest

        try:
            listing = ''.join(cls._list_dir(full_path, virt_path))
            listing = listing.encode('utf-8')
        except NotADirectoryError:
            # This path refers to a file. Return a Not Found error (as most
            # Web servers do)
            raise FileNotFoundError(str(full_path)) from None

        handler.send_response(HTTPStatus.OK)
        handler.send_header('Content-type', 'text/html;charset=utf-8')
        handler.send_header('Content-length', str(len(listing)))
        handler.send_header('Connection', 'keep-alive')
        handler.end_headers()
        handler.wfile.write(listing)

    @classmethod
    def _handle_file(cls, handler, full_path, prefix, rest):
        """
        Handle getting a file.
        """

        try:
            file_type, charset = mimetypes.guess_type(full_path)
            if file_type is None:
                file_type = 'application/octet-stream'
            elif charset is None and file_type.startswith('text/'):
                charset = 'utf-8'

            with full_path.open('rb') as fdesc:
                cls._send_fdesc(handler, fdesc, file_type, charset)
        except IsADirectoryError:
            AddSlashPrefixHandler.get_instance().handle_get(handler, prefix,
                rest, '')

    @staticmethod
    def _list_dir(full_path, virt_path):
        """
        Yields a HTML directory listing for the specified path.
        """

        page_title = html.escape(f"Index of {virt_path}")

        yield "<!DOCTYPE html>\n"
        yield "<html>\n"
        yield "<head>\n"
        yield from ("<title>", page_title, "</title>\n")
        yield "</head>\n"
        yield "<body>\n"
        yield from ("<h1>", page_title, "</h1>\n")
        yield "<hr />"
        yield "<ul>\n"
        for item in full_path.iterdir():
            name = item.name
            if item.is_dir():
                name += '/'

            yield from ("<li><a href=\"", url_quote(name), "\">",
                html.escape(name), "</a></li>\n")

        yield "</ul>\n"
        yield "</body>\n"
        yield "</html>\n"

    @staticmethod
    def _send_fdesc(handler, fdesc, file_type, charset):
        """
        Sends the file to the client after checking the last-modified ate.
        """

        fdesc_stat = os.fstat(fdesc.fileno())
        last_modified = int(fdesc_stat.st_mtime)
        file_size = fdesc_stat.st_size

        if 'If-None-Match' in handler.headers:
            if_modified_since = None
        else:
            if_modified_since = handler.headers.get('If-Modified-Since')

        if if_modified_since is not None:
            try:
                if_modified_since = mktime_tz(parsedate_tz(if_modified_since))
            except (KeyError, ValueError):
                pass

        if if_modified_since is not None and last_modified <= if_modified_since:
            handler.send_response(HTTPStatus.NOT_MODIFIED)
            handler.send_header('Content-length', '0')
            handler.send_header('Connection', 'keep-alive')
            handler.end_headers()
            return

        if charset:
            content_type = f"{file_type};charset={charset}"
        else:
            content_type = file_type

        handler.send_response(HTTPStatus.OK)
        handler.send_header('Content-Type', content_type)
        handler.send_header('Content-Length', str(file_size))
        handler.send_header('Last-Modified', formatdate(last_modified,
            usegmt=True))

        # We do not control how much data is sent by copyfileobj, so we close
        # the connection after sending the file.
        handler.send_header('Connection', 'close')
        handler.end_headers()
        try:
            shutil.copyfileobj(fdesc, handler.wfile)
        except BrokenPipeError:
            pass


class WSGIURLPrefixHandler(URLPrefixHandler):
    """
    Handles URL managed by a WSGI script
    """

    HANDLER_NAME = 'wsgi'

    class WSGIRunner:
        """
        Runs a WSGI request.
        """

        def __init__(self, handler, application):
            self._handler = handler
            self._application = application
            self._response_started = False
            self._remaining = None

        def run(self, prefix, rest, query):
            """
            Runs the request and performs resource cleanup, if needed.
            """

            environment = self._get_environment(self._handler, prefix,
                rest, query)
            result = self._application(environment, self._start_response)
            try:
                for data in result:
                    self._write(data)
            finally:
                close_func = getattr(result, 'close', None)
                if close_func is not None:
                    close_func()

            if self._remaining not in {None, 0} or not self._response_started:
                # The WSGI either did not send the right amount of bytes
                # specified in its Content-Length, or it did not call
                # start_response. In either case, force the connection closed
                # so the browser detects the error.
                self._handler.close_connection = True

        def _start_response(self, status, response_headers, exc_info=None):
            """
            Handles the WSGI start_response method.
            """

            if exc_info:
                try:
                    if self._response_started:
                        # Output started, re-raise exception to cause the
                        # thread to quit
                        raise exc_info[1].with_traceback(exc_info[2])
                finally:
                    exc_info = None  # Break circular reference

            assert not self._response_started
            self._response_started = True

            code, _, message = status.partition(' ')
            code = int(code)
            if not message:
                message = None

            self._handler.send_response(code, message)
            for header, value in response_headers:
                lower_header = header.lower()
                if lower_header == 'connection':
                    continue

                if lower_header == 'content-length':
                    assert self._remaining is None
                    self._remaining = int(value)
                    self._handler.send_header('Connection', 'keep-alive')

                self._handler.send_header(header, value)
            self._handler.end_headers()

            return self._write

        def _write(self, data):
            """
            Handles the WSGI write method.
            """

            if not data:
                return

            if self._remaining is not None:
                self._remaining -= len(data)

            self._handler.wfile.write(data)

        @staticmethod
        def _get_environment(handler, prefix, rest, query):
            """
            Determines the WSGI environment to be passed to the WSGI
            application.
            """

            req_headers = handler.headers

            environ = {
                'REQUEST_METHOD': handler.command,
                'SCRIPT_NAME': prefix,
                'PATH_INFO': rest,
                'QUERY_STRING': query,
                'SERVER_NAME': handler.local_addr,
                'SERVER_PORT': handler.local_port,
                'SERVER_PROTOCOL': handler.protocol_version,
                'wsgi.version': (1, 0),
                'wsgi.url_scheme': 'https' if handler.is_https else 'http',
                'wsgi.input': handler.rfile,
                'wsgi.errors': sys.stderr,
                'wsgi.multithread': True,
                'wsgi.multiprocess': False,
                'wsgi.run_once': False
            }

            opt_environ = {
                'CONTENT_TYPE': req_headers.get('Content-Type', ''),
                'CONTENT_LENGTH': req_headers.get('Content-Length', ''),
                'HTTP_REFERER': req_headers.get('Referer', ''),
                'HTTP_ACCEPT': ','.join(req_headers.get_all('Accept', ())),
                'HTTP_USER_AGENT': req_headers.get('User-Agent', ''),
                'HTTP_COOKIE': ', '.join(req_headers.get_all('Cookie', ())),
                'HTTP_HOST': req_headers.get('Host', ''),
            }

            for key, value in opt_environ.items():
                if value:
                    environ[key] = value

            return environ

        def __repr__(self):
            return f"<WSGIRunner: {self._application!r}>"

    def __init__(self, _is_file, arg):
        module_path, _, wsgi_path = arg.rpartition(':')
        if module_path:
            sys.path.insert(0, module_path)
            wsgi_path = pathlib.Path(module_path) / wsgi_path

        try:
            wsgi_vars = runpy.run_path(wsgi_path)
        except Exception as err:
            raise ValueError(f"Unable to execute {wsgi_path}: {err}") from None
        except SystemExit as err:
            raise ValueError(f"{wsgi_path}: SystemExit: {err}") from None

        application = wsgi_vars.get('application')
        if application is None:
            raise ValueError(f"{wsgi_path} did not define an application")

        self._application = application

    def handle_get(self, handler, prefix, rest, query):
        self.WSGIRunner(handler, self._application).run(prefix, rest, query)

    def handle_post(self, handler, prefix, rest, query):
        self.WSGIRunner(handler, self._application).run(prefix, rest, query)


class AddSlashPrefixHandler:
    """
    Special handler (not directly usable from the configuration) that redirects
    to the same URL but with an added / at the end.
    """

    _instance = None

    @classmethod
    def get_instance(cls):
        """
        Get a singleton instance for the handler.
        """

        if cls._instance is None:
            cls._instance = cls()

        return cls._instance

    def handle_get(self, handler, prefix, rest, query):
        """
        Handles a GET request; redirects it, adding the slash
        """

        assert not rest.endswith('/')
        if query:
            full_path = f"{prefix}{rest}/?{query}"
        else:
            full_path = f"{prefix}{rest}/"

        handler.send_response(HTTPStatus.MOVED_PERMANENTLY)
        handler.send_header('Location', full_path)
        handler.send_header('Content-Length', '0')
        handler.send_header('Connection', 'keep-alive')
        handler.end_headers()


class Configuration(typing.NamedTuple):
    """
    This object holds the result of parsing of the configuration file.
    """

    DEFAULT_HSTS_DURATION = 31536000
    DEFAULT_TIMEOUT = 30
    MIN_TIMEOUT = 2

    class ListenAddress(typing.NamedTuple):
        """
        Listen address for a socket
        """

        # For systemd-enabled sockets, addr is the identifier and port is None
        addr: str | ipaddress.IPv4Address | ipaddress.IPv6Address | None
        port: int | None

        def create_socket(self):
            """
            Creates a listener socket from the configuration.
            """

            if self.port is None:
                return SystemdInterface.get_instance().get_socket(self.addr)

            addr = self.addr
            family = socket.AF_INET
            dualstack_ipv6 = False

            if addr is None:
                addr = ''
                if socket.has_dualstack_ipv6():
                    family = socket.AF_INET6
                    dualstack_ipv6 = True
            elif addr.version == 6:
                family = socket.AF_INET6

            return socket.create_server((str(addr), self.port), family=family,
                dualstack_ipv6=dualstack_ipv6)

        @classmethod
        def from_string(cls, value):
            """
            Creates a listen address from the specified value
            """

            addr_str, _, port_str = value.rpartition(':')
            if addr_str == 'sd' and port_str:
                return cls(port_str.strip(), None)

            try:
                port = int(port_str)
            except ValueError:
                port = -1

            if port < 1 or port > 65535:
                raise ValueError(f"{value}: Invalid port {port_str}")

            addr_str = addr_str.strip()
            if addr_str:
                addr = ipaddress.ip_address(addr_str)
            else:
                addr = None

            return cls(addr, port)

    listeners: typing.List[ListenAddress]
    ssl_listeners: typing.List[ListenAddress]
    ssl_context: ssl.SSLContext
    file_routes: typing.Dict[str, BaseHTTPRequestHandler]
    dir_routes: typing.List[typing.Tuple[str, BaseHTTPRequestHandler]]
    max_threads: int
    hsts_duration: int
    timeout: int

    @classmethod
    def from_file(cls, path):
        """
        Parse the configuration file and create a configuration instance.
        """

        parser = configparser.ConfigParser()

        # Disable lowercasing of keys
        parser.optionxform = lambda option: option

        try:
            with open(path, 'r', encoding='utf-8') as fdesc:
                parser.read_file(fdesc, path)

            # Set up environment variables before parsing routes, since that
            # will trigger the load of WSGI scripts
            cls._setup_env_vars(parser)

            listeners = cls._get_listeners(parser, 'listen')
            ssl_listeners = cls._get_listeners(parser, 'listen_ssl')
            ssl_context = cls._get_ssl_context(parser)
            max_threads = cls._get_max_threads(parser)
            file_routes, dir_routes = cls._get_routes(parser)
            hsts_duration = cls._get_hsts_duration(parser)
            timeout = parser.getint('server', 'timeout',
                fallback=cls.DEFAULT_TIMEOUT)

            if not listeners and not ssl_listeners:
                raise ValueError("No listen addresses specified.")

            if ssl_listeners and not ssl_context:
                raise ValueError("listen_ssl requires ssl_cert and ssl_key "
                    "to be set.")

            if timeout < cls.MIN_TIMEOUT:
                raise ValueError(f"timeout is too short (min. "
                    f"{cls.MIN_TIMEOUT} seconds)")

        except (ValueError, OSError) as err:
            sys.exit(f"Error reading configuration {path}: {err}")

        return cls(listeners, ssl_listeners, ssl_context, file_routes,
            dir_routes, max_threads, hsts_duration, timeout)

    def create_sockets(self):
        """
        Creates the listening sockets from the configuration.
        """

        sockets = []
        for listener in self.listeners:
            sockets.append(listener.create_socket())

        for ssl_listener in self.ssl_listeners:
            raw_sock = ssl_listener.create_socket()
            ssl_socket = self.ssl_context.wrap_socket(raw_sock,
                server_side=True, do_handshake_on_connect=False)
            sockets.append(ssl_socket)

        return sockets

    @classmethod
    def _get_listeners(cls, parser, name):
        """
        Get a list of listen addresses from the configuration file.
        """

        listen_str = parser.get('server', name, fallback='').strip()
        if not listen_str:
            return []

        listeners = []
        for raw_listener in re.split(r'\s+|\s*,\s', listen_str):
            try:
                listener = cls.ListenAddress.from_string(raw_listener)
            except ValueError as err:
                raise ValueError(f"{name}: {err}") from None
            listeners.append(listener)

        return listeners

    @classmethod
    def _get_ssl_context(cls, parser):
        """
        Instantatiate a SSL context based on the configuration.
        Returns None if the configuration does not specifies the key/certificate
        to use.
        """

        cred_dir = os.environ.get('CREDENTIALS_DIRECTORY')
        if cred_dir is not None:
            cred_dir = pathlib.Path(cred_dir)

        cert = cls._get_path(parser, cred_dir, 'ssl_cert')
        key = cls._get_path(parser, cred_dir, 'ssl_key')

        if cert and key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                context.load_cert_chain(cert, key)
            except OSError as err:
                raise ValueError(f"Loading certificate {cert} or key {key} "
                    f"failed: {err}") from None
            return context

        if cert or key:
            raise ValueError("Both ssl_cert and ssl_key must be provided.")

        return None

    @staticmethod
    def _get_max_threads(parser):
        """
        Returns the maximum number of concurrent threads allowed.
        """

        max_threads = parser.getint('server', 'max_threads', fallback=20)
        if max_threads < 1:
            raise ValueError("Invalid value for max_threads")

        return max_threads

    @staticmethod
    def _get_routes(parser):
        """
        Returns the file and directory routes defined in the configuration.
        """

        file_routes = {}
        dir_routes = []

        for path, handler_str in parser['routes'].items():
            if (not path.startswith('/') or '//' in path or '/../' in path
                or path.endswith('/..')):
                raise ValueError(f"Route {path!r}: Path needs to be "
                    f"normalized (no .. or //) and start with /")

            is_file = not path.endswith('/')

            handler = URLPrefixHandler.from_string(is_file, handler_str)

            if is_file:
                # File route
                file_routes[path] = handler
            else:
                # Directory route
                dir_routes.append((path, handler))

        # Check for file/directory duplicates (other duplicates are checked by
        # the configuration parser)
        for path, _ in dir_routes:
            if path[:-1] in file_routes:
                raise ValueError(f"Route {path!r} is used both as a file and "
                    "a directory")

        # Sort directory routes by reverse length so longer routes are tested
        # first
        dir_routes.sort(key=lambda route: -len(route[0]))

        return file_routes, dir_routes

    @classmethod
    def _get_hsts_duration(cls, parser):
        """
        Gets the HSTS duration provided in the configuration.
        """

        raw_value = parser.get('server', 'hsts', fallback='').strip().lower()
        if raw_value in {'y', 'yes', 'true', '1', 'enabled'}:
            value = cls.DEFAULT_HSTS_DURATION
        elif raw_value in {'', 'n', 'no', 'false', '0', 'disabled'}:
            value = 0
        else:
            try:
                value = int(raw_value, 10)
            except ValueError:
                value = -1

            if value < 0:
                raise ValueError(f"hsts: Invalid value {raw_value!r}")

        return value

    @staticmethod
    def _setup_env_vars(parser):
        """
        Sets up the environment variables provided in the configuration.
        """

        key_re = re.compile(r'^[A-Za-z0-9_]+$')

        try:
            section = parser['environ']
        except KeyError:
            return

        for key, value in section.items():
            if not key_re.match(key):
                raise ValueError(f"[environ]: Invalid key {key!r}")
            os.environ[key] = value

    @staticmethod
    def _get_path(parser, cred_dir, name):
        """
        Get a path for a configuration item.
        If the configuration specifies a systemd credential file, the path to
        the crendential is resolved.
        """

        value = parser.get('server', name, fallback='').strip()
        if not value.startswith('sd:'):
            return value

        cred_id = value[3:].strip()
        if cred_dir is None:
            raise ValueError(f"{name}: Unable to load {value}: The systemd "
                "credential store is not available")

        if '/' in cred_id or cred_id in {'', '.', '..'}:
            raise ValueError(f"{name}: Invalid credential ID {cred_id!r}")

        return str(cred_dir / cred_id)

class RequestDispatcher:
    """
    Dispatches a socket connection to the appropriate handler, on a new thread.
    """

    class DispatcherHandler(BaseHTTPRequestHandler):
        """
        HTTP request handler that dispatch the request to the specific
        route handler.
        """

        server_version = "pyminihttpd"

        def __init__(self, conn, addr, dispatcher, config):
            # The request is processed in super().__init__ so these attributes
            # need to be set beforehand.
            info = conn.getsockname()
            self.local_addr = info[0]
            self.local_port = info[1]
            self.is_https = isinstance(conn, ssl.SSLSocket)

            if config.hsts_duration > 0:
                self._hsts = f'max-age={config.hsts_duration}'
            else:
                self._hsts = None

            if self.is_https:
                # Do the SSL handshake explicitly now that we are on a thread.
                # (This is not strictly necessary, but allows proper logging
                # of EOF errors during handshake)
                conn.do_handshake()

            super().__init__(conn, addr, dispatcher)

        def end_headers(self):
            # Add the HSTS header if needed, before finalising the headers
            if self._hsts is not None:
                self.send_header('Strict-Transport-Security', self._hsts)

            super().end_headers()

        # Naming required by the superclass
        # pylint: disable-next=invalid-name
        def do_GET(self):
            """
            Handles a GET request
            """

            handler, prefix, rest, query = self.server.route_path(self.path)
            if not handler:
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            handler.handle_get(self, prefix, rest, query)

        # Naming required by the superclass
        # pylint: disable-next=invalid-name
        def do_POST(self):
            """
            Handles a POST request
            """

            handler, prefix, rest, query = self.server.route_path(self.path)
            if not handler:
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            handler.handle_post(self, prefix, rest, query)

        # Argument name defined by the superclass
        # pylint: disable-next=redefined-builtin
        def log_message(self, format, *args):
            """
            Log a request message to standard output.
            """

            message = format % args
            message = message.translate(self._control_char_table)
            address = self.address_string()
            date_time = self.log_date_time_string()

            print(f"{address} - - [{date_time}] {message}", flush=True)

    def __init__(self, config):
        self._sockets = config.create_sockets()
        self._selector = selectors.DefaultSelector()
        self._threads = []
        self._config = config
        self._err_sock = socket.socketpair()

    def run(self):
        """
        Handles the request dispatch.
        """

        selector = self._selector

        for sock in self._sockets:
            selector.register(sock, selectors.EVENT_READ)

        selector.register(self._err_sock[1], selectors.EVENT_READ)

        while True:
            for key, _ in selector.select():
                sock = key.fileobj

                if sock is self._err_sock[1]:
                    sys.exit("Exiting after a thread failure.")

                try:
                    conn, addr = sock.accept()
                except (ConnectionAbortedError, ConnectionResetError) as err:
                    print(f"Connection accept error: {err}", file=sys.stderr,
                        flush=True)
                    continue

                conn.settimeout(self._config.timeout)
                self._handle_conn(conn, addr)

    def close(self):
        """
        Releases the resources after the requests have completed.
        """

        self._cleanup_threads()

        for thread in self._threads:
            thread.join()

        for sock in self._sockets:
            sock.close()

        for sock in self._err_sock:
            sock.close()

        self._selector.close()

    def route_path(self, raw_path):
        """
        Determines the appropriate handler for the specified path.
        Returns a tuple containing:
         - The handler instance (None if no handler was found)
         - The prefix matched by the handler (without ending /)
         - The rest of the path (starts with /, '' for a file route)
         - The query string ('' if none)

        The path is normalized before processing.
        """

        raw_path = raw_path.split('#', 1)[0]
        raw_path, _, query = raw_path.partition('?')

        parts = []
        for part in raw_path.split('/'):
            if part == '..':
                if parts:
                    parts.pop()
            elif part and part != '.':
                parts.append(part)

        norm_path = '/' + '/'.join(parts)

        is_dir_path = raw_path.endswith('/')

        # Try to find a file handler first
        handler = self._config.file_routes.get(norm_path)
        prefix = norm_path
        rest = ''

        if handler is None:
            # No file handler, try to find a dir handler
            if norm_path == '/':
                norm_path_slash = norm_path
            else:
                norm_path_slash = norm_path + '/'

            if is_dir_path:
                norm_path = norm_path_slash

            for candidate_prefix, candidate_handler in self._config.dir_routes:
                if norm_path.startswith(candidate_prefix):
                    handler = candidate_handler
                    prefix = norm_path[:len(candidate_prefix) - 1]
                    rest = norm_path[len(candidate_prefix) - 1:]

                    break

                if (not is_dir_path and
                    norm_path_slash.startswith(candidate_prefix)):
                    # There is a path prefix "/x/" but the specified path was
                    # "/x".
                    handler = AddSlashPrefixHandler.get_instance()
                    break

        elif is_dir_path:
            # A file handler was found but a directory path was specified.
            # Return a Not Found error.
            handler = None

        return handler, prefix, rest, query

    def _handle_conn(self, conn, addr):
        """
        Handles a received socket connection.
        """

        self._cleanup_threads()
        while len(self._threads) >= self._config.max_threads:
            time.sleep(.5)
            self._cleanup_threads()

        thread = threading.Thread(target=self._handle_conn_thread,
            name=f"Conn-Handler-{addr[0]}-{addr[1]}", args=(conn, addr),
            daemon=True)
        self._threads.append(thread)
        thread.start()

    def _handle_conn_thread(self, conn, addr):
        """
        Handle a received socket connection on a thread.
        """

        try:
            self.DispatcherHandler(conn, addr, self, self._config)
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        except OSError as err:
            print(f"Error from {addr[0]}:{addr[1]}: {err}", file=sys.stderr,
                flush=True)
        except Exception:
            # Will notify self._err_sock[1], stopping the main thread
            # This is thread safe and can safely be done multiple times
            self._err_sock[0].close()
            raise
        finally:
            conn.close()

    def _cleanup_threads(self):
        """
        Removes completed threads from the thread list.
        """

        self._threads[:] = (thread for thread in self._threads
            if thread.is_alive())


class SystemdInterface:
    """
    Interface with systemd for notifications and socket activation.
    """

    _instance = None

    @classmethod
    def get_instance(cls):
        """
        Get the singleton instance of the systemd interface.
        """

        if cls._instance is None:
            cls._instance = cls()

        return cls._instance

    def __init__(self):
        self._notify_sock = self._get_notify_socket()
        self._fds = self._get_fds()

    def get_socket(self, ident):
        """
        Gets a socket from systemd. Receives an identifier, which is '1' for
        the first systemd configured socket, '2' for the second, etc.
        Must be called before ready() is called.
        """

        fdesc = self._fds.pop(ident, None)
        if fdesc is None:
            values = ",".join(self._fds.keys()) or "<none>"
            raise ValueError(f"Invalid systemd socket ID {ident}. Valid "
                f"IDs: {values}")

        return socket.socket(fileno=fdesc)

    def ready(self):
        """
        Indicates that the service is ready.
        This also sets up the SIGTERM signal so it cleanly stops the
        process.
        """

        if self._notify_sock is not None:
            self._notify_sock.send(b'READY=1')

        for fdesc in self._fds.values():
            os.close(fdesc)

        signal.signal(signal.SIGTERM, self._on_signal)

        self._fds = None

    def close(self):
        """
        Indicates that the service is terminating, and release associated
        resources.
        """

        if self._notify_sock is not None:
            self._notify_sock.send(b'STOPPING=1')
            self._notify_sock.close()
            self._notify_sock = None

    @staticmethod
    def _on_signal(_signum, _frame):
        """
        Called when the SIGTERM signal is received. Cleanly stops the process.
        """

        sys.exit()

    @staticmethod
    def _get_notify_socket():
        """
        Returns a socket connected to the service manager, or None if the
        process was not started by systemd.
        """

        name = os.environ.pop('NOTIFY_SOCKET', None)
        if name is None:
            return None

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            if name.startswith('@'):
                sock.connect(f'\x00{name[1:]}')
            elif name.startswith('/'):
                sock.connect(name)
            else:
                sys.exit(f"Invalid notify socket name {name!r}.")
        except OSError as err:
            sys.exit(f"Failed to connect to notify socket {name!r}: {err}.")

        return sock

    @staticmethod
    def _get_fds():
        """
        Returns a dictionary of file descriptors, identified by their index.
        """

        fds = {}

        if os.environ.get('LISTEN_PID', '') != str(os.getpid()):
            return fds

        fd_count_var = os.environ.get('LISTEN_FDS', '')
        try:
            fd_count = int(fd_count_var)
        except ValueError:
            fd_count = -1

        if fd_count < 0:
            sys.exit(f"Invalid LISTEN_FDS value {fd_count_var}")

        for i in range(fd_count):
            fds[str(i + 1)] = i + 3

        return fds


def run():
    """
    Program entry point
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', '-c', help="Configuration file",
        default='/etc/pyminihttpd.conf')
    args = parser.parse_args()
    systemd = SystemdInterface.get_instance()
    config = Configuration.from_file(args.config)
    try:
        dispatcher = RequestDispatcher(config)
    except (OSError, ValueError) as err:
        sys.exit(f"Initialization error: {err}")

    try:
        systemd.ready()
        dispatcher.run()

    except KeyboardInterrupt:
        print("")
    finally:
        systemd.close()
        dispatcher.close()


if __name__ == '__main__':
    run()
