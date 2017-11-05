posh: Print Over Simple HTTP
============================

posh is a small HTTP daemon that listens for requests and sends the request
body to the specified printing device. The received payload is written directly
to the specified device file (raw mode) so your printer must be able to print
the payload data without drivers.

Inspired by the `12 Factor <http://12factor.net>`_ approach of treating backing
services as attached resources, the printer becomes a URL based resource.

Building
--------

There are no external libraries so it's a simple case of:

.. code-block:: sh

    $ go build posh.go

which will produce a statically linked binary.

Alternatively, you can download a precompiled binary (see releases).

Usage
-----

Run with the help flag to see a list of options:

.. code-block:: sh

    $ ./posh --help

posh is secured via HTTP basic authentication so, at the very least, you must
configure a username and password. By default, this is specified in the file
``/etc/posh.json`` as a JSON object:

.. code-block:: json

    {
      "username": "admin",
      "password": "secret",
      "port": 443
    }

The ``port`` key is optional and will default to the standard HTTPS port:
443.

If the file doesn't exist, or cannot be read, you'll need to specify a username
and password via the command line flags:

.. code-block:: sh

    $ ./posh --username admin --password secret

These flags will override values in the configuration file, if it exists.

posh will then generate a self-signed certificate, bind to the specified port,
default 443, and listen for incoming connections.  As all connections are over
TLS, your client must connect using the 'https' scheme. Note that since the
certificate is generated on the fly, and stored only in memory, it will be
different each time posh starts. This provides secure transport but doesn't
protect against man-in-the-middle attacks. Whether this is acceptable to you
depends on your threat model.

To print something, send a HTTP POST request with the printer device path and
print data payload:

.. code-block:: sh

    $ curl --insecure -X POST https://admin:secret@localhost/dev/usb/lp0 -d @file.ps

It may be useful to configure udev, or whatever device manager you're using, to
assign a more memorable device name to your printer, e.g.
``/dev/usb/laserjet``.

If you make an authenticated GET request to */stats*, you'll see stats relating
to the number of print jobs submitted.

An unauthenticated GET request to the root path, */*, returns version
information. Its main use is for health check polling.

Daemonizing
-----------

Sample files are provided to setup posh as a daemon:

- systemd: Copy ``posh.service`` to ``/etc/systemd/system/posh.service``.
- OpenRC: Copy ``posh.openrc`` to ``/etc/init.d/posh``.

Both expect the posh executable in ``/usr/local/bin/`` and run it under the
*lp* user. Since this is an unprivileged user, you may need two additional
capabilities:

- ``CAP_NET_BIND_SERVICE``: Set this if binding to a port less than 1024.
- ``CAP_DAC_OVERRIDE``: Set this if the printer device descriptor does not have
  write permission for the user you're running under (this shouldn't be the
  case if you're running under the ``lp`` user). Note that this is a very broad
  capability, it effectively bypasses all discretionary access control checks.
  It would be better to modify the device file permissions, either
  automatically, via udev rules, or manually via ``chmod`` or ``chown``.

Use the ``setcap`` utility to set capabilities. For example, setting both:

.. code-block:: sh

    $ setcap cap_net_bind_service,cap_dac_override+eip /usr/local/bin/posh
