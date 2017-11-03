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

Alternatively, you can download a precompiled binary in the releases section.

Usage
-----

Run with the help flag to see a list of options:

.. code-block:: sh

    $ ./posh --help

posh is secured via HTTP basic authentication so you must configure a username
and password. By default, this is specified in in :code:`/etc/posh.json` like so:

.. code-block:: json

    {
      "username": "admin",
      "password": "secret"
    }

If the file doesn't exist, or cannot be read, you'll need to specify a username
and password via the command line flags:

.. code-block:: sh

    $ ./posh --username admin --password secret

These flags will override values in the configuration file, if it exists.

Then send a HTTP POST request with the printer device path and print data
payload:

.. code-block:: sh

    $ curl --insecure -X POST https://admin:secret@localhost/dev/usb/lp0 -d @file.ps

Note that posh uses TLS so your client must connect using the 'https' scheme.
Every time posh starts, it generates a new self-signed certificate.

If you make an authenticated GET request to */stats*, you'll see stats relating
to the number of print jobs submitted.

An unauthenticated GET request to the root path, */*, is permissible and just
returns version information. Its main use is for health check polling.
