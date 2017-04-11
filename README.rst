posh: Print Over Simple HTTP
============================

posh is a small HTTP daemon that listens for requests and sends the request
body to the specified printing device.

Inspired by the `12 Factor <http://12factor.net>`_ approach of treating backing
services as attached resources, the printer becomes a URL based resource.

Building
--------

There are no external libraries so it's a simple case of:

.. code-block:: sh

    $ go build posh.go

which will produce a statically linked binary.

Usage
-----

Run with the help flag to see a list of options:

.. code-block:: sh

    $ ./posh --help

At the bare minimum you'll need to specify a username and password for HTTP
basic authentication:

.. code-block:: sh

    $ ./posh --username admin --password password

Then send it a HTTP POST request with the device path and print data payload:

.. code-block:: sh

    $ curl --insecure -X POST https://foo:bar@localhost/dev/usb/lp0 -d @file.ps

Note that posh uses TLS so your client must connect using the 'https' scheme.
Every time posh starts, it generates a self-signed certificate.

If you make an authenticated GET request to */stats*, you'll see stats relating
to the number of print jobs submitted.

An unauthenticated GET request to the root path, */*, is permissible and just
returns *posh*. Its main use is for health check polling.
