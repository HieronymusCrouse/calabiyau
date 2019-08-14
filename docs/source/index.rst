Welcome to Calabiyau documentation!
===================================

Release v\ |version| (:ref:`Installation <install>`)

.. _about_calabiyau:

About this project
------------------

The Calabiyau is project is a module of the `Tachyonic <http://tachyonic.org>`_ Framework, that provides an interface
to the RADIUS service. It contains the API and UI views and models, as well as a full fledged RFC 2865 compliant
RADIUS server. Effort has been made to focus on performance, only the bare minimum of processing happens upon
RADIUS packet receipt, computations are mostly performed in background processes.

Features
--------

- Thread safe
- Scalable
- Support Multiple Vendors
- Per NAS mass disconnect of sessions via POD
- Real-time service update via CoA
- Time- and usage-based criteria can be used to activate deactivate services.
- Contains most common AVPs, but can easily be extended.

Documentation
-------------

.. toctree::
   :maxdepth: 2

   license
   install
   releases
   userguide
