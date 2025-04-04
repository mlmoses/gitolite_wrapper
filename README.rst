################
Gitolite Wrapper
################

Or, more precisely, a wrapper for gitolite-shell that allows one to use
Gitolite with SSH certificates. This program implements the same basic idea
presented in the gl-wrapper scripts discussed in `gitolite and ssh
certificates`_, but hopefully faster and more efficiently.

The only official public repository for gitolite_wrapper is on Gitlab_.
However, there is an official mirror on Github_ for the convenience of those
who have a Github account but no Gitlab account.

.. _gitolite and ssh certificates: https://gitolite.com/gitolite/gitolite-and-ssh-certs.html
.. _Gitlab: https://gitlab.com/mlmoses/gitolite_wrapper
.. _Github: https://github.com/mlmoses/gitolite_wrapper


How To Use
##########

1. Put the gitolite_wrapper binary somewhere on your server.

2. Follow the directions in `gitolite and ssh certificates`_, but instead of
   putting ``/usr/local/bin/gl-wrapper`` in the AuthorizedPrincipalsFile, use
   the path to the gitolite_wrapper binary.

3. If gitolite-shell is not in your PATH, you will need to use the ``--shell``
   or ``-s`` command line parameters to specify the appropriate path.
