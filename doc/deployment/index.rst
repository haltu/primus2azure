Building the deployment package on Windows
==========================================

Prerequisites:

* Python 2.7
* Requests must be installed (for example from http://www.lfd.uci.edu/~gohlke/pythonlibs/)
* cx_freeze must be installed (for example http://www.lfd.uci.edu/~gohlke/pythonlibs/#cx_freeze)
* To install packages in Windows use pip bundled with Python
  `c:\python27\python -m pip install [package]`

Execute `python setup.py build`


Deploying the tool
==================

* In Azure create application credentials. The following permissions are
  needed:

  * Application Permissions: Read and write directory data
  * Delegated Permissions: Read and write directory data, Read and write all
    groups

* To authorize the application to change user passwords use Powershell to add
  it to the User Account Administrator role::

  Connect-MsolService
  $displayName = "Application Name"
  $objectId = (Get-MsolServicePrincipal -SearchString $displayName).ObjectId
  $roleName = "User Account Administator"
  Add-MsolRoleMember -RoleName $roleName -RoleMemberType ServicePrincipal -RoleMemberObjectId $objectId

* Configure the client id, client secret and domain in primus2azure.cfg
* Configure attribute rules and group rules in primus2azure.cfg

