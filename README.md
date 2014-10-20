# Rampage Rbac

This is a leightweight Rbac implementation.
It exists due to the ZF2 rbac implementation has some major design flaws.

## Installation

Add a require statement to your composer.json `composer.phar require rampage-php/rbac`.

## Usage (brief)

A simple suage example

```php
// let rbac instanciate standard roles
$rbac = new rampage\rbac\Rbac();
$rbac->addRole('foo');
$rbac->addRole('bar', ['foo']);
$rbac->getRole('foo')->allow('permission');

// instanciate your own roles (they need to implement rampage\rbac\RoleInterface)
$role = new Role('baz')
$role->addChild('bar'); // will utilize $rbac->getRole('bar') if present.

$rbac->addRole($role);
```
