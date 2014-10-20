<?php
/**
 * Copyright (c) 2014 Axel Helmert
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author    Axel Helmert
 * @copyright Copyright (c) 2014 Axel Helmert
 * @license   http://www.gnu.org/licenses/gpl-3.0.txt GNU General Public License
 */

namespace rampagetest\rbac;

use rampage\rbac\exceptions;
use rampage\rbac\Rbac;
use rampage\rbac\RbacInterface;
use rampage\rbac\Role;
use rampage\rbac\RoleInterface;
use rampage\rbac\RoleContainerInterface;

use PHPUnit_Framework_TestCase as TestCase;
use PHPUnit_Framework_Constraint_IsIdentical as IsIdentical;


class RbacTest extends TestCase
{
    /**
     * @var Rbac
     */
    protected $rbac;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        parent::setUp();
        $this->rbac = new Rbac();
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        $this->rbac = null;
        parent::tearDown();
    }

    /**
     * Test if rbac implements the required interfaces
     */
    public function testRbacImplementsInterfaces()
    {
        $this->assertInstanceOf(RbacInterface::class, $this->rbac);
        $this->assertInstanceOf(RoleContainerInterface::class, $this->rbac);
        $this->assertInstanceOf('Traversable', $this->rbac);
    }

    /**
     * @covers rampage\rbac\Rbac::getRole
     */
    public function testGetNonExistingRoleThrowsException()
    {
        $this->setExpectedException(exceptions\RoleNotFoundException::class);
        $this->rbac->getRole('no_such_role');
    }

    /**
     * @covers rampage\rbac\Rbac::hasRole
     */
    public function testHasRole()
    {
        $this->rbac->addRole('foo');

        $this->assertTrue($this->rbac->hasRole('foo'));
        $this->assertFalse($this->rbac->hasRole('bar'));
    }

    /**
     * @covers rampage\rbac\Rbac::addRole
     * @covers rampage\rbac\Rbac::getRole
     * @covers rampage\rbac\Rbac::hasRole
     */
    public function testAddRoleFromString()
    {
        $this->rbac->addRole('myrole');
        $this->assertTrue($this->rbac->hasRole('myrole'));
        $this->assertInstanceOf(RoleInterface::class, $this->rbac->getRole('myrole'));
    }

    /**
     * @covers rampage\rbac\Rbac::addRole
     * @covers rampage\rbac\Rbac::getRole
     * @covers rampage\rbac\Rbac::hasRole
     */
    public function testAddRole()
    {
        $role = new Role('foo');
        $this->rbac->addRole($role);

        return $this->assertTrue($this->rbac->hasRole('foo'));
    }

    /**
     * @covers rampage\rbac\Rbac::addRole
     * @covers rampage\rbac\Rbac::getRole
     * @covers rampage\rbac\Rbac::hasRole
     */
    public function testAddRoleWithChildren()
    {
        $this->rbac->addRole('foo', ['bar', 'baz']);
        $this->assertTrue($this->rbac->hasRole('foo'));
        $this->assertEquals(['bar', 'baz'], array_values($this->rbac->getRole('foo')->getChildren()));
    }

    /**
     * @covers rampage\rbac\Rbac::addRole
     */
    public function testAddRoleTwiceThrowsException()
    {
        $this->setExpectedException(exceptions\LogicException::class);
        $this->rbac->addRole('foo');
        $this->rbac->addRole('foo');
    }

    /**
     * @covers rampage\rbac\Rbac::getRole
     */
    public function testAddRoleSetsContainer()
    {
        $basicRole = new Role('foo');
        $role = $this->getMockForAbstractClass(RoleInterface::class);
        $role->expects($this->atLeastOnce())
            ->method('getRoleId')
            ->will($this->returnValue('customrole'));

        $role->expects($this->once())
            ->method('setContainer')
            ->with(new IsIdentical($this->rbac))
            ->will($this->returnSelf());

        $this->rbac->addRole($basicRole)
            ->addRole($role)
            ->addRole('bar');


        $this->assertSame($this->rbac, $basicRole->getContainer());
        $this->assertSame($this->rbac, $this->rbac->getRole('bar')->getContainer());
    }

    /**
     * @covers rampage\rbac\Rbac::getRole
     */
    public function testGetRoleReturnsRegisteredImplementation()
    {
        $roleName = 'customrole';
        $role = $this->getMockForAbstractClass(RoleInterface::class);
        $role->expects($this->atLeastOnce())
            ->method('getRoleId')
            ->will($this->returnValue($roleName));

        $this->rbac->addRole($role);

        $this->assertSame($role, $this->rbac->getRole($roleName));
        $this->assertSame($role, $this->rbac->getRole(new Role($roleName)));
    }

    /**
     * @covers rampage\rbac\Rbac::isGranted
     */
    public function testIsGranted()
    {
        $role = $this->getMockForAbstractClass(RoleInterface::class);
        $role->expects($this->atLeastOnce())
            ->method('getRoleId')
            ->will($this->returnValue('foo'));

        $role->expects($this->once())
            ->method('isGranted')
            ->with('bar')
            ->will($this->returnValue(true));

        $this->rbac->addRole($role);

        $this->assertFalse($this->rbac->isGranted('no-such-role', 'bar'));
        $this->assertTrue($this->rbac->isGranted('foo', 'bar'));
    }

    /**
     * @covers rampage\rbac\Rbac::isGranted
     */
    public function testIsGrantedUsesRegisteredRole()
    {
        $role = new Role('test');
        $role->allow('foo');

        $this->rbac->addRole($role);

        $this->assertTrue($this->rbac->isGranted(new Role('test'), 'foo'));
    }


    /**
     * @covers rampage\rbac\Role::isGranted()
     */
    public function testIsGrantedChecksChildren()
    {
        $first = new Role('first');
        $second = new Role('second');
        $third = new Role('third');

        $this->rbac->addRole($third)
            ->addRole($second, [ $third ])
            ->addRole($first, [ $second ]);

        $third->allow('foo');

        $this->assertTrue($this->rbac->isGranted('first', 'foo'));
        $this->assertTrue($this->rbac->isGranted('second', 'foo'));
    }

    /**
     * @covers rampage\rbac\Role::isGranted()
     */
    public function testIsGrantedNotChecksChildrenIfDefined()
    {
        $first = new Role('first');
        $second = $this->getMockForAbstractClass(RoleInterface::class);

        $second->expects($this->any())
            ->method('getRoleId')
            ->will($this->returnValue('second'));

        $second->expects($this->never())
            ->method('isGranted')
            ->will($this->returnValue(null));

        $this->rbac->addRole($second)
            ->addRole($first, [ $second ]);

        $first->allow('foo');
        $first->deny('bar');

        $this->assertTrue($this->rbac->isGranted('first', 'foo'));
        $this->assertFalse($this->rbac->isGranted('first', 'bar'));
    }
}
