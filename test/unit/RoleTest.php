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

use rampage\rbac\Role;
use rampage\rbac\RoleContainerInterface;

use PHPUnit_Framework_TestCase as TestCase;


/**
 * Role test case.
 */
class RoleTest extends TestCase
{
    /**
     * @var Role
     */
    private $role = null;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        parent::setUp();
        $this->role = new Role('testRole');
    }

    /**
     * {@inheritdoc}
     */
    protected function tearDown()
    {
        $this->role = null;
        parent::tearDown();
    }

    /**
     * @covers rampage\rbac\Role::__construct()
     * @covers rampage\rbac\Role::getRoleId()
     */
    public function testConstructionWithId()
    {
        $role = new Role('myRole');
        $this->assertEquals('myRole', $role->getRoleId());
    }

    /**
     * @covers rampage\rbac\Role::addChild()
     */
    public function testAddChild()
    {
        $this->role->addChild('foo');
        $this->assertEquals(['foo'], array_values($this->role->getChildren()));
    }

    /**
     * @covers rampage\rbac\Role::hasChildren()
     */
    public function testHasChildrenReturnsFalseIfNotInContainer()
    {
        $container = $this->getMockForAbstractClass(RoleContainerInterface::class);
        $container->expects($this->atLeastOnce())
            ->method('hasRole')
            ->will($this->returnValue(false));

        $this->role->setContainer($container)
            ->addChild('foo');

        $this->assertFalse($this->role->hasChildren());
    }

    /**
     * @covers rampage\rbac\Role::hasChildren()
     */
    public function testHasChildrenReturnsTrueIfInContainer()
    {
        $container = $this->getMockForAbstractClass(RoleContainerInterface::class);
        $container->expects($this->atLeastOnce())
            ->method('hasRole')
            ->will($this->returnValue(true));

        $this->role->setContainer($container)
            ->addChild('foo');

        $this->assertTrue($this->role->hasChildren());
    }

    /**
     * @covers rampage\rbac\Role::hasChildren()
     */
    public function testHasChildrenReturnsFalseWithoutContainer()
    {
        $this->role->addChild('foo');
        $this->assertFalse($this->role->hasChildren());
    }

    /**
     * Tests Role->getChildren()
     */
    public function testGetChildren()
    {
        $child = new Role('child1');

        $this->role->addChild($child)
            ->addChild('child2');

        $this->assertEquals(['child1', 'child2'], array_values($this->role->getChildren()));
    }

    /**
     * @covers rampage\rbac\Role::isGranted()
     */
    public function testIsGranted()
    {
        $this->role->allow('foo');
        $this->role->deny('bar');

        $this->assertTrue($this->role->isGranted('foo'));
        $this->assertFalse($this->role->isGranted('bar'));
        $this->assertNull($this->role->isGranted('baz'));
    }

    /**
     * Tests Role->getContainer()
     */
    public function testGetContainer()
    {
        $container = $this->getMockForAbstractClass(RoleContainerInterface::class);

        $this->role->setContainer($container);
        $this->assertSame($container, $this->role->getContainer());
    }
}

