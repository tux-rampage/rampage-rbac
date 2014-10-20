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

namespace rampage\rbac;

use IteratorAggregate;
use RecursiveIteratorIterator;


class Role implements RoleInterface, IteratorAggregate
{
    /**
     * @var string
     */
    protected $id;

    /**
     * Child role names
     *
     * @var string[]
     */
    protected $children = array();

    /**
     * @var RoleContainerInterface
     */
    protected $container = null;

    /**
     * @var string[]
     */
    protected $permissions = array();

    /**
     * @param string $id
     */
    public function __construct($id)
    {
        $this->id = $id;
        $this->container = new Rbac();
    }

    /**
     * {@inheritdoc}
     */
    public function getIterator()
    {
        return new RecursiveRoleIterator($this);
    }

    /**
     * {@inheritdoc}
     */
    public function getRoleId()
    {
        return $this->id;
    }

    /**
     * @param RoleInterface|string $child
     * @return self
     */
    public function addChild($child)
    {
        if ($child instanceof RoleInterface) {
            $child = $child->getRoleId();
        }

        $this->children[$child] = $child;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function hasChildren()
    {
        if (empty($this->children) || !$this->container) {
            return false;
        }

        foreach ($this->children as $role) {
            if ($this->container->hasRole($role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     * @return RoleInterface[]
     */
    public function getChildren()
    {
        return $this->children;
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted($permission)
    {
        if (isset($this->permissions[$permission])) {
            return (bool)$this->permissions[$permission];
        }

        return null;
    }

    /**
     * @param string $permission
     * @return self
     */
    public function allow($permission)
    {
        $this->permissions[$permission] = true;
        return $this;
    }

    /**
     * @param string $permision
     * @return self
     */
    public function deny($permision)
    {
        $this->permissions[$permision] = false;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function setContainer(RoleContainerInterface $container)
    {
        $this->container = $container;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getContainer()
    {
        return $this->container;
    }
}
