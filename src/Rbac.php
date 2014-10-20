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

use ArrayIterator;
use IteratorAggregate;
use RecursiveIteratorIterator;


class Rbac implements IteratorAggregate, RbacInterface
{
    /**
     * @var RoleInterface[]
     */
    protected $roles = array();

    /**
     * {@inheritdoc}
     */
    public function getIterator()
    {
        return new ArrayIterator($this->roles);
    }

    /**
     * @param RoleInterface|string $role
     * @param string $children
     * @return self
     */
    public function addRole($role, $children = null)
    {
        if (is_string($role)) {
            $role = new Role($role);
        }

        if (!$role instanceof RoleInterface) {
            throw new exceptions\InvalidArgumentException(sprintf(
                'A role must implement rampage\rbac\RoleInterface, %s given',
                is_object($role)? get_class($role) : gettype($role)
            ));
        }

        if ($this->hasRole($role)) {
            throw new exceptions\LogicException('The role "%s" is already defined');
        }

        $role->setContainer($this);

        if (($role instanceof Role) && (is_array($children) || ($children instanceof \Traversable))) {
            foreach ($children as $child) {
                $role->addChild($child);
            }
        }

        $this->roles[$role->getRoleId()] = $role;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted($role, $permission)
    {
        if (!$this->hasRole($role)) {
            return false;
        }

        $role = $this->getRole($role);
        $result = $role->isGranted($permission);

        if ($result !== null) {
            return (bool)$result;
        }

        $iterator = new RecursiveIteratorIterator(new RecursiveRoleIterator($role), RecursiveIteratorIterator::SELF_FIRST);

        foreach ($iterator as $child) {
            $result = $child->isGranted($permission);

            if ($result !== null) {
                return (bool)$result;
            }
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getRole($role)
    {
        if ($role instanceof RoleInterface) {
            $role = $role->getRoleId();
        }

        if (!$this->hasRole($role)) {
            throw new exceptions\RoleNotFoundException(sprintf('Could not find role "%s"', $role));
        }

        return $this->roles[$role];
    }

    /**
     * {@inheritdoc}
     */
    public function hasRole($role)
    {
        if ($role instanceof RoleInterface) {
            $role = $role->getRoleId();
        }

        return isset($this->roles[$role]);
    }
}
