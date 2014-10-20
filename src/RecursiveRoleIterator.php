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

use RecursiveIterator;
use IteratorIterator;
use ArrayIterator;


class RecursiveRoleIterator implements RecursiveIterator
{
    /**
     * @var RoleInterface
     */
    protected $role = null;

    /**
     * recursion detection stack
     *
     * @var array
     */
    protected $stack = array();

    /**
     * @var \Iterator
     */
    protected $iterator = null;

    /**
     * @param RoleInterface $role
     */
    public function __construct(RoleInterface $role)
    {
        $this->role = $role;
        $this->stack[$role->getRoleId()] = $role->getRoleId();

        $iterator = $role->getChildren();
        $this->iterator = is_array($iterator)? new ArrayIterator($iterator) : new IteratorIterator($iterator);
    }

    /**
     * {@inheritdoc}
     * @return RoleInterface
     */
    public function current()
    {
        if (!$this->valid()) {
            return null;
        }

        return $this->role->getContainer()->getRole($this->iterator->current());
    }

    /**
     * {@inheritdoc}
     */
    public function getChildren()
    {
        if (!$this->valid()) {
            throw new exceptions\LogicException('Cannot get children when in invalid iterator state');
        }

        $role = $this->current();

        $children = new static($role);
        $children->stack = $this->stack;
        $children->stack[$role->getRoleId()] = $role->getRoleId();

        return $children;
    }

    /**
     * {@inheritdoc}
     */
    public function hasChildren()
    {
        return $this->valid() && $this->current()->hasChildren();
    }

    /**
     * {@inheritdoc}
     */
    public function key()
    {
        return $this->current()->getRoleId();
    }

    /**
     * @return boolean
     */
    protected function accept()
    {
        if (!$this->role->getContainer()->hasRole($this->iterator->current())) {
            return false;
        }

        if (in_array($this->iterator->current(), $this->stack)) {
            // recursion
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function next()
    {
        $this->iterator->next();

        while ($this->iterator->valid() && !$this->accept()) {
            $this->iterator->next();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function rewind()
    {
        $this->iterator->rewind();
    }

    /**
     * {@inheritdoc}
     */
    public function valid()
    {
        return $this->iterator->valid();
    }
}
