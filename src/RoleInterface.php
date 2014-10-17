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

/**
 * Interface for RBAC Roles
 */
interface RoleInterface
{
    /**
     * @return string
     */
    public function getRoleId();

    /**
     * @param RoleContainerInterface $container
     */
    public function setContainer(RoleContainerInterface $container);

    /**
     * @return RoleContainerInterface
     */
    public function getContainer();

    /**
     * @return bool
     */
    public function hasChildren();

    /**
     * @return RoleInterface[]
     */
    public function getChildren();

    /**
     * @param string $permission
     * @param bool
     */
    public function isGranted($permission);
}
