<?php

declare(strict_types=1);

/*
 * This file is part of the FOSOAuthServerBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\OAuthServerBundle\Util;

/**
 * @internal
 *
 * @author Sanjay Pillai <sanjaypillai11@gmail.com>
 */
final class LegacyFormHelper
{
    /**
     * @var string[]
     */
    private static $map = [
        'Symfony\Component\Form\Extension\Core\Type\HiddenType' => 'hidden',
        'FOS\OAuthServerBundle\Form\Type\AuthorizeFormType' => 'fos_oauth_server_authorize',
    ];

    /**
     * No code needed here the main goal is to make the function private
     */
    private function __construct()
    {
    }

    /**
     * No code needed here the main goal is to make the function private
     */
    private function __clone()
    {
    }

    public static function getType(string $class): string
    {
        if (!self::isLegacy()) {
            return $class;
        }

        if (!isset(self::$map[$class])) {
            throw new \InvalidArgumentException(sprintf('Form type with class "%s" can not be found. Please check for typos or add it to the map in LegacyFormHelper', $class));
        }

        return self::$map[$class];
    }

    public static function isLegacy(): bool
    {
        return !method_exists('Symfony\Component\Form\AbstractType', 'getBlockPrefix');
    }
}
