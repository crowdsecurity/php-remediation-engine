<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine\Configuration\Cache;

use CrowdSec\RemediationEngine\Configuration\AbstractCache;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

/**
 * The remediation cache configuration for Memcached.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
class Memcached extends AbstractCache
{
    /**
     * @var string[]
     */
    protected $keys = [
        'memcached_dsn',
        'use_cache_tags'
    ];

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('config');
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();
        $rootNode->children()
            ->scalarNode('memcached_dsn')->isRequired()->cannotBeEmpty()->end()
        ->end()
        ;
        $this->addCommonNodes($rootNode);
        $this->validate($rootNode);

        return $treeBuilder;
    }

    /**
     * Conditional validation.
     *
     * @return void
     */
    protected function validate($rootNode)
    {
        $rootNode->validate()
            ->ifTrue(function (array $v) {
                return true === $v['use_cache_tags'];
            })
            ->thenInvalid('Cache tags is not supported by Memcached cache.')
        ->end();
    }
}
