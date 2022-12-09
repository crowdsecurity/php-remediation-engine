<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine\Configuration;

use CrowdSec\RemediationEngine\CapiRemediation;
use CrowdSec\RemediationEngine\Constants;
use CrowdSec\RemediationEngine\LapiRemediation;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * The remediation common configuration.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
abstract class AbstractRemediation implements ConfigurationInterface
{
    private function getDefaultOrderedRemediations(): array
    {
        if (get_class($this) === Capi::class) {
            return array_merge(CapiRemediation::ORDERED_REMEDIATIONS, [Constants::REMEDIATION_BYPASS]);
        }

        return array_merge(LapiRemediation::ORDERED_REMEDIATIONS, [Constants::REMEDIATION_BYPASS]);
    }

    /**
     * Common remediation settings.
     *
     * @return void
     */
    protected function addCommonNodes($rootNode)
    {
        $rootNode->children()
            ->scalarNode('fallback_remediation')
                ->defaultValue(Constants::REMEDIATION_BYPASS)
            ->end()
            ->arrayNode('ordered_remediations')->cannotBeEmpty()
                ->validate()
                ->ifArray()
                ->then(function (array $remediations) {
                    // Remove bypass if any
                    foreach ($remediations as $key => $remediation) {
                        if (Constants::REMEDIATION_BYPASS === $remediation) {
                            unset($remediations[$key]);
                        }
                    }
                    // Add bypass as the lowest priority remediation
                    $remediations = array_merge($remediations, [Constants::REMEDIATION_BYPASS]);

                    return array_values(array_unique($remediations));
                })
                ->end()
                ->scalarPrototype()->cannotBeEmpty()->end()
                ->defaultValue($this->getDefaultOrderedRemediations())
            ->end()
            ->booleanNode('stream_mode')->defaultTrue()->end()
            ->integerNode('clean_ip_cache_duration')
                ->min(1)->defaultValue(Constants::CACHE_EXPIRATION_FOR_CLEAN_IP)
            ->end()
            ->integerNode('bad_ip_cache_duration')
                ->min(1)->defaultValue(Constants::CACHE_EXPIRATION_FOR_BAD_IP)
            ->end()
        ->end();
    }

    /**
     * Conditional validation.
     *
     * @return void
     */
    protected function validateCommon($rootNode)
    {
        $rootNode->validate()
            ->ifTrue(function (array $v) {
                return Constants::REMEDIATION_BYPASS !== $v['fallback_remediation'] &&
                       !in_array($v['fallback_remediation'], $v['ordered_remediations']);
            })
            ->thenInvalid('Fallback remediation must belong to ordered remediations.')
            ->end();
    }
}
