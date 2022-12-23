<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine;

use CrowdSec\LapiClient\Bouncer;
use CrowdSec\RemediationEngine\CacheStorage\AbstractCache;
use CrowdSec\RemediationEngine\CacheStorage\CacheException;
use CrowdSec\RemediationEngine\Configuration\Lapi as LapiRemediationConfig;
use Psr\Cache\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Config\Definition\Processor;

class LapiRemediation extends AbstractRemediation
{
    /** @var array The list of each known LAPI remediation, sorted by priority */
    public const ORDERED_REMEDIATIONS = [Constants::REMEDIATION_BAN, Constants::REMEDIATION_CAPTCHA];

    private const SELF_ORIGIN = 'lapi-remediation-engine';

    /**
     * @var Bouncer
     */
    private $client;

    public function __construct(
        array $configs,
        Bouncer $client,
        AbstractCache $cacheStorage,
        LoggerInterface $logger = null
    ) {
        $this->configure($configs);
        $this->client = $client;
        parent::__construct($this->configs, $cacheStorage, $logger);
    }

    /**
     * {@inheritdoc}
     *
     * @throws CacheException
     * @throws InvalidArgumentException|\Psr\Cache\CacheException
     */
    public function getIpRemediation(string $ip): string
    {
        $country = $this->getCountryForIp($ip);
        $cachedDecisions = $this->getAllCachedDecisions($ip, $country);

        if (!$cachedDecisions) {
            // In stream_mode, we do not store this bypass, and we do not call LAPI directly
            if ($this->getConfig('stream_mode')) {
                return Constants::REMEDIATION_BYPASS;
            }
            // In live mode, ask LAPI (Retrieve Ip AND Range scoped decisions)
            $rawIpDecisions = $this->client->getFilteredDecisions(['ip' => $ip]);
            $ipDecisions = $this->convertRawDecisionsToDecisions($rawIpDecisions);
            $countryDecisions = [];
            if ($country) {
                // Retrieve country scoped decisions
                $rawCountryDecisions = $this->client->getFilteredDecisions(
                    ['scope' => Constants::SCOPE_COUNTRY, 'value' => $country]
                );
                $countryDecisions = $this->convertRawDecisionsToDecisions($rawCountryDecisions);
            }
            $liveDecisions = array_merge($ipDecisions, $countryDecisions);

            $finalDecisions = $liveDecisions ?:
                $this->convertRawDecisionsToDecisions([[
                    'scope' => Constants::SCOPE_IP,
                    'value' => $ip,
                    'type' => Constants::REMEDIATION_BYPASS,
                    'origin' => self::SELF_ORIGIN,
                    'duration' => sprintf('%ss', (int) $this->getConfig('clean_ip_cache_duration')),
                ]]);
            // Store decision(s) even if bypass
            $stored = $this->storeDecisions($finalDecisions);

            $cachedDecisions = !empty($stored[AbstractCache::STORED]) ? $stored[AbstractCache::STORED] : [];
        }

        return $this->getRemediationFromDecisions($cachedDecisions);
    }

    /**
     * {@inheritdoc}
     *
     * @throws CacheException
     * @throws InvalidArgumentException
     * @throws RemediationException|\Psr\Cache\CacheException
     *
     * @SuppressWarnings(PHPMD.BooleanArgumentFlag)
     */
    public function refreshDecisions(bool $startup = false, array $filter = []): array
    {
        $rawDecisions = $this->client->getStreamDecisions($startup, $filter);
        $newDecisions = $this->convertRawDecisionsToDecisions($rawDecisions[self::CS_NEW] ?? []);
        $deletedDecisions = $this->convertRawDecisionsToDecisions($rawDecisions[self::CS_DEL] ?? []);
        $stored = $this->storeDecisions($newDecisions);
        $removed = $this->removeDecisions($deletedDecisions);

        return [
            self::CS_NEW => $stored[AbstractCache::DONE] ?? 0,
            self::CS_DEL => $removed[AbstractCache::DONE] ?? 0,
        ];
    }

    /**
     * Process and validate input configurations.
     */
    private function configure(array $configs): void
    {
        $configuration = new LapiRemediationConfig();
        $processor = new Processor();
        $this->configs = $processor->processConfiguration($configuration, [$configs]);
    }
}
