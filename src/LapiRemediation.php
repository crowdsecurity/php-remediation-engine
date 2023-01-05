<?php

declare(strict_types=1);

namespace CrowdSec\RemediationEngine;

use CrowdSec\LapiClient\Bouncer;
use CrowdSec\LapiClient\ClientException;
use CrowdSec\RemediationEngine\CacheStorage\AbstractCache;
use CrowdSec\RemediationEngine\CacheStorage\CacheStorageException;
use CrowdSec\RemediationEngine\Configuration\Lapi as LapiRemediationConfig;
use Psr\Cache\CacheException;
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
    /**
     * @var null|array
     */
    private $scopes;

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
     * @throws CacheStorageException
     * @throws InvalidArgumentException
     * @throws RemediationException
     * @throws CacheException|ClientException
     */
    public function getIpRemediation(string $ip): string
    {
        $country = $this->getCountryForIp($ip);
        $cachedDecisions = $this->getAllCachedDecisions($ip, $country);

        if (!$cachedDecisions) {
            $this->logger->debug('There is no cached decision', [
                'type' => 'LAPI_REM_NO_CACHED_DECISIONS',
                'ip' => $ip,
            ]);
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
     * @param bool $startup
     * @param array $filter
     * @return array
     * @throws CacheException
     * @throws CacheStorageException
     * @throws ClientException
     * @throws InvalidArgumentException
     * @SuppressWarnings(PHPMD.BooleanArgumentFlag)
     */
    private function getStreamDecisions(bool $startup = false, array $filter = []): array
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
     * @return array
     */
    private function getScopes(): array
    {
        if (null === $this->scopes) {
            $finalScopes = [Constants::SCOPE_IP, Constants::SCOPE_RANGE];
            $geolocConfigs = (array) $this->getConfig('geolocation');
            if (!empty($geolocConfigs['enabled'])) {
                $finalScopes[] = Constants::SCOPE_COUNTRY;
            }
            $this->scopes = $finalScopes;
        }

        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     *
     * @SuppressWarnings(PHPMD.BooleanArgumentFlag)
     * @return array
     * @throws CacheException
     * @throws CacheStorageException
     * @throws ClientException
     * @throws InvalidArgumentException
     */
    public function refreshDecisions(): array
    {
        if (!$this->getConfig('stream_mode')) {
            $this->logger->info('Decisions refresh is only available in stream mode', [
                'type' => 'LAPI_REM_REFRESH_DECISIONS'
            ]);

            return [
                self::CS_NEW => 0,
                self::CS_DEL => 0
            ];
        }

        $filter = ['scopes' => implode(',', $this->getScopes())];

        if (!$this->isWarm()) {
            return $this->warmUp($filter);
        }

        return $this->getStreamDecisions(false, $filter);
    }

    /**
     * @throws InvalidArgumentException
     */
    private function isWarm(): bool
    {
        $cacheConfigItem = $this->cacheStorage->getItem(AbstractCache::CONFIG);
        $cacheConfig = $cacheConfigItem->get();

        return (\is_array($cacheConfig) && isset($cacheConfig[AbstractCache::WARMUP])
                && true === $cacheConfig[AbstractCache::WARMUP]);
    }

    /**
     * @throws ClientException
     * @throws InvalidArgumentException
     * @throws CacheException
     * @throws CacheStorageException
     */
    private function warmUp(array $filter): array
    {
        $this->logger->info('Will now clear the cache', ['type' => 'LAPI_REM_CACHE_WARMUP_CLEAR']);
        $this->cacheStorage->clear();
        $this->logger->info('Beginning of cache warmup', ['type' => 'LAPI_REM_CACHE_WARMUP_START']);
        $result = $this->getStreamDecisions(true, $filter);
        // Store the fact that the cache has been warmed up.
        $this->cacheStorage->updateItem(AbstractCache::CONFIG, [AbstractCache::WARMUP => true]);

        $this->logger->info('End of cache warmup', [
            'type' => 'LAPI_REM_CACHE_WARM_UP_END',
            self::CS_NEW => $result[self::CS_NEW] ?? 0,
            self::CS_DEL => $result[self::CS_DEL] ?? 0
        ]);
        return $result;
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
